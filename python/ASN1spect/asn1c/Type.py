import copy
import json
import re

import angr
import claripy
from tqdm import tqdm

from ASN1spect import ASN1AngrProject
from ASN1spect.Analysis.Analysis import Analysis

# from ASN1spect.Analysis.EnumerationAnalysis import EnumerationAnalysis
from ASN1spect.Analysis.DifferentialEnumerationAnalysis import (
    DifferentialEnumerationAnalysis,
)
from ASN1spect.Analysis.IncompleteTypeGeneration import IncompleteTypeGeneration
from ASN1spect.Analysis.NonEnforcedConstraintAnalysis import (
    NonEnforcedConstraintAnalysis,
)
from ASN1spect.Analysis.RecursiveTypeAnalysis import RecursiveTypeAnalysis
from ASN1spect.asn1c.Constraints import (
    asn_encoding_constraints,
    asn_per_encoding_constraint,
    asn_per_encoding_constraints,
)
from ASN1spect.asn1c.Operations import asn_type_operation
from ASN1spect.asn1c.StructureKind import structure_type
from ASN1spect.asn1c.utils import set_encoding_constraints
from ASN1spect.Checkpoint import Checkpoint


class asn_type:
    inherit_symbol_checked = {}
    types_checked = {}

    symbolic_constraints = {}
    checkpoint = Checkpoint()
    NativeEnumerated_Types = checkpoint.NativeEnumerated_Types or {}
    NativeEnumerated_Timeouts = checkpoint.NativeEnumerated_Timeouts or {}
    inherit_symbol_problems = checkpoint.inherit_symbol_problems or {}
    AnalyzedTypes = {}

    def __init__(self, proj: ASN1AngrProject = None, symbol=None):
        self.name = "Unknown"
        self.xml_tag = ""
        self.op = asn_type_operation()
        self.elements_count = 0
        self.elements = []  # asn_member()
        self.encoding_constraints = 0
        self.specifics = (
            0  # Additional ptr to specs. Used in ENUMs and maybe other types
        )

        self.symbol = symbol
        self.recursive = False
        self.constraints = 0
        self.pointer = -1  # Pointer to itself in the code

        self.proj = proj
        if self.proj.get_project() not in self.symbolic_constraints:
            self.symbolic_constraints[self.proj.get_project()] = {}

        if self.proj not in self.types_checked:
            self.types_checked[self.proj] = set()

    # older versions of asn1c have a different structure layout. Find the correct one to use.
    # In the older version, the "elements" field matches to encode_uper function. If it does, use the other structure type.
    def determine_structure_type(self, value):
        angrProj = self.proj.get_project()

        elements_symbol = angrProj.loader.find_symbol(
            value.asn_TYPE_descriptor_t.elements.intmax_t.concrete
        )
        oer_constraints = angrProj.loader.find_symbol(
            value.asn_TYPE_descriptor_t.encoding_constraints.oer_constraints.intmax_t.concrete
        )
        per_constraints = angrProj.loader.find_symbol(
            value.asn_TYPE_descriptor_t.encoding_constraints.per_constraints.intmax_t.concrete
        )
        general_constraints = angrProj.loader.find_symbol(
            value.asn_TYPE_descriptor_t.encoding_constraints.general_constraints.intmax_t.concrete
        )

        outmost_tag = angrProj.loader.find_symbol(
            value.asn_TYPE_descriptor_t_legacy.outmost_tag.intmax_t.concrete
        )

        if (
            oer_constraints != None and oer_constraints.name.startswith("asn_PER_type_")
        ) or (per_constraints != None and per_constraints.name.endswith("_constraint")):
            return value.asn_TYPE_descriptor_t_no_oer, structure_type.MODERN_NO_OER

        if general_constraints != None:
            # Check if the general constraints actually points to the elements field. If it does, either the per_constraints or oer_constraints are not in the structure.
            if general_constraints.name.startswith("asn_MBR_"):
                # we've already handled the case of no OER, so this must be no per.
                return value.asn_TYPE_descriptor_t_no_per, structure_type.MODERN_NO_PER
            if general_constraints.name.endswith("_constraint"):
                return value.asn_TYPE_descriptor_t, structure_type.MODERN

        if (
            outmost_tag != None
            and "_decode_aper" in outmost_tag.name
            and "_encode_xer" in per_constraints.name
        ):
            return (
                value.asn_TYPE_descriptor_t_legacy_with_aper,
                structure_type.LEGACY_WITH_APER,
            )

        # if PER constraints point to the elements, then both oer and per are disabled.
        if per_constraints != None:
            if per_constraints.name.startswith("asn_MBR_"):
                return (
                    value.asn_TYPE_descriptor_t_neither,
                    structure_type.MODERN_NEITHER,
                )
            if "_encode_xer" in per_constraints.name:
                return value.asn_TYPE_descriptor_t_legacy, structure_type.LEGACY
            if per_constraints.name.startswith("asn_PER_type"):
                return value.asn_TYPE_descriptor_t, structure_type.MODERN

        if elements_symbol != None:
            if elements_symbol.name.endswith("_encode_uper"):
                return value.asn_TYPE_descriptor_t_legacy, structure_type.LEGACY
            elif elements_symbol.name.endswith("_encode_aper"):
                return (
                    value.asn_TYPE_descriptor_t_legacy_with_aper,
                    structure_type.LEGACY_WITH_APER,
                )
            elif elements_symbol.name.startswith("asn_MBR_"):
                return value.asn_TYPE_descriptor_t, structure_type.MODERN

        if oer_constraints != None and oer_constraints.name.startswith("asn_OER_type"):
            return value.asn_TYPE_descriptor_t, structure_type.MODERN

        print(
            "Warning: We couldn't determine what type of structure to use. Just returning the modern type."
        )
        print("Outmost tag", outmost_tag)
        print("Elements symbol points to", elements_symbol)
        print("oer constraints are", oer_constraints)
        print("per constraints are", per_constraints)
        print("general constraints are", general_constraints)
        return value.asn_TYPE_descriptor_t, structure_type.MODERN

    def determine_member_kind(self, elements, kind):
        # print("Trying to determine member structure of", elements.deref.asn_TYPE_member_t.array(self.elements_count)[0])

        if kind == structure_type.MODERN:
            return elements.deref.asn_TYPE_member_t.array(self.elements_count)
        elif kind == structure_type.MODERN_NO_OER:
            return elements.deref.asn_TYPE_member_t_no_oer.array(self.elements_count)
        elif kind == structure_type.MODERN_NO_PER:
            return elements.deref.asn_TYPE_member_t_no_per.array(self.elements_count)
        elif kind == structure_type.MODERN_NEITHER:
            return elements.deref.asn_TYPE_member_t_neither.array(self.elements_count)
        elif kind == structure_type.LEGACY or kind == structure_type.LEGACY_WITH_APER:
            return elements.deref.asn_TYPE_member_t_legacy.array(self.elements_count)

    def getPtrType(self, op):
        return {
            "asn_OP_NativeInteger": "long *",
            "asn_OP_PrintableString": "PrintableString_t *",
            "asn_OP_BIT_STRING": "BIT_STRING_t *",
            "asn_OP_NumericString": "OCTET_STRING_t *",
            "asn_OP_IA5String": "OCTET_STRING_t *",
            "asn_OP_OCTET_STRING": "OCTET_STRING_t *",
            "asn_OP_NativeEnumerated": "long *",
            "asn_OP_OPEN_TYPE": "asn_CHOICE_specifics_t *",
            "asn_OP_CHOICE": "asn_CHOICE_specifics_t *",
            "asn_OP_INTEGER": "INTEGER_t *",
            "asn_OP_SEQUENCE_OF": "asn_anonymous_set_ *",
        }.get(op, "type error")

    def get_options(self):
        options = (
            angr.options.resilience.union(angr.options.refs)
            .union(angr.options.symbolic)
            .union(angr.options.common_options)
            .union(angr.options.simplification)
        )
        # options = angr.options.unicorn
        options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        options.add(angr.options.MEMORY_SYMBOLIC_BYTES_MAP)
        options.add(angr.options.REVERSE_MEMORY_NAME_MAP)
        options.add(angr.options.LAZY_SOLVES)
        # options.add(angr.options.CONCRETIZE)
        # options.add(angr.options.UNICORN_AGGRESSIVE_CONCRETIZATION)
        options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
        # options.add(angr.options.UNICORN_THRESHOLD_CONCRETIZATION)
        options.add(angr.options.TRACK_SOLVER_VARIABLES)

        return options

    def setup_simgr(self, type_ptr, symbol, op, default_type):
        symbolic_var = claripy.BVS("symbolic_var", 64)
        ptr_to_symbolicvar = angr.PointerWrapper(symbolic_var, buffer=True)
        init_state = proj.factory.full_init_state(add_options=self.get_options())

        if default_type == None and op != None:
            ptrType = self.getPtrType(op.name)
        elif default_type == None and op == None:
            ptrType = "long *"
            print("ERROR:", symbol, type_ptr, self)
        else:
            ptrType = default_type

        if ptrType == None:
            ptrType = "long *"

        if op != None:
            print("PtrType is", ptrType, op.name)

        type_sig = angr.types.parse_signature(
            """static int
			memb_value_constraint_121(const asn_TYPE_descriptor_t *td, const """
            + ptrType
            + """ sptr,
			void *ctfailcb, void *app_key)"""
        )  # Removed app_constraint_failed_f type from ctfailcb and sptr changed to const long, instead of void*
        # The reason for changing this is the symbolic execution results are usable like this, but not when the definitions are the default

        prototype = angr.sim_type.SimTypeFunction(type_sig.args, type_sig.returnty)
        cc = proj.factory.cc()
        if type == None:
            state = proj.factory.call_state(
                symbol.rebased_addr,
                type_ptr,
                ptr_to_symbolicvar,
                cc=cc,
                prototype=prototype,
                base_state=init_state,
            )
        else:
            state = proj.factory.call_state(
                symbol.rebased_addr,
                type_ptr,
                symbolic_var,
                cc=cc,
                prototype=prototype,
                base_state=init_state,
            )

        # state.solver.add(state.regs.eax == 0)
        # callfunc = proj.factory.callable(symbol.rebased_addr, concrete_only=False, perform_merge=True, prototype=prototype, cc=cc, base_state = init_state)
        simgr = proj.factory.simulation_manager(
            state, save_unconstrained=True, save_unsat=True, completion_mode=all
        )

        # simgr.use_technique(angr.exploration_techniques.Threading(threads=64))
        simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=2048))
        simgr.use_technique(angr.exploration_techniques.Timeout(timeout=180))
        simgr.use_technique(angr.exploration_techniques.Suggestions())

        return simgr, symbolic_var

    def run_symbolic(self, type_ptr, symbol, op, default_type=None):
        if (
            symbol.name == "S1AP_PLMNidentity_constraint"
            or symbol.name == "S1AP_ProtocolExtensionID_constraint"
        ):
            return

        proj = self.proj.get_project()

        if symbol.name in self.symbolic_constraints[proj]:
            return self.symbolic_constraints[proj][symbol.name]

        # print("run symbolic", symbol, op, hex(type_ptr))

        simgr, symbolic_var = self.setup_simgr(type_ptr, symbol, op, default_type)

        while len(simgr.active) > 0:
            # simgr2.explore(find=0xb01000) # Use this address to determine when a function returns.
            simgr.step()

        # print(len(simgr2.deadended))

        if len(simgr.deadended) == 0:
            self.symbolic_constraints[proj][symbol.name] = self.run_symbolic(
                type_ptr, symbol, op, "long"
            )
            return self.symbolic_constraints[proj][symbol.name]

        if len(simgr.timeout) != 0:
            print(
                "Some execution paths timed out. Constraints are questionable. Double check them"
            )

        for state2 in simgr.deadended:
            if state2.solver.satisfiable(extra_constraints=[state2.regs.eax == 0]):
                if (
                    state2.solver.constraints == None or state2.solver.constraints == []
                ) and default_type == None:
                    self.symbolic_constraints[proj][symbol.name] = self.run_symbolic(
                        type_ptr, symbol, op, "long"
                    )

                    return self.symbolic_constraints[proj][symbol.name]
                else:
                    self.symbolic_constraints[proj][symbol.name] = (
                        state2.solver.constraints
                    )

                if len(state2.solver.constraints) == 0:
                    return []

                real_symbolic_var = state2.solver.eval(
                    symbolic_var, extra_constraints=[state2.regs.eax == 0]
                )
                symbolic_var_equal_ops = []

                for constraint in state2.solver.constraints:
                    if len(constraint.args) > 0:
                        for arg in constraint.args:
                            if type(arg) != bool:
                                for var in arg.variables:
                                    # If there is some constraint that says our symbolic var must be equal to some value....
                                    if (
                                        "symbolic_var" in var
                                        and constraint.op == "__eq__"
                                    ):
                                        # Its likely an entire offset to the symbolic var (since its a pointer)
                                        # Evaluate it
                                        evaled = hex(state2.solver.eval(arg))
                                        # print("I think this constraint makes the symbolic var of interest", evaled, "instead of", hex(real_symbolic_var))
                                        # Map the symbolic var for when a memory address is used
                                        symbolic_var_equal_ops.append(
                                            ("mem_" + str(evaled)[2:], arg)
                                        )
                            else:
                                print(
                                    "weird arg",
                                    arg,
                                    constraint,
                                    state2.solver.constraints,
                                    symbol.name,
                                )
                                # TODO

                return self.symbolic_constraints[proj][symbol.name]
            else:
                print(
                    "Found no satisfiable constraints for eax == 0",
                    state2.solver.constraints,
                )
                # raise Exception("Found no satisfiable constraints for eax == 0 " + str(symbol) + str(type_ptr))

        # while len(simgr.active) > 0:

    def check_inherit_symbol(self, inherit_symbol):
        if self.proj not in self.inherit_symbol_checked:
            self.inherit_symbol_checked[self.proj] = []
        if inherit_symbol.rebased_addr in self.inherit_symbol_checked[self.proj]:
            return

        self.inherit_symbol_checked[self.proj].append(inherit_symbol.rebased_addr)
        # print("Checking inherit symbol. Our type descriptor is", self.symbol)
        target = self.encoding_constraints.general_constraints
        # print("The target is", target)
        angrProj = self.proj.get_project()

        init_state = angrProj.factory.full_init_state(add_options=self.get_options())

        type_sig = angr.types.parse_signature(
            """static void FANSSpeedIndicatedMetric_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td)"""
        )

        prototype = angr.sim_type.SimTypeFunction(type_sig.args, type_sig.returnty)
        cc = angrProj.factory.cc()
        call_state = angrProj.factory.call_state(
            inherit_symbol.rebased_addr,
            self.symbol.rebased_addr,
            cc=cc,
            prototype=prototype,
            base_state=init_state,
        )

        simgr = angrProj.factory.simulation_manager(
            call_state, save_unconstrained=False, save_unsat=False, completion_mode=all
        )

        # simgr.use_technique(angr.exploration_techniques.Threading(threads=64))
        simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=2048))
        simgr.use_technique(angr.exploration_techniques.Timeout(timeout=180))
        simgr.use_technique(angr.exploration_techniques.Suggestions())

        while len(simgr.active) > 0:
            simgr.step()

            if (
                len(simgr.deadended) > 50
            ):  # Don't run for too long, this problem should only manifest it easy-to-run symbolic execution, so this many deadends likely means there is no issue in this function...
                break

        before, after = None, None

        stash = None
        if len(simgr.deadended) > 0:
            stash = simgr.deadended
        # elif len(simgr.errored) > 0:
        # 	stash = simgr.errored

        if stash != None:
            for symbol in angrProj.loader.symbols:
                if symbol.rebased_addr == target.rebased_addr and before == None:
                    before = symbol
                    # print("Before symbol is", before)

                if (
                    symbol.rebased_addr
                    == stash[0]
                    .mem[self.symbol.rebased_addr]
                    .asn_TYPE_descriptor_t_legacy.check_constraints.uint32_t.concrete
                    and after == None
                ):
                    after = symbol
                    # print("After symbol is", after)

                if before != None and after != None:
                    break
        else:
            print(
                "I don't know what symbolic execution stash to check. Here's the simgr",
                simgr,
            )

        if (
            before != None
            and after != None
            and before.rebased_addr != after.rebased_addr
        ):
            if angrProj.filename not in inherit_symbol_problems:
                inherit_symbol_problems[angrProj.filename] = []

            if self.symbol.name not in inherit_symbol_problems[angrProj.filename]:
                inherit_symbol_problems[angrProj.filename].append(self.symbol.name)

            self.checkpoint.inherit_symbol_problems = inherit_symbol_problems

            # with open("inherit_symbols.json", "w") as ofile:
            # 	ofile.write(json.dumps(inherit_symbol_problems, indent=4, default=vars))

            # print("Value before symbolic execution:", init_state.mem[asn_symbol.rebased_addr + 32].int.concrete, "Value after:", simgr.deadended[0].mem[asn_symbol.rebased_addr + 32].int.concrete)

    def _initialize_basic_attributes(self, value, symbol, proj):
        """Initializes basic attributes of the asn_type instance."""
        if proj is not None:
            self.proj = proj
        angrProj = self.proj.get_project()

        self.name = value.asn_TYPE_descriptor_t.name.deref.string.concrete.decode(
            "ascii"
        )
        self.xml_tag = value.asn_TYPE_descriptor_t.xml_tag.deref.string.concrete.decode(
            "ascii"
        )
        self.pointer = value.uint32_t.concrete
        self.symbol = symbol
        self.encoding_constraints = asn_encoding_constraints()

        self.struct, self.kind = self.determine_structure_type(value)
        self.elements_count = self.struct.elements_count.uint32_t.concrete
        self.specifics = self.struct.specifics  # ptr to specifics

        return angrProj

    def _determine_operation(self, struct, kind, angrProj):
        """Determines the ASN.1 operation type."""
        op_symbol = None
        if kind >= structure_type.MODERN and struct.op.uint32_t.concrete != 0:
            op_symbol = angrProj.loader.find_symbol(struct.op.uint32_t.concrete)
            self.op.determineOperation(struct.op, kind)
        elif kind == structure_type.LEGACY or kind == structure_type.LEGACY_WITH_APER:
            self.op.determineOperation(struct, kind)
        return op_symbol

    def _analyze_members(self, struct, kind, parents, angrProj, op_symbol):
        """Analyzes the members of the ASN.1 type recursively."""
        # Import Member here instead of at module level to prevent circular imports
        from ASN1spect.asn1c.Member import asn_member

        if struct.elements.intmax_t.concrete != 0:
            members = self.determine_member_kind(struct.elements, kind)
            elements_sym = angrProj.loader.find_symbol(struct.elements.concrete)

            if elements_sym is not None and elements_sym.name.startswith("asn_MBR_"):
                for i in range(self.elements_count):
                    p = copy.copy(parents)
                    sym = angrProj.loader.find_symbol(self.pointer)
                    if sym is not None:
                        p.append(sym)
                    else:
                        p.append(self.pointer)
                    member = asn_member(
                        self.proj,
                        members[i],
                        self.elements_count,
                        self.name,
                        p,
                        kind,
                        op_symbol if kind >= structure_type.MODERN else None,
                    )
                    member.determineRecursiveMembers()
                    self.elements.append(member)
            else:
                print(
                    "Look at this, the structure definition may be wrong for this binary."
                )
                print(struct)
                print(
                    "Specifically, the elements of", elements_sym, kind, struct.elements
                )

    def _set_encoding_constraints(self, struct, kind, angrProj):
        """Sets the encoding constraints for the ASN.1 type."""
        if (
            kind >= structure_type.MODERN
            and struct.encoding_constraints.intmax_t.concrete != 0
        ):
            if kind != structure_type.MODERN_NO_PER:
                if (
                    struct.encoding_constraints.asn_encoding_constraints_t.per_constraints.intmax_t.concrete
                    != 0
                ):
                    constraints = struct.encoding_constraints.asn_encoding_constraints_t.per_constraints.deref.asn_per_constraints_t
                    self.encoding_constraints = set_encoding_constraints(
                        self.encoding_constraints,
                        constraints,
                        struct.encoding_constraints.asn_encoding_constraints_t.general_constraints,
                        angrProj,
                    )
            self.encoding_constraints.general_constraints = angrProj.loader.find_symbol(
                struct.encoding_constraints.asn_encoding_constraints_t.general_constraints.intmax_t.concrete
            )
        elif kind == structure_type.LEGACY or kind == structure_type.LEGACY_WITH_APER:
            if struct.per_constraints.intmax_t.concrete != 0:
                constraints = struct.per_constraints.deref.asn_per_constraints_t
                self.encoding_constraints = set_encoding_constraints(
                    self.encoding_constraints,
                    constraints,
                    struct.check_constraints,
                    angrProj,
                )
            self.encoding_constraints.general_constraints = angrProj.loader.find_symbol(
                struct.check_constraints.intmax_t.concrete
            )

    def _handle_native_enumerated(self, kind, op_symbol, angrProj):
        """Handles logic specific to NativeEnumerated types."""
        if self.encoding_constraints.general_constraints is not None:
            ourSymbolName = self.symbol.name[8:]
            digits = extract_trailing_digits(ourSymbolName)
            numdigits = len(digits)
            if numdigits == 0:
                digits = "1"
            else:
                ourSymbolName = ourSymbolName[: -(numdigits + 1)]

            enum2value = angrProj.loader.find_symbol(
                "asn_MAP_" + ourSymbolName + "_enum2value_" + digits
            )

            if enum2value is not None:
                if angrProj.filename not in self.NativeEnumerated_Types:
                    self.NativeEnumerated_Types[angrProj.filename] = []
                if (
                    self.symbol.name
                    not in self.NativeEnumerated_Types[angrProj.filename]
                ):
                    self.NativeEnumerated_Types[angrProj.filename].append(
                        self.symbol.name
                    )
                    self.checkpoint.NativeEnumerated_Types = self.NativeEnumerated_Types

        # Handle specific constraints for NativeEnumerated
        if (
            kind >= structure_type.MODERN
            and kind != structure_type.MODERN_NO_PER
            and op_symbol is not None
        ):
            if op_symbol.name == "asn_OP_NativeEnumerated" and self.specifics != 0:
                self.encoding_constraints.per_constraints.value = (
                    asn_per_encoding_constraint()
                )
                self.encoding_constraints.per_constraints.value.lower_bound = 0
                self.encoding_constraints.per_constraints.value.upper_bound = (
                    self.specifics.deref.asn_INTEGER_specifics_t.map_count.uint32_t.concrete
                    - 1
                )
        elif kind == structure_type.MODERN and op_symbol is None:
            print("No op was detected for", self)

    def _check_inherit_symbol_logic(self, angrProj):
        """Checks for and handles inherit_TYPE_descriptor symbols."""
        if self.encoding_constraints.general_constraints is not None:
            ourSymbolName = self.symbol.name[8:]
            digits = extract_trailing_digits(ourSymbolName)
            numdigits = len(digits)
            if numdigits == 0:
                digits = "1"
            else:
                ourSymbolName = ourSymbolName[: -(numdigits + 1)]

            ourSymbolName = ourSymbolName + "_" + digits
            inherit_symbol = angrProj.loader.find_symbol(
                ourSymbolName + "_inherit_TYPE_descriptor"
            )
            if inherit_symbol is not None:
                self.check_inherit_symbol(inherit_symbol)

    def Analyze(
        self,
        proj: ASN1AngrProject,
        value: angr.state_plugins.view.SimMemView,
        parents,
        symbol,
    ):
        """Analyzes the ASN.1 type descriptor by breaking down the process into smaller steps."""

        if proj is not None and proj not in self.AnalyzedTypes:
            self.AnalyzedTypes[proj] = {}

        # Step 0: Check if already processed
        if (
            proj is not None
            and proj in self.types_checked
            and self.pointer in self.types_checked[proj]
            or self.pointer in self.AnalyzedTypes[proj]
        ):
            # print("Skipping processing of type", self.name, "because it was already processed.")
            return

        # Step 1: Initialize basic attributes and determine structure kind
        angrProj = self._initialize_basic_attributes(value, symbol, proj)

        if (
            proj is not None
            and proj in self.types_checked
            and self.pointer in self.types_checked[proj]
            or self.pointer in self.AnalyzedTypes[proj]
        ):
            # print("Skipping processing of type", self.name, "because it was already processed.")
            return

        self.AnalyzedTypes[proj][self.pointer] = self

        # Step 2: Determine the operation type
        op_symbol = self._determine_operation(self.struct, self.kind, angrProj)

        self.op_symbol = op_symbol

        # Step 3: Analyze members recursively
        self._analyze_members(self.struct, self.kind, parents, angrProj, op_symbol)

        # if self.pointer in self.types_checked[proj]:
        # 	return

        # Step 4: Set encoding constraints
        self._set_encoding_constraints(self.struct, self.kind, angrProj)

        # # Step 5: Handle NativeEnumerated specific logic
        # self._handle_native_enumerated(kind, op_symbol, angrProj)

        # # Step 6: Check for inherit_TYPE_descriptor symbol
        # self._check_inherit_symbol_logic(angrProj)

        # print("\nRegistered Analyses:")
        # for name in Analysis.get_registered_analyses().keys():
        # 	print(f"- {name}")

        # The other analyses work on members and the analysis engine is built to work with types specifically.
        # Additional custom analyses can be registered to work on members, but for now we only run the two analyses that work on the type itself.
        # It is faster to integrate the other analysis strategies while looping through the types rather than causing an additional loop over the types for each analysis.

        # print("NativeEnumerated Types is", results)

        # Mark as processed
        self.types_checked[proj].add(self.pointer)
        self.AnalyzedTypes[proj][self.pointer] = self

        # print("Done processing type", self.name)

    def __str__(self):
        return (
            "["
            + str(self.proj.get_binary())
            + "] asn_type: ["
            + self.name
            + "]"
            + " elements: "
            + str(self.elements_count)
        )

    @classmethod
    def GetType(cls, proj, ptr):
        return cls.AnalyzedTypes[proj][ptr]

    @classmethod
    def run_all_nondifferential_analyses(cls, proj):
        if proj in cls.AnalyzedTypes:
            for i, t in enumerate(
                tqdm(
                    cls.AnalyzedTypes[proj].values(),
                    desc=f"[*] Analyzing ASN.1 symbols",
                    position=1,
                    leave=False,
                )
            ):
                # print("Running analysis on", t.name)
                results = Analysis.run_all_nondifferential_analyses(t)

                cls.checkpoint.inherit_symbol_problems = results[
                    "NonEnforcedConstraintAnalysis"
                ]
                if "EnumerationAnalysis" in results:
                    cls.checkpoint.NativeEnumerated_Types = results[
                        "EnumerationAnalysis"
                    ]
                elif "DifferentialEnumerationAnalysis" in results:
                    native_enum_results = results["DifferentialEnumerationAnalysis"]
                    if (
                        isinstance(native_enum_results, dict)
                        and "NativeEnumerated_Types" in native_enum_results
                    ):
                        cls.checkpoint.NativeEnumerated_Types = native_enum_results[
                            "NativeEnumerated_Types"
                        ]
                    else:
                        cls.checkpoint.NativeEnumerated_Types = native_enum_results
                    if (
                        isinstance(native_enum_results, dict)
                        and "NativeEnumerated_Timeouts" in native_enum_results
                    ):
                        cls.checkpoint.NativeEnumerated_Timeouts = native_enum_results[
                            "NativeEnumerated_Timeouts"
                        ]
                cls.checkpoint.recursive_types = results["RecursiveTypeAnalysis"]
                cls.checkpoint.array_mismatches = results["IncompleteTypeGeneration"]

                # print("")
                # print("incomplete type gen is", cls.checkpoint.array_mismatches)
                # print("recursive types is", cls.checkpoint.recursive_types)
                # print("")


def extract_trailing_digits(s):
    match = re.search(r"(\d+)$", s)
    return match.group(0) if match else ""
