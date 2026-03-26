from typing import Optional

import angr

from ASN1spect.Analysis.Analysis import Analysis
from ASN1spect.asn1c.Constraints import (
    asn_encoding_constraints,
    asn_per_encoding_constraint,
    asn_per_encoding_constraints,
)
from ASN1spect.asn1c.StructureKind import structure_type


def extract_trailing_digits(s):
    """Extract trailing digits from a string"""
    import re

    match = re.search(r"\d+$", s)
    return match.group(0) if match else ""


def are_types_compatible(type1, type2):
    """Check if two ASN.1 types are compatible for encoding/decoding"""
    if type1 == type2:
        return True

    # Define compatibility groups
    compatible_groups = [
        {"SET", "SEQUENCE"},  # SET is compatible with SEQUENCE
        {"OCTET", "BIT"},  # OCTET string is compatible with BIT string
        {"OCTET", "UniversalString"},  # OCTET string is compatible with UniversalString
        {"OCTET", "GeneralizedTime"},
        {"OCTET", "UTCTime"},
        {"OCTET", "BMPString"},
        {"OCTET", "OBJECT"},
        {"OCTET", "RELATIVE"},
        {"OCTET", "ANY"},
    ]

    # Check if both types belong to the same compatibility group
    for group in compatible_groups:
        if type1 in group and type2 in group:
            return True

    return False


@Analysis.register
class DifferentialEnumerationAnalysis(Analysis):
    NativeEnumerated_Types = {}
    NativeEnumerated_Timeouts = {}
    inherit_symbol_checked = {}
    cfg = {}

    ignore_types = [
        "asn_DEF_NativeEnumerated",
        "asn_DEF_ENUMERATED",
        "asn_DEF_OBJECT_IDENTIFIER",
        "asn_DEF_RELATIVE_OID",
        "asn_DEF_NULL",
        "asn_DEF_UTF8String",
    ]

    def __init__(self, type1: "asn_type"):
        super().__init__(type1, False)

    def is_enum(self, type):
        if type.encoding_constraints.general_constraints is not None:
            ourSymbolName = type.symbol.name[8:]
            digits = extract_trailing_digits(ourSymbolName)
            numdigits = len(digits)
            if numdigits == 0:
                digits = "1"
            else:
                ourSymbolName = ourSymbolName[: -(numdigits + 1)]

            angrProj = type.proj.get_project()
            enum2value = angrProj.loader.find_symbol(
                "asn_MAP_" + ourSymbolName + "_enum2value_" + digits
            )

            return enum2value is not None

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

    def check_inherit_symbol(self, inherit_symbol):
        if self.type1.proj not in self.inherit_symbol_checked:
            self.type1.inherit_symbol_checked[self.type1.proj] = []
        if (
            inherit_symbol.rebased_addr
            in self.type1.inherit_symbol_checked[self.type1.proj]
        ):
            return None, None, None, False

        self.type1.inherit_symbol_checked[self.type1.proj].append(
            inherit_symbol.rebased_addr
        )
        # print("Checking inherit symbol. Our type descriptor is", self.symbol)
        target = self.type1.encoding_constraints.general_constraints
        # print("The target is", target)
        angrProj = self.type1.proj.get_project()

        init_state = angrProj.factory.full_init_state(add_options=self.get_options())

        type_sig = angr.types.parse_signature(
            """static void FANSSpeedIndicatedMetric_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td)"""
        )

        prototype = angr.sim_type.SimTypeFunction(type_sig.args, type_sig.returnty)
        cc = angrProj.factory.cc()
        call_state = angrProj.factory.call_state(
            inherit_symbol.rebased_addr,
            self.type1.symbol.rebased_addr,
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

        timeout_hit = len(simgr.timeout) > 0
        if timeout_hit:
            if angrProj.filename not in self.NativeEnumerated_Timeouts:
                self.NativeEnumerated_Timeouts[angrProj.filename] = []
            if (
                self.type1.symbol.name
                not in self.NativeEnumerated_Timeouts[angrProj.filename]
                and self.type1.symbol.name not in self.ignore_types
            ):
                self.NativeEnumerated_Timeouts[angrProj.filename].append(
                    self.type1.symbol.name
                )
                self.type1.checkpoint.NativeEnumerated_Timeouts = (
                    self.NativeEnumerated_Timeouts
                )

        before, after = None, None

        stash = None
        if len(simgr.deadended) > 0:
            stash = simgr.deadended
        # elif len(simgr.errored) > 0:
        # 	stash = simgr.errored

        der_encoder = None
        ber_decoder = None
        constraint_function = None

        if stash != None:
            for symbol in angrProj.loader.symbols:
                if (
                    symbol.rebased_addr
                    == stash[0]
                    .mem[self.type1.symbol.rebased_addr]
                    .asn_TYPE_descriptor_t_legacy.ber_decoder.uint32_t.concrete
                ):
                    ber_decoder = symbol
                    # print("After symbol is", after)

                if (
                    symbol.rebased_addr
                    == stash[0]
                    .mem[self.type1.symbol.rebased_addr]
                    .asn_TYPE_descriptor_t_legacy.der_encoder.uint32_t.concrete
                ):
                    der_encoder = symbol
                    # print("After symbol is", after)

                if (
                    symbol.rebased_addr
                    == stash[0]
                    .mem[self.type1.symbol.rebased_addr]
                    .asn_TYPE_descriptor_t_legacy.check_constraints.uint32_t.concrete
                ):
                    constraint_function = symbol

                if (
                    der_encoder != None
                    and ber_decoder != None
                    and constraint_function != None
                ):
                    break
        else:
            print(
                "I don't know what symbolic execution stash to check. Here's the simgr",
                simgr,
            )

        return der_encoder, ber_decoder, constraint_function, timeout_hit

    def analyze(self):
        angrProj = self.type1.proj.get_project()
        der_encoder = angrProj.loader.find_symbol(self.type1.op.der_encoder)
        ber_decoder = angrProj.loader.find_symbol(self.type1.op.ber_decoder)
        decoders_encoders = [
            ber_decoder,
            der_encoder,
            angrProj.loader.find_symbol(self.type1.op.xer_decoder),
            angrProj.loader.find_symbol(self.type1.op.xer_encoder),
            angrProj.loader.find_symbol(self.type1.op.uper_decoder),
            angrProj.loader.find_symbol(self.type1.op.uper_encoder),
        ]

        type_names = []
        for decoder_encoder in decoders_encoders:
            if decoder_encoder is not None:
                parts = decoder_encoder.name.split("_")
                assert len(parts) > 1, (
                    "Symbol is not the right format. Symbol: " + decoder_encoder.name
                )
                type_names.append(parts[0])

                # Check if all type names are compatible
        if len(type_names) > 1:
            # Find the first type that is not None and doesn't contain "primitive"
            reference_type = None
            for type_name in type_names:
                if (
                    type_name is not None
                    and "ber" != type_name
                    and "der" != type_name
                    and "xer" != type_name
                    and "uper" != type_name
                ):
                    reference_type = type_name
                    break

            # If no suitable reference type found, use the first non-None type
            if reference_type is None:
                reference_type = next(
                    (name for name in type_names if name is not None), type_names[0]
                )

            # Check for incompatible types

            for i, type_name in enumerate(type_names):
                if (
                    type_name is not None
                    and type_name != reference_type
                    and "ber" not in type_name
                    and "der" not in type_name
                    and "xer" not in type_name
                    and "uper" not in type_name
                ):
                    if (
                        not are_types_compatible(reference_type, type_name)
                        and decoders_encoders[i] is not None
                        and self.type1.symbol.name not in self.ignore_types
                    ):
                        # Found an incompatible type, this is a real issue
                        different_decoder_encoder = decoders_encoders[i]
                        print(
                            f"Incompatible type name '{type_name}' found in decoder/encoder: {different_decoder_encoder.name}. This is semantically different from encoding type: {reference_type}. The type is {self.type1.symbol.name}"
                        )

                        if angrProj.filename not in self.NativeEnumerated_Types:
                            self.NativeEnumerated_Types[angrProj.filename] = []

                        self.NativeEnumerated_Types[angrProj.filename].append(
                            self.type1.symbol.name
                        )
                        break

        ## Check enumerated types specifically a little bit more.

        if self.is_enum(self.type1):
            angrProj = self.type1.proj.get_project()
            native_integer_decode_ber = angrProj.loader.find_symbol(
                "NativeInteger_decode_ber"
            )
            native_integer_encode_der = angrProj.loader.find_symbol(
                "NativeInteger_encode_der"
            )

            # do the differential comparison between the BER/DER encoding of integers and enumerated types.
            # When enumerated types use integer decodes, they don't check the enum2map variable.

            if (
                native_integer_decode_ber is not None
                and native_integer_encode_der is not None
            ):
                if self.type1.kind <= structure_type.LEGACY_WITH_APER:
                    constraint_function = angrProj.loader.find_symbol(
                        self.type1.op.check_constraints
                    )
                elif self.type1.kind > structure_type.LEGACY_WITH_APER:
                    constraint_function = (
                        self.type1.encoding_constraints.general_constraints
                    )
                asn_generic_no_constraint = angrProj.loader.find_symbol(
                    "asn_generic_no_constraint"
                )

                ourSymbolName = self.type1.symbol.name[8:]
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
                    der_encoder, ber_decoder, constraint_function, timeout_hit = (
                        self.check_inherit_symbol(inherit_symbol)
                    )

                if (
                    der_encoder != None
                    and ber_decoder != None
                    and constraint_function != None
                    and native_integer_encode_der.rebased_addr
                    == der_encoder.rebased_addr
                    and native_integer_decode_ber.rebased_addr
                    == ber_decoder.rebased_addr
                    and constraint_function.rebased_addr
                    == asn_generic_no_constraint.rebased_addr
                ):
                    if angrProj.filename not in self.NativeEnumerated_Types:
                        self.NativeEnumerated_Types[angrProj.filename] = []
                    if (
                        self.type1.symbol.name
                        not in self.NativeEnumerated_Types[angrProj.filename]
                        and self.type1.symbol.name not in self.ignore_types
                    ):
                        self.NativeEnumerated_Types[angrProj.filename].append(
                            self.type1.symbol.name
                        )

        return {
            "NativeEnumerated_Types": self.NativeEnumerated_Types,
            "NativeEnumerated_Timeouts": self.NativeEnumerated_Timeouts,
        }
