from typing import Optional

import angr

from ASN1nspect.Analysis.Analysis import Analysis
from ASN1nspect.asn1c.Constraints import (
    asn_encoding_constraints,
    asn_per_encoding_constraint,
    asn_per_encoding_constraints,
)
from ASN1nspect.asn1c.StructureKind import structure_type


def extract_trailing_digits(s):
    """Extract trailing digits from a string"""
    import re

    match = re.search(r"\d+$", s)
    return match.group(0) if match else ""


@Analysis.register
class EnumerationAnalysis(Analysis):
    NativeEnumerated_Types = {}
    cfg = {}

    ignore_types = [
        "asn_DEF_NativeEnumerated",
        "asn_DEF_ENUMERATED",
        "asn_DEF_OBJECT_IDENTIFIER",
        "asn_DEF_RELATIVE_OID",
        "asn_DEF_NULL",
        "asn_DEF_UTF8String",
    ]

    def __init__(self, type1: "asn_type", type2: Optional["asn_type"] = None):
        super().__init__(type1, type2, False)

    def analyze(self):
        if self.type1.encoding_constraints.general_constraints is not None:
            ourSymbolName = self.type1.symbol.name[8:]
            digits = extract_trailing_digits(ourSymbolName)
            numdigits = len(digits)
            if numdigits == 0:
                digits = "1"
            else:
                ourSymbolName = ourSymbolName[: -(numdigits + 1)]

            angrProj = self.type1.proj.get_project()
            enum2value = angrProj.loader.find_symbol(
                "asn_MAP_" + ourSymbolName + "_enum2value_" + digits
            )

            # if enum2value is not None:
            # 	# Check for ber_decode calls from CFG
            # 	ber_decode_symbol = angrProj.loader.find_symbol("ber_decode")
            # 	if ber_decode_symbol:
            # 		ber_decode_addr = ber_decode_symbol.rebased_addr
            # 		#print(f"Found ber_decode at {hex(ber_decode_addr)}")

            # 		binary = self.type1.proj.binary
            # 		if binary not in self.cfg:
            # 			try:
            # 				# Generate CFG
            # 				self.cfg[binary] = angrProj.analyses.CFGFast()
            # 			except Exception as e:
            # 				print(f"Error generating CFG: {e}")
            # 				self.cfg[binary] = None

            # 		if binary in self.cfg and self.cfg[binary] is not None:
            # 			# Find all callers of ber_decode
            # 			ber_decode_callers = []

            # 			target_function_addr = None
            # 			# Functions are stored in the knowledge base (kb) populated by the CFG analysis
            # 			for addr, func in self.cfg[binary].kb.functions.items():
            # 				if func.name == "ber_decode":
            # 					target_function_addr = addr
            # 					break

            # 			callers = []
            # 			if target_function_addr is not None:
            # 				if target_function_addr in self.cfg[binary].kb.callgraph:
            # 					# predecessors() gives an iterator over addresses of functions that call target_function_addr
            # 					for caller_addr in self.cfg[binary].kb.callgraph.predecessors(target_function_addr):
            # 						caller_func = self.cfg[binary].kb.functions.get(caller_addr) # Get the Function object for the caller
            # 						if caller_func:
            # 							callers.append({'name': caller_func.name, 'address': hex(caller_addr)})
            # 						else:
            # 							# This case should be rare if the callgraph is consistent with kb.functions
            # 							callers.append({'name': f"Unknown function at {hex(caller_addr)}", 'address': hex(caller_addr)})
            # 				#else:

            # 			if len(callers) > 0:
            # 				print("Found callers of ber_decode:", callers)
            # 				if angrProj.filename not in self.NativeEnumerated_Types:
            # 					self.NativeEnumerated_Types[angrProj.filename] = []
            # 				self.NativeEnumerated_Types[angrProj.filename].append(callers)

            # angrProj = self.type1.proj.get_project()
            # Find main function to trace call paths

            # 		if binary in self.cfg and self.cfg[binary] is not None:
            # 			# Find all callers of ber_decode
            # 			ber_decode_callers = []

            # 			for function in self.cfg[binary].functions.values():
            # 				for call_site in function.get_call_sites():
            # 					target = function.get_call_target(call_site)
            # 					if target == ber_decode_addr:
            # 						ber_decode_callers.append((function, call_site))

            # 			if ber_decode_callers:
            # 				print(f"Found {len(ber_decode_callers)} call sites to ber_decode:")
            # 				for function, call_site in ber_decode_callers:
            # 					print(f"  - {function.name} at {hex(function.addr)} calls ber_decode at {hex(call_site)}")

            # 				angrProj = self.type1.proj.get_project()
            # 				# Find main function to trace call paths
            # 				# Get all functions in the main binary
            # 				print("\nCall paths from all functions to ber_decode callers:")

            # 				# Get unique caller functions that call ber_decode
            # 				caller_functions = set([func for func, _ in ber_decode_callers])

            # 				# Get all functions in the binary
            # 				all_functions = self.cfg[binary].functions

            # 				paths_found = 0

            # 				# For each function in the binary, find paths to ber_decode callers
            # 				for source_addr, source_func in all_functions.items():
            # 					# Skip if the source function is already a ber_decode caller
            # 					if source_func in caller_functions:
            # 						continue

            # 					for caller in caller_functions:
            # 						# Use callgraph to find paths
            # 						callgraph = self.cfg[binary].functions.callgraph

            # 						# BFS to find paths
            # 						visited = set([source_addr])
            # 						queue = [(source_addr, [source_func.name])]

            # 						while queue:
            # 							current_addr, path = queue.pop(0)

            # 							if current_addr == caller.addr:
            # 								print(f"  {source_func.name} -> {' -> '.join(path[1:])} -> ber_decode")
            # 								paths_found += 1
            # 								break  # Found a path, move to next caller

            # 							# Get all functions called by current function
            # 							if current_addr in callgraph:
            # 								for callee_addr in callgraph[current_addr]:
            # 									if callee_addr not in visited:
            # 										callee_func = self.cfg[binary].functions.get_by_addr(callee_addr)
            # 										if callee_func:
            # 											visited.add(callee_addr)
            # 											new_path = path + [callee_func.name]
            # 											queue.append((callee_addr, new_path))

            # 						if paths_found == 0:
            # 							print("  No paths found from main")
            # 				else:
            # 					print("\nCould not find 'main' function to trace call paths")
            # 			else:
            # 				print("No calls to ber_decode were found in the CFG")

            if enum2value is not None:
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
                    # self.checkpoint.NativeEnumerated_Types = self.NativeEnumerated_Types

        return self.NativeEnumerated_Types
