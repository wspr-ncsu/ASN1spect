from typing import Optional

import angr
from ASN1spect.Analysis.Analysis import Analysis
from ASN1spect.asn1c.StructureKind import structure_type

#from ASN1spect.asn1c.Type import asn_type

@Analysis.register
class IncompleteTypeGeneration(Analysis):

	array_mismatches = {}

	def __init__(self, type1: "asn_type", type2: Optional["asn_type"] = None):
		super().__init__(type1, type2, False)

		#self.type_selector = type1.type_selector

	def analyze(self):
		angr_proj = self.type1.proj.get_project()

		if self.type1.elements_count > 0:
			for element in self.type1.elements:
				if element.kind >= structure_type.MODERN and element.type_selector != 0:
					symbol = angr_proj.loader.find_symbol(element.type_selector)
					# ^ we don't really wanna run symbolic execution on this if its legacy datastructure.
					# This is because when the legacy data structure was in the code base, there was no support for information object sets.

					if symbol != None:
						self.__checkForIOSFlaws(element, symbol)

		return self.array_mismatches

	def findInstruction(self, symbol, instruction_to_match):
		simgr = self.type1.proj.create_simulation_manager(symbol) # 32 bytes after the first instruction of the function is when the asn_ioc_set_t variable is saved into RAX.
		angr_proj = self.type1.proj.get_project()

		found_instruction = None
		while len(simgr.active) > 0:

			for found in simgr.active:
				block = angr_proj.factory.block(found.addr)
				for instruction in block.capstone.insns:
					# print("Instruction:", instruction)

					for i in range(0, len(instruction.bytes)):
						bytes = instruction.bytes
						# print("[AT] The bytes we're considering:")

						if len(bytes) >= i + 2 and bytes[i] == instruction_to_match[0] and bytes[i+1] == instruction_to_match[1] and bytes[i+2] == instruction_to_match[2]:
							# print("[AT] ARRAY MISMATCH INSTRUCTION FOUND.")
							found_instruction = instruction
							# print("[AT] Found the desired instruction at address:", hex(instruction.address))
							simgr.explore(find=instruction.address)
							break
					if found_instruction != None:
						break
				if found_instruction != None:
					break

				# bytes = block.capstone.insns[0].insn.bytes
				# if bytes[0] == 0x48 and bytes[1] == 0x8D and bytes[2] == 0x05:
				# 	# Condition met, do something
				# 	print("[AT] ARRAY MISMATCH INSTRUCTION FOUND.")
				# 	found_instruction = True
				# 	print("[AT] Found the desired instruction at address:", found.addr)
				# 	break

			if found_instruction != None:
				break

			simgr.step()

		assert found_instruction != None and len(simgr.found) > 0, "Error: Could not find instruction in type to perform information object set analysis."

		return simgr

	def __checkForIOSFlaws(self, element, symbol):
		#print("[AT] We found the type selector symbol. It is", symbol)
		symbol_addr = symbol.rebased_addr
		angr_proj = self.type1.proj.get_project()

		simgr = self.findInstruction(symbol_addr, [0x48, 0x8D, 0x05]) # load effective address

		for found in simgr.found:
			block = angr_proj.factory.block(found.addr)

			# Convert the hexadecimal string to an integer
			result = self.__get_bytes(block.capstone.insns[0].insn)

			# print("[AT]", found.regs.rax)
			# print("[AT]", found.mem[found.regs.rip + result + 7].asn_ioc_set_t)
			#print(block.capstone.insns[0].insn.bytes)
			# run lea rax, [rip + result]. add 7 because the value of rip is taken after the lea instruction (which is 7 bytes long)

			rows = angr_proj.loader.find_symbol(found.mem[found.regs.rip + result + 7].asn_ioc_set_t.rows.uint32_t.concrete)

			# print("[AT] Rows test", rows)
			#print("member symbol", memb.type.deref.asn_TYPE_descriptor_t.name.deref.string.concrete)
			#print("Symbol for real:", memb.type.deref.asn_TYPE_descriptor_t.concrete)

			rows_count = found.mem[found.regs.rip + result + 7].asn_ioc_set_t.rows_count.uint32_t.concrete
			columns_count = found.mem[found.regs.rip + result + 7].asn_ioc_set_t.columns_count.uint32_t.concrete

			# print("[AT] Checking rows count == elements_count.", self.type.elements_count, rows_count)

			if element.type.elements_count != 0 and rows_count != element.type.elements_count and abs(rows_count - element.type.elements_count) < 3:

				#print("[AT] Found a mismatch! Saving result.")

				filename = angr_proj.filename

				if filename not in self.array_mismatches:
					self.array_mismatches[filename] = {}

				if self.type1.name not in self.array_mismatches[filename]:
					self.array_mismatches[filename][self.type1.name] = []

				result = {
					"name": self.type1.name,
					"ElementCount": element.type.elements_count,
					"RowCount": rows_count,
					"Function": symbol.name
				}

				if result not in self.array_mismatches[filename][self.type1.name]:
					self.array_mismatches[filename][self.type1.name].append(result)

	def __get_bytes(self, insn):
		# Go through the bytes in reverse order, and only indices [3-5)
		hex_string = ''.join(format(byte, '02x') for byte in insn.bytes[5:2:-1])

		#print(hex_string)

		# Convert the hexadecimal string to an integer
		result = int(hex_string, 16)

		return result