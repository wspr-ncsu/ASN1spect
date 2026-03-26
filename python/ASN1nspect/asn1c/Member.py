import copy
import time
from dataclasses import dataclass

import angr
from ASN1nspect import AngrProject, ASN1AngrProject
from ASN1nspect.asn1c import *
from ASN1nspect.asn1c.Constraints import (asn_encoding_constraints,
                                          asn_per_encoding_constraints,
                                          asn_type_flags)
from ASN1nspect.asn1c.StructureKind import structure_type
from ASN1nspect.asn1c.utils import set_encoding_constraints
from ASN1nspect.Checkpoint import Checkpoint


@dataclass
class ArrayMismatch:
	name: str
	ElementCount: int
	RowCount: int
	Function: str

	def to_json(self):
		return {
			"name": self.name,
			"ElementCount": self.ElementCount,
			"RowCount": self.RowCount,
			"Function": self.Function
		}

	@classmethod
	def from_json(cls, data):
		return cls(
			name=data["name"],
			ElementCount=data["ElementCount"],
			RowCount=data["RowCount"],
			Function=data["Function"]
		)

class asn_member:
	checked_members = {}

	def __init__(self, proj: ASN1AngrProject, memb: angr.state_plugins.view.SimMemView, max_elems: int, parent_type_name: str, parents, kind: structure_type, symbol = None):
		# Import Type here instead of at module level to prevent circular imports
		from ASN1nspect.asn1c.Type import asn_type

		self.flags = asn_type_flags.ATF_NOFLAGS
		self.optional = -1 # Valid values are unsigned
		self.memb_offset = -1 # Valid values are unsigned
		self.tag = -1
		self.tag_mode = -1
		self.type = asn_type(proj, symbol)
		self.type_selector = -1
		self.encoding_constraints = asn_encoding_constraints()
		self.constraints = 0
		self.pointer = memb.uint32_t.concrete
		self.recursive = False

		self.kind = kind
		self.proj = proj
		self.memb = memb
		self.max_elems = max_elems
		self.parent_type_name = parent_type_name
		self.parents = parents
		self.checkpoint = Checkpoint()

		if self.proj not in self.checked_members:
			self.checked_members[self.proj] = set()

		self._initialize_basic_attributes()

	def __get_bytes(self, insn):
		# Go through the bytes in reverse order, and only indices [3-5)
		hex_string = ''.join(format(byte, '02x') for byte in insn.bytes[5:2:-1])

		#print(hex_string)

		# Convert the hexadecimal string to an integer
		result = int(hex_string, 16)

		return result

	def __checkForRecursion(self, angr_proj):
		if self.memb.type.uint32_t.concrete != 0:
			if self.memb.type.uint32_t.concrete not in self.parents:
				p = copy.copy(self.parents)
				p.append(self.memb.type.uint32_t.concrete)
				#print("Recursing on member", self.name, "member type ptr:", self.memb.type.deref)
				#print("Parents:", p)
				symbol = angr_proj.loader.find_symbol(self.memb.type.uint32_t.concrete)
				self.type.Analyze(self.proj, self.memb.type.deref, p, symbol)
			else:
				self.type = self.type.GetType(self.proj, self.memb.type.deref.uint32_t.concrete)
				self.recursive = True
				#recursive_types = self.checkpoint.recursive_types
				#name = self.proj.get_binary().name
				# if name not in recursive_types:
				# 	recursive_types[name] = []

				#symbol = angr_proj.loader.find_symbol(self.memb.type.uint32_t.concrete)

				# if symbol.name not in recursive_types[name]:
				# 	recursive_types[name].append(symbol.name)

				# parent_list = []
				# for p in self.parents:
				# 	sym = angr_proj.loader.find_symbol(p)
				# 	if sym != None:
				# 		parent_list.append((sym.name, sym.rebased_addr))

				# recursive_types[name][symbol.name].append(parent_list)
				# self.checkpoint.recursive_types = recursive_types

	def findInstruction(self, angr_proj, symbol, instruction_to_match):
		simgr = self.proj.create_simulation_manager(symbol) # 32 bytes after the first instruction of the function is when the asn_ioc_set_t variable is saved into RAX.

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

	def __checkForIOSFlaws(self, angr_proj, symbol):
		#print("[AT] We found the type selector symbol. It is", symbol)
		symbol = symbol.rebased_addr

		simgr = self.findInstruction(angr_proj, symbol, [0x48, 0x8D, 0x05]) # load effective address

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

			if self.type.elements_count != 0 and rows_count != self.type.elements_count:

				#print("[AT] Found a mismatch! Saving result.")

				array_mismatches = self.checkpoint.array_mismatches
				filename = angr_proj.filename

				if filename not in array_mismatches:
					array_mismatches[filename] = {}

				if self.parent_type_name not in array_mismatches[filename]:
					array_mismatches[filename][self.parent_type_name] = []

				element = {
					"name": self.name,
					"ElementCount": self.type.elements_count,
					"RowCount": rows_count,
					"Function": angr_proj.loader.find_symbol(self.type_selector).name
				}

				if element not in array_mismatches[filename][self.parent_type_name]:
					array_mismatches[filename][self.parent_type_name].append(element)
					self.checkpoint.array_mismatches = array_mismatches

				#raise Exception("Array mismatch found")
	def __fillEncodingConstraints(self, angr_proj):
		if self.kind >= structure_type.MODERN:
			if self.kind != structure_type.MODERN_NO_PER:
				constraints_ptr = self.memb.encoding_constraints.asn_encoding_constraints_t.per_constraints
				if constraints_ptr.intmax_t.concrete != 0:
					constraints = constraints_ptr.deref.asn_per_constraints_t
					self.encoding_constraints = set_encoding_constraints(self.encoding_constraints, constraints,
						self.memb.encoding_constraints.asn_encoding_constraints_t.general_constraints, angr_proj)
			else:
				general_constraints = self.memb.encoding_constraints.asn_encoding_constraints_t.general_constraints
				if general_constraints.deref.intmax_t.concrete != 0:
					self.encoding_constraints.general_constraints = angr_proj.loader.find_symbol(general_constraints.intmax_t.concrete)

		elif self.kind == structure_type.LEGACY or self.kind == structure_type.LEGACY_WITH_APER:
			if self.memb.per_constraints.intmax_t.concrete != 0:
				constraints = self.memb.per_constraints.deref.asn_per_constraints_t
				self.encoding_constraints = set_encoding_constraints(self.encoding_constraints, constraints,
					self.memb.memb_constraints.deref, angr_proj)
			elif self.memb.memb_constraints.deref.intmax_t.concrete != 0:
				self.encoding_constraints.general_constraints = angr_proj.loader.find_symbol(self.memb.memb_constraints.deref.intmax_t.concrete)

	def _initialize_basic_attributes(self):
		self.flags = self.memb.flags.uint32_t.concrete
		self.optional = self.memb.optional.uint32_t.concrete
		self.memb_offset = self.memb.memb_offset.uint32_t.concrete
		self.tag = self.memb.tag.uint32_t.concrete
		self.tag_mode = self.memb.tag_mode.int32_t.concrete
		self.name = self.memb.name.deref.string.concrete.decode("ascii")

		if self.kind >= structure_type.MODERN:
			self.type_selector = self.memb.type_selector.uint32_t.concrete

	def determineRecursiveMembers(self):

		angr_proj = self.proj.get_project()

		self.__checkForRecursion(angr_proj)

		if self.memb.type.uint32_t.concrete in self.checked_members[self.proj]:
			# print("Skipping member", self.name, "because it has already been checked.")
			return
		else:
			self.checked_members[self.proj].add(self.memb.type.uint32_t.concrete)

		#self.IOSAnalysis()
		self.__fillEncodingConstraints(angr_proj)

	def IOSAnalysis(self):
		angr_proj = self.proj.get_project()
		if self.kind >= structure_type.MODERN and self.type_selector != 0:
			symbol = angr_proj.loader.find_symbol(self.type_selector)
			# ^ we don't really wanna run symbolic execution on this if its legacy datastructure.
			# This is because when the legacy data structure was in the code base, there was no support for information object sets.

			if symbol != None:
				self.__checkForIOSFlaws(angr_proj, symbol)

	def __str__(self):
		return "asn_member: [" + self.name + "]" + " type: " + str(self.type) + " symbol: " + self.symbol