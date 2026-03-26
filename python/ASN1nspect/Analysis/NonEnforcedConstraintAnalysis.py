from typing import Optional

import angr
import claripy
from ASN1nspect.Analysis.Analysis import Analysis

# from ASN1nspect.asn1c.Type import asn_type


def extract_trailing_digits(s):
	"""Extract trailing digits from a string"""
	import re
	match = re.search(r'\d+$', s)
	return match.group(0) if match else ""

@Analysis.register
class NonEnforcedConstraintAnalysis(Analysis):
	"""
	This class is used to analyze non-enforced constraints in ASN.1 structures.
	It provides methods to check if a constraint is enforced or not.
	"""

	inherit_symbol_checked = {}
	inherit_symbol_problems = {}

	def __init__(self, type1: "asn_type", type2: Optional["asn_type"] = None):
		super().__init__(type1, type2, False)

		#self.inherit_symbol_problems = self.type1.inherit_symbol_problems or {}

	def get_options(self):
		options = angr.options.resilience.union(angr.options.refs).union(angr.options.symbolic).union(angr.options.common_options).union(angr.options.simplification)
		#options = angr.options.unicorn
		options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
		options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
		options.add(angr.options.MEMORY_SYMBOLIC_BYTES_MAP)
		options.add(angr.options.REVERSE_MEMORY_NAME_MAP)
		options.add(angr.options.LAZY_SOLVES)
		#options.add(angr.options.CONCRETIZE)
		#options.add(angr.options.UNICORN_AGGRESSIVE_CONCRETIZATION)
		options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
		#options.add(angr.options.UNICORN_THRESHOLD_CONCRETIZATION)
		options.add(angr.options.TRACK_SOLVER_VARIABLES)

		return options

	def check_inherit_symbol(self, inherit_symbol):
		if self.type1.proj not in self.inherit_symbol_checked:
			self.type1.inherit_symbol_checked[self.type1.proj] = []
		if inherit_symbol.rebased_addr in self.type1.inherit_symbol_checked[self.type1.proj]:
			return

		self.type1.inherit_symbol_checked[self.type1.proj].append(inherit_symbol.rebased_addr)
		#print("Checking inherit symbol. Our type descriptor is", self.symbol)
		target = self.type1.encoding_constraints.general_constraints
		#print("The target is", target)
		angrProj = self.type1.proj.get_project()

		init_state = angrProj.factory.full_init_state(add_options=self.get_options())

		type_sig = angr.types.parse_signature("""static void FANSSpeedIndicatedMetric_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td)""")

		prototype = angr.sim_type.SimTypeFunction(type_sig.args, type_sig.returnty)
		cc = angrProj.factory.cc()
		call_state = angrProj.factory.call_state(inherit_symbol.rebased_addr, self.type1.symbol.rebased_addr, cc=cc, prototype=prototype, base_state = init_state)

		simgr = angrProj.factory.simulation_manager(call_state, save_unconstrained=False, save_unsat=False, completion_mode=all)

		#simgr.use_technique(angr.exploration_techniques.Threading(threads=64))
		simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=2048))
		simgr.use_technique(angr.exploration_techniques.Timeout(timeout=180))
		simgr.use_technique(angr.exploration_techniques.Suggestions())

		while len(simgr.active) > 0:
			simgr.step()

			if len(simgr.deadended) > 50: # Don't run for too long, this problem should only manifest it easy-to-run symbolic execution, so this many deadends likely means there is no issue in this function...
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
					#print("Before symbol is", before)

				if symbol.rebased_addr == stash[0].mem[self.type1.symbol.rebased_addr].asn_TYPE_descriptor_t_legacy.check_constraints.uint32_t.concrete and after == None:
					after = symbol
					#print("After symbol is", after)

				if before != None and after != None:
					break
		else:
			print("I don't know what symbolic execution stash to check. Here's the simgr", simgr)

		if before != None and after != None and before.rebased_addr != after.rebased_addr:
			if angrProj.filename not in self.inherit_symbol_problems:
				self.inherit_symbol_problems[angrProj.filename] = {}

			after_symbol = angrProj.loader.find_symbol(after.rebased_addr)
			if after is not None:
				after_symbol_name = after.name
			else:
				after_symbol_name = "Unknown"

			compared_constriants = True
			if after.name != "asn_generic_no_constraint":
				compared_constriants = self.run_comparison(before, after)

			result = None
			if compared_constriants:
				result = [before.name, after_symbol_name]

			if self.type1.symbol.name not in self.inherit_symbol_problems[angrProj.filename] and result is not None:
				self.inherit_symbol_problems[angrProj.filename][self.type1.symbol.name] = result

			#type1.checkpoint.inherit_symbol_problems = self.inherit_symbol_problems

			# with open("inherit_symbols.json", "w") as ofile:
			# 	ofile.write(json.dumps(inherit_symbol_problems, indent=4, default=vars))

			#print("Value before symbolic execution:", init_state.mem[asn_symbol.rebased_addr + 32].int.concrete, "Value after:", simgr.deadended[0].mem[asn_symbol.rebased_addr + 32].int.concrete)

	def run_comparison(self, before, after) -> bool:
		before_constraints = self.run_constraint_function(before)
		after_constraints = self.run_constraint_function(after)

		# print(f"Before constraints ({before.name}) length: {len(before_constraints)}")
		# print(f"After constraints ({after.name}) length: {len(after_constraints)}")

		# Check if number of states is the same
		# if len(before_constraints) != len(after_constraints):
		# 	print(f"WARNING: Different number of states between {before.name} ({len(before_constraints)}) and {after.name} ({len(after_constraints)})")

		if len(before_constraints) == 0 and len(after_constraints) == 0:
			return False

		# Compare constraints between corresponding states
		if len(before_constraints) != len(after_constraints) or after.name == "SEQUENCE_constraint":
			return True

		min_states = min(len(before_constraints), len(after_constraints))
		constraints_equivalent = True
		for i in range(min_states):
			before_state = before_constraints[i]
			after_state = after_constraints[i]

			# Compare constraints semantically rather than by string representation
			# This handles cases where variable names differ but constraints are equivalent
			before_satisfiable = before_state.solver.satisfiable()
			after_satisfiable = after_state.solver.satisfiable()

			if len(before_state.solver.constraints) != len(after_state.solver.constraints):
				constraints_equivalent = False

			# Check if constraints are semantically equivalent by checking mutual implication
			# constraints_equivalent = True
			if before_satisfiable != after_satisfiable:
				constraints_equivalent = False
			elif before_satisfiable:  # Only check further if both are satisfiable
				# Check if each constraint set implies the other
				for b_constraint in before_state.solver.constraints:
					# Check if negation of constraint is satisfiable in after_state
					if after_state.solver.satisfiable(extra_constraints=[b_constraint]):
						continue  # after state implies this constraint
					constraints_equivalent = False
					break

				if constraints_equivalent:
					for a_constraint in after_state.solver.constraints:
						# Check if negation of constraint is satisfiable in before_state
						if before_state.solver.satisfiable(extra_constraints=[a_constraint]):
							continue  # before state implies this constraint
						constraints_equivalent = False
						break

			if constraints_equivalent:
				return False
		return True

	def run_constraint_function(self, target):
		angrProj = self.type1.proj.get_project()

		init_state = angrProj.factory.full_init_state(add_options=self.get_options())

		type_sig = angr.types.parse_signature("""int ADSv2Level_constraint(asn_TYPE_descriptor_t *td, const void *sptr, void *ctfailcb, void *app_key)""")

		prototype = angr.sim_type.SimTypeFunction(type_sig.args, type_sig.returnty)
		cc = angrProj.factory.cc()
		# Create a symbolic variable to represent the input pointer (sptr)
		sptr_symbolic = claripy.BVS('sptr', angrProj.arch.bits)
		ptr_to_symbolicvar = angr.PointerWrapper(sptr_symbolic, buffer=True)

		call_state = angrProj.factory.call_state(target.rebased_addr, self.type1.symbol.rebased_addr, ptr_to_symbolicvar, 0, 0, cc=cc, prototype=prototype, base_state = init_state)

		simgr = angrProj.factory.simulation_manager(call_state, save_unconstrained=False, save_unsat=False, completion_mode=all)

		#simgr.use_technique(angr.exploration_techniques.Threading(threads=64))
		simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=2048))
		simgr.use_technique(angr.exploration_techniques.Timeout(timeout=180))
		simgr.use_technique(angr.exploration_techniques.Suggestions())

		while len(simgr.active) > 0:
			simgr.step()

			if len(simgr.deadended) > 50: # Don't run for too long, this problem should only manifest it easy-to-run symbolic execution, so this many deadends likely means there is no issue in this function...
				break

		# Filter deadended states to only include those where RAX is 0
		zero_return_states = []
		for state in simgr.deadended:
			if state.solver.satisfiable(extra_constraints=[state.regs.rax == 0]):
				state.add_constraints(state.regs.rax == 0)
				zero_return_states.append(state)

		return zero_return_states

	def analyze(self):
		"""
		Analyze the ASN.1 type(s) to identify non-enforced constraints.

		:return: A list of non-enforced constraints found in the type(s).
		:raises ValueError: If differential analysis is enabled but type2 is None.
		"""

		angrProj = self.type1.proj.get_project()

		if self.type1.encoding_constraints.general_constraints is not None:
			ourSymbolName = self.type1.symbol.name[8:]
			digits = extract_trailing_digits(ourSymbolName)
			numdigits = len(digits)
			if numdigits == 0:
				digits = "1"
			else:
				ourSymbolName = ourSymbolName[:-(numdigits + 1)]

			ourSymbolName = ourSymbolName + "_" + digits
			inherit_symbol = angrProj.loader.find_symbol(ourSymbolName + "_inherit_TYPE_descriptor")
			if inherit_symbol is not None:
				self.check_inherit_symbol(inherit_symbol)

		return self.inherit_symbol_problems