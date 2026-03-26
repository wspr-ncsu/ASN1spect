from enum import IntFlag, Enum
import angr

class asn_type_flags(IntFlag):
	ATF_NOFLAGS = 0
	ATF_POINTER = 0x01
	ATF_OPEN_TYPE = 0x02
	ATF_ANY_TYPE = 0x04

class asn_per_constraint_flags(IntFlag):
	APC_UNCONSTRAINED = 0x0
	APC_SEMI_CONSTRAINED = 0x1
	APC_CONSTRAINED = 0x2
	APC_EXTENSIBLE = 0x4

class asn_per_encoding_constraint:
	def __init__(self, ptr = 0):
		self.ptr = ptr
		self.flags = asn_per_constraint_flags.APC_UNCONSTRAINED
		self.range_bits = 0
		self.effective_bits = 0
		self.lower_bound = 0
		self.upper_bound = 0

	def __str__(self):
		return str(self.flags) + " range: " + str(hex(self.range_bits)) + " effective bits: " + str(hex(self.effective_bits)) + " lower_bound: " + str(self.lower_bound) + " upper bound: " + str(self.upper_bound)


class asn_encoding_constraints:
	def __init__(self):
		self.general_constraints = None # Ptr to asn_constr_check_f in asn1c
		self.per_constraints = asn_per_encoding_constraints()

class asn_per_encoding_constraints:
	def __init__(self):
		self.value = asn_per_encoding_constraint()
		self.size = asn_per_encoding_constraint()

	def get_per_encoding_constraint(constraint: angr.state_plugins.view.SimMemView) -> asn_per_encoding_constraint:
		encoding_constraint = asn_per_encoding_constraint(constraint.intmax_t.concrete)
		encoding_constraint.flags = asn_per_constraint_flags(constraint.flags.intmax_t.concrete)
		encoding_constraint.effective_bits = constraint.effective_bits.intmax_t.concrete
		encoding_constraint.range_bits = constraint.range_bits.uint32_t.concrete
		encoding_constraint.upper_bound = constraint.upper_bound.intmax_t.concrete
		encoding_constraint.lower_bound = constraint.lower_bound.intmax_t.concrete

		return encoding_constraint