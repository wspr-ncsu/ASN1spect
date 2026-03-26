from ASN1nspect.ComparisonStrategies.ASN1ComparisonStrategy import ASN1ComparisonStrategy
from ASN1nspect.FieldMatchers import FieldMatcherStrategy
from ASN1nspect import ASN1AngrProject
from ASN1nspect.Checkpoint import Checkpoint
from ASN1nspect.asn1c.Constraints import asn_per_constraint_flags
import json
from typing import Dict, Tuple, Any

class ASN1CConstraintComparison(ASN1ComparisonStrategy):
	def __init__(self, proj1: ASN1AngrProject, proj2: ASN1AngrProject, fms: FieldMatcherStrategy):
		super().__init__()
		self.fm = fms
		self.checkpoint = Checkpoint()
		self.proj1 = proj1
		self.proj2 = proj2

		key_mapping = self.fm.match()
		constraints = self._initialize_constraints()
		self._compare_and_save_constraints(key_mapping, constraints)

	def _initialize_constraints(self) -> Dict[str, Dict]:
		"""Initialize the constraints dictionary structure."""
		b1 = str(self.proj1.get_binary())
		b2 = str(self.proj2.get_binary())
		return {b1: {b2: {}}}

	def _check_element_counts(self, item1, item2, constraints: Dict, b1: str, b2: str) -> bool:
		"""Check if element counts match between items."""
		if item1.elements_count != item2.elements_count:
			print("Element counts do not match")
			constraints[b1][b2][item1.symbol.name] = {
				"count": (item1.elements_count, item2.elements_count)
			}
			return False
		return True

	def _compare_per_constraints_value(self, item1, item2, constraints: Dict, b1: str, b2: str):
		"""Compare PER constraints for values between items."""
		if self._has_mismatching_constraint_ptrs(item1.encoding_constraints.per_constraints.value,
											   item2.encoding_constraints.per_constraints.value):
			print("Mismatching encoding constraints")
			return

		if item1.encoding_constraints.per_constraints.value.ptr != 0:
			if item1.encoding_constraints.per_constraints.value.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
				val1 = (item1.encoding_constraints.per_constraints.value.lower_bound,
					   item1.encoding_constraints.per_constraints.value.upper_bound)
				val2 = (item2.encoding_constraints.per_constraints.value.lower_bound,
					   item2.encoding_constraints.per_constraints.value.upper_bound)

				if val1 != val2:
					print("NON MATCHING PER CONSTRAINTS")
					self._update_constraints_dict(constraints, b1, b2, item1.symbol.name,
											   item2.symbol.name, "value", (val1, val2))

	def _compare_per_constraints_size(self, item1, item2, constraints: Dict, b1: str, b2: str):
		"""Compare PER constraints for sizes between items."""
		if self._has_mismatching_constraint_ptrs(item1.encoding_constraints.per_constraints.size,
											   item2.encoding_constraints.per_constraints.size):
			print("(SIZE) Mismatching encoding constraints")
			return

		if item1.encoding_constraints.per_constraints.size.ptr != 0:
			if item1.encoding_constraints.per_constraints.size.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
				size1 = (item1.encoding_constraints.per_constraints.size.lower_bound,
						item1.encoding_constraints.per_constraints.size.upper_bound)
				size2 = (item2.encoding_constraints.per_constraints.size.lower_bound,
						item2.encoding_constraints.per_constraints.size.upper_bound)

				if size1 != size2:
					print("(SIZE) NON MATCHING PER CONSTRAINTS")
					self._update_constraints_dict(constraints, b1, b2, item1.symbol.name,
											   item2.symbol.name, "size", (size1, size2))

	def _has_mismatching_constraint_ptrs(self, constraint1, constraint2) -> bool:
		"""Check if constraint pointers mismatch."""
		return (constraint1.ptr != 0 and constraint2.ptr == 0) or \
			   (constraint2.ptr != 0 and constraint1.ptr == 0)

	def _update_constraints_dict(self, constraints: Dict, b1: str, b2: str,
							   sym1: str, sym2: str, key: str, value: Tuple):
		"""Update the constraints dictionary with new comparison results."""
		if sym1 not in constraints[b1][b2]:
			constraints[b1][b2][sym1] = {}
		if sym2 not in constraints[b1][b2][sym1]:
			constraints[b1][b2][sym1][sym2] = {}
		constraints[b1][b2][sym1][sym2][key] = value

	def _compare_and_save_constraints(self, key_mapping, constraints: Dict):
		"""Compare constraints between matched items and save results to file."""
		b1 = str(self.proj1.get_binary())
		b2 = str(self.proj2.get_binary())

		for item, item2 in key_mapping:
			print(item, item2, item.symbol, item2.symbol)

			if not self._check_element_counts(item, item2, constraints, b1, b2):
				continue

			print(item, "its constraints are", item.constraints)
			self._compare_per_constraints_value(item, item2, constraints, b1, b2)
			self._compare_per_constraints_size(item, item2, constraints, b1, b2)

		# Save constraints to checkpoint
		self.checkpoint.constraints = constraints