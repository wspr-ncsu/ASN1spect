import angr
from ASN1nspect.asn1c.Constraints import (asn_encoding_constraints,
                                          asn_per_encoding_constraint)


def set_encoding_constraints(encoding_constraints, constraints, general_constraints_ptr, angr_proj):
    """
    Sets encoding constraints for ASN.1 types based on the structure kind.

    Args:
        encoding_constraints: The encoding_constraints object to modify
        constraints: The constraints object containing size and value constraints
        general_constraints_ptr: Pointer to general constraints
        angr_proj: The angr project

    Returns:
        The modified encoding_constraints object
    """
    # Create a new object if none was provided
    if encoding_constraints is None:
        encoding_constraints = asn_encoding_constraints()

    # Set PER constraints for size
    encoding_constraints.per_constraints.size = asn_per_encoding_constraint()
    encoding_constraints.per_constraints.size.lower_bound = constraints.size.lower_bound.int32_t.concrete
    encoding_constraints.per_constraints.size.upper_bound = constraints.size.upper_bound.int32_t.concrete
    encoding_constraints.per_constraints.size.effective_bits = constraints.size.effective_bits.int32_t.concrete

    # Set PER constraints for value
    encoding_constraints.per_constraints.value = asn_per_encoding_constraint()
    encoding_constraints.per_constraints.value.lower_bound = constraints.value.lower_bound.int32_t.concrete
    encoding_constraints.per_constraints.value.upper_bound = constraints.value.upper_bound.int32_t.concrete
    encoding_constraints.per_constraints.value.effective_bits = constraints.value.effective_bits.int32_t.concrete

    # Set general constraints if available
    if general_constraints_ptr is not None and general_constraints_ptr.intmax_t.concrete != 0:
        encoding_constraints.general_constraints = angr_proj.loader.find_symbol(general_constraints_ptr.intmax_t.concrete)

    return encoding_constraints