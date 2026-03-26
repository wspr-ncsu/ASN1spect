import angr
from ASN1nspect.asn1c.StructureKind import structure_type

class asn_type_operation:
	def __init__(self):
		self.print_struct = -1
		self.compare_struct = -1
		self.ber_decoder = -1 # There's no BER encoder
		self.der_encoder = -1 # There's no DER decoder
		self.xer_decoder = -1
		self.xer_encoder = -1
		self.jer_decoder = -1
		self.jer_encoder = -1
		self.oer_decoder = -1
		self.oer_encoder = -1
		self.uper_decoder = -1
		self.uper_encoder = -1
		self.aper_decoder = -1
		self.aper_encoder = -1
		self.random_fill = -1
		self.outmost_tag = -1
		self.addr = -1

	def determineOperation(self, op: angr.state_plugins.view.SimMemView, kind: structure_type):

		if kind == structure_type.LEGACY or kind == structure_type.LEGACY_WITH_APER:
			self.free_struct = op.free_struct.uint32_t.concrete
			self.check_constraints = op.check_constraints.uint32_t.concrete

		elif kind >= structure_type.MODERN:
			self.addr = op.uint32_t.concrete
			op = op.deref.asn_TYPE_operation_t

			self.compare_struct = op.compare_struct.uint32_t.concrete

			self.jer_decoder = op.jer_decoder.uint32_t.concrete
			self.jer_encoder = op.jer_encoder.uint32_t.concrete

			self.oer_decoder = op.oer_decoder.uint32_t.concrete
			self.oer_encoder = op.oer_encoder.uint32_t.concrete

			self.random_fill = op.random_fill.uint32_t.concrete

		if kind == structure_type.LEGACY_WITH_APER or kind == structure_type.MODERN:
			self.aper_decoder = op.aper_decoder.uint32_t.concrete
			self.aper_encoder = op.aper_encoder.uint32_t.concrete

		self.outmost_tag = op.outmost_tag.uint32_t.concrete

		self.print_struct = op.print_struct.uint32_t.concrete

		self.print_struct = op.print_struct.uint32_t.concrete

		self.ber_decoder = op.ber_decoder.uint32_t.concrete

		self.der_encoder = op.der_encoder.uint32_t.concrete

		self.xer_decoder = op.xer_decoder.uint32_t.concrete
		self.xer_encoder = op.xer_encoder.uint32_t.concrete

		self.uper_decoder = op.uper_decoder.uint32_t.concrete
		self.uper_encoder = op.uper_encoder.uint32_t.concrete
