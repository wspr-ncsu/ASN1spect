from ASN1spect.srsRAN.Field import Field

class Structure:
	structures = {}
	def __init__(self, name: str, fields: list[Field]):
		self.name = name
		self.fields = fields
		self.constraints = None # Only used for enum types

		if self.name == None:
			return

		assert name not in Structure.structures
		Structure.structures[self.name] = self

	def find_structure(structure_name: str) -> 'Structure':
		if structure_name not in Structure.structures:
			return Structure(structure_name, [])

		return Structure.structures[structure_name]

	def set_structure(struct_name: str, s: 'Structure') -> None:
		Structure.structures[struct_name] = s

	def __str__(self):
		if self.constraints == None:
			return f"{self.name}: {self.fields}"
		else:
			return f"{self.name}: {self.fields} {self.constraints}"


	def __repr__(self):
		return self.__str__()