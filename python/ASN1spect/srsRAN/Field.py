class Field:
	def __init__(self, name: str, type: str, template_specifiers: list[str] = None):
		self.name = name
		self.type = type
		self.template_specifiers = template_specifiers
		self.constraints = None

	def __str__(self):
		def format_specifier(d):
			if isinstance(d, str):
				return d
			elif d is None:
				return 'None'
			else:
				key = list(d.keys())[0]
				value = d[key]
				if value is not None and value[0] != None:
					return f"{key}<{', '.join(map(format_specifier, value))}>"
				else:
					return key

		if self.template_specifiers is not None:
			formatted_specifiers = ', '.join(map(format_specifier, self.template_specifiers))
			return f"{self.name}: {self.type}<{formatted_specifiers}>"
		return f"{self.name}: {self.type}"

	def __repr__(self):
		return self.__str__()