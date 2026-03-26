import copy
from typing import Optional

import angr
from ASN1spect.Analysis.Analysis import Analysis

#from ASN1spect.asn1c.Type import asn_type

@Analysis.register
class RecursiveTypeAnalysis(Analysis):

	recursive_types = {}

	def __init__(self, type1: "asn_type", type2: Optional["asn_type"] = None):
		super().__init__(type1, type2, False)

		self.parents = []

	def analyze(self):
		from ASN1spect.asn1c.Member import asn_member

		if len(self.type1.elements) > 0 and self.type1.elements_count > 0:
			for memb in self.type1.elements:

				# Recursive types are marked during type extraction.
				if memb.recursive == True:
					angr_proj = self.type1.proj.get_project()
					name = self.type1.proj.get_binary().name
					if name not in self.recursive_types:
						self.recursive_types[name] = []

					symbol = memb.type.symbol

					if symbol.name not in self.recursive_types[name]:
						self.recursive_types[name].append(symbol.name)

				#print("Found a recursive type:", self.type1.name, "its parents are", self.parents)

		return self.recursive_types