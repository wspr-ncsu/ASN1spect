import pdb

import angr
from ASN1nspect.Analysis.Analysis import Analysis

@Analysis.register
class DebugAnalysis(Analysis):
	"""
	This class is used to analyze the debug information of ASN.1 structures.
	It provides methods to check if a constraint is enforced or not.
	"""

	def __init__(self, type1: "asn_type", type2: Optional["asn_type"] = None):
		super().__init__(type1, type2, False)

	def analyze(self):
		pdb.set_trace()
