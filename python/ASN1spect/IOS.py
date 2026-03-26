# Code for Information Object Sets

from enum import Enum
import re
from collections import defaultdict
from ASN1spect.ASN1AngrProject import ASN1AngrProject

class Criticality(Enum):
	reject = 0
	ignore = 1
	notify = 2
	nulltype = 3

class Presence(Enum):
	optional = 0
	conditional = 1
	mandatory = 2
	nulltype = 3

class ProtocolIE:
	def __init__(self, criticality: Criticality = Criticality.nulltype, value: int = -1, id: int = -1, presence: Presence = Presence.nulltype):
		self.criticality = criticality
		self.value = int(value)
		self.id = int(id)
		self.presence = presence
		self.structure = None
		self.enum_idx = None

	def __str__(self):
		return "ID: " + str(self.id) + " Criticality: " + str(self.criticality) + " Presence: " + str(self.presence) + " Value: " + str(self.value) + " Enum idx: " + str(self.enum_idx)


class IOS_ArrayMismatch:
	def __init__(self):
		self.name = ""
		self.ElementCount = -1
		self.RowCount = -1
		self.Function = ""

	def __eq__(self, other):
		if not isinstance(other, IOS_ArrayMismatch):
			return False

		else:
			return (
				self.name == other.name
				and self.ElementCount == other.ElementCount
				and self.RowCount == other.RowCount
				and self.Function == other.Function
			)

class IOSAnalyzer:
	def __init__(self, project: ASN1AngrProject):
		self.asn1c_asn = re.compile(r"""^asn\_VAL\_[0-9]+(.*)id\_(?P<asn>.*)""")
		self.asn1c_asn_IOS_rows = re.compile(r"""^asn_IOS_*(.*_).*\_rows$""")
		self.ProtocolIEs = {}
		self.project = project

		self.analyze_project()

	def get_symbol_id(self, spec):
		return self.asn1c_asn.match(spec)

	def get_protocols(self):
		return self.ProtocolIEs

	def analyze_project(self):
		ProtocolIEs = {}
		angrProject = self.project.get_project()
		obj = angrProject.loader.all_objects
		simgr = self.project.create_simulation_manager()

		for o in obj:
			for f in o.symbols:
				result = self.asn1c_asn_IOS_rows.match(f.name)

				if result != None and f.name not in ProtocolIEs:
					# guess the array size, max of 500
					MAX_ARRAY_SIZE = 500
					cells = simgr.active[0].mem[f.rebased_addr].asn_ioc_cell_t.array(MAX_ARRAY_SIZE)
					ProtocolIEs[f.name] = {}
					last_id = -1
					pIE = ProtocolIE()

					for i in range(0, MAX_ARRAY_SIZE):
						name = cells[i].field_name.deref.string.concrete.decode("ascii")

						if len(name) == 0:
							print(f.name + " is size " + str(i))
							if i % 4 != 0:
								print("Warning: Possible error in " + f.name + " size is not divisible by 4")
							print("Done sizing")
							break

						addr = hex(simgr.active[0].solver.eval(cells[i]._addr))
						matching_symbols = [symbol for symbol in o.symbols if hex(symbol.rebased_addr) == addr]
						if len(matching_symbols) > 0 and matching_symbols[0].name != f.name:
							# We guessed the size wrong!
							break

						if name == "&id":
							last_id = cells[i].value_sptr.deref.uint32_t.concrete
							pIE.id = cells[i].value_sptr.deref.uint32_t.concrete
						elif name == "&criticality":
							pIE.criticality = Criticality(cells[i].value_sptr.deref.uint32_t.concrete)
						elif name == "&Value" or name == "&Extension":
							pIE.value = cells[i].type_descriptor.uint32_t.concrete
						elif name == "&presence":
							pIE.presence = Presence(cells[i].value_sptr.deref.uint32_t.concrete)
							ProtocolIEs[f.name][last_id] = pIE
							pIE = ProtocolIE()
							last_id = -1
						elif name == "&InitiatingMessage" or name == "&SuccessfulOutcome" or name == "&UnsuccessfulOutcome" or name == "&criticality" or name == "&procedureCode":
							print("Skipping", name)
							break
						else:
							raise Exception("I don't know what " + name + " is")

		return ProtocolIEs
