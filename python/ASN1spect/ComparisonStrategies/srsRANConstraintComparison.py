from ASN1spect.ComparisonStrategies.ASN1ComparisonStrategy import ASN1ComparisonStrategy
from ASN1spect.FieldMatchers.FieldMatcherStrategy import FieldMatcherStrategy
from ASN1spect.asn1c.Constraints import asn_per_constraint_flags
from ASN1spect.asn1c.Type import asn_type
from ASN1spect import ASN1AngrProject
from ASN1spect.srsRAN.Structure import Structure
from ASN1spect.srsRAN.Field import Field

import re

srsRAN_asn_class = re.compile(r"""^asn1::s1ap::(?P<class>.*)::""")

class SRSRanConstraintComparison(ASN1ComparisonStrategy):

	def __init__(self, proj1: ASN1AngrProject, proj2: ASN1AngrProject, fms: FieldMatcherStrategy):
		super()

		#self.convert_constraints(proj1)
		self.convert_constraints(proj2)

		# Create new claripy constraints that we can run a solver with
		#self.create_solver()

		self.fChosen = {}

		# Match fields between implementations
		self.fm = fms

		keyMapping = self.fm.match()
		#print(keyMapping)

		#with open("constraints.json", "w") as ofile:

		output = {}
		proj1binary = str(proj1.binary)
		proj2binary = str(proj2.binary)
		output[proj1binary] = {}
		output[proj1binary][proj2binary] = {}
		for key1, key2 in keyMapping.items():
			assert type(key1) == str and type(key2) == str

			# TODO map members of types between implementations
			output[proj1binary][proj2binary][key1] = {}
			output[proj1binary][proj2binary][key1][key2] = {}

			print("Analyzing type", key1, key2)

			print("Checking element fields")
			for k in proj1.Protocols[key1].keys():
				value = proj1.Protocols[key1][k].value
				print(value, "its constraints are", value.constraints)
				output[proj1binary][proj2binary][key1][key2]["1"] = {}
				output[proj1binary][proj2binary][key1][key2]["1"]["value"] = value.name
				output[proj1binary][proj2binary][key1][key2]["1"]["constraints"] = value.constraints

				if value.encoding_constraints.per_constraints.value.ptr != 0:
					output[proj1binary][proj2binary][key1][key2]["1"]["per_constraints"] = {}
					if value.encoding_constraints.per_constraints.value.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
						print("PER Constraints value", value.encoding_constraints.per_constraints.value.lower_bound, value.encoding_constraints.per_constraints.value.upper_bound)
						if "per_constraints" not in output[proj1binary][proj2binary][key1][key2]["1"]:
							output[proj1binary][proj2binary][key1][key2]["1"]["per_constraints"] = {}
						output[proj1binary][proj2binary][key1][key2]["1"]["per_constraints"]["value"] = (value.encoding_constraints.per_constraints.value.lower_bound, value.encoding_constraints.per_constraints.value.upper_bound)

				if value.encoding_constraints.per_constraints.size.ptr != 0:
					if value.encoding_constraints.per_constraints.size.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
						print("PER Constraints size", value.encoding_constraints.per_constraints.size.lower_bound, value.encoding_constraints.per_constraints.size.upper_bound)
						if "per_constraints" not in output[proj1binary][proj2binary][key1][key2]["1"]:
							output[proj1binary][proj2binary][key1][key2]["1"]["per_constraints"] = {}
						output[proj1binary][proj2binary][key1][key2]["1"]["per_constraints"]["size"] = (value.encoding_constraints.per_constraints.size.lower_bound, value.encoding_constraints.per_constraints.size.upper_bound)

				if k in proj2.Protocols[key2].keys():
					p2v = proj2.Protocols[key2][k]
					res = srsRAN_asn_class.match(key2)
					if res != None:
						prefix = res.group("class")
						struct = proj2.Types[prefix]

					output[proj1binary][proj2binary][key1][key2]["2"] = {}
					output[proj1binary][proj2binary][key1][key2]["2"]["value"] = struct.fields[p2v.enum_idx].name
					output[proj1binary][proj2binary][key1][key2]["2"]["constraints"] = struct.fields[p2v.enum_idx].constraints

					print("srsRAN guess:", struct.fields[p2v.enum_idx].constraints)

					sameConstraints = False

					if value.encoding_constraints.per_constraints.value.ptr != 0 and value.encoding_constraints.per_constraints.value.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
						if value.encoding_constraints.per_constraints.value.lower_bound == struct.fields[p2v.enum_idx].constraints[0] and value.encoding_constraints.per_constraints.value.upper_bound == struct.fields[p2v.enum_idx].constraints[1]:
							sameConstraints = True

					if value.encoding_constraints.per_constraints.size.ptr != 0 and value.encoding_constraints.per_constraints.size.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
						if value.encoding_constraints.per_constraints.size.lower_bound == struct.fields[p2v.enum_idx].constraints[0] and value.encoding_constraints.per_constraints.size.upper_bound == struct.fields[p2v.enum_idx].constraints[1]:
							sameConstraints = True

					if not sameConstraints:
						print("Constraints for (srsRAN)", struct.fields[p2v.enum_idx].name, "does not match (asn1c)")

					if proj1.Protocols[key1][k].criticality == p2v.criticality and proj1.Protocols[key1][k].presence == p2v.presence and k == p2v.id:
						s = Structure.find_structure(struct.fields[p2v.enum_idx].type)
						matches = []

						for i in range(0, value.elements_count):
							matches.append(self.recursivelyFindASN1C(value.elements[i], value.name, s.fields, value.name, 4))

						output[proj1binary][proj2binary][key1][key2]["1"]["elements"] = []
						output[proj1binary][proj2binary][key1][key2]["2"]["elements"] = []

						marriages = self.find_stable_marriage(value.name, value.elements, matches)
						for i in range(0, len(marriages)):
							field1, field2 = {}, {}
							field1["name"] = value.elements[marriages[i][0]].name
							field1["constraints"] = value.elements[marriages[i][0]].constraints

							field2["name"] = s.fields[marriages[i][1]].name
							field2["constraints"] = s.fields[marriages[i][1]].constraints
							print("asn1c", value.elements[marriages[i][0]].name, "constraints:", value.elements[marriages[i][0]].constraints)
							# Check typed PER constraints:
							if type(value.elements[marriages[i][0]]) == asn_member:
								print(value.elements[marriages[i][0]].type, "type constraints:", value.elements[marriages[i][0]].type.constraints)
								if value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.value.ptr != 0:
									if "per_constraints" not in field1:
											field1["per_constraints"] = {}

									if value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.value.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
										print("Type PER Constraints value", value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.value.lower_bound, value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.value.upper_bound)
										field1["per_constraints"]["value"] = (value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.value.lower_bound, value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.value.upper_bound)
								if value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.size.ptr != 0:
									if value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.size.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
										if "per_constraints" not in field1:
											field1["per_constraints"] = {}

										print("Type PER Constraints size", value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.size.lower_bound, value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.size.upper_bound)
										field1["per_constraints"]["size"] = (value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.size.lower_bound, value.elements[marriages[i][0]].type.encoding_constraints.per_constraints.size.upper_bound)


							sameConstraints = False

							if value.elements[marriages[i][0]].encoding_constraints.per_constraints.value.ptr != 0 and value.elements[marriages[i][0]].encoding_constraints.per_constraints.value.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
								if value.elements[marriages[i][0]].encoding_constraints.per_constraints.value.lower_bound == struct.fields[p2v.enum_idx].constraints[0] and value.elements[marriages[i][0]].encoding_constraints.per_constraints.value.upper_bound == struct.fields[p2v.enum_idx].constraints[1]:
									sameConstraints = True

							if value.elements[marriages[i][0]].encoding_constraints.per_constraints.size.ptr != 0 and value.elements[marriages[i][0]].encoding_constraints.per_constraints.size.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
								if value.elements[marriages[i][0]].encoding_constraints.per_constraints.size.lower_bound == struct.fields[p2v.enum_idx].constraints[0] and value.elements[marriages[i][0]].encoding_constraints.per_constraints.size.upper_bound == struct.fields[p2v.enum_idx].constraints[1]:
									sameConstraints = True

							if not sameConstraints:
								print("Constraints for (srsRAN)", s.fields[marriages[i][1]].name, s.fields[marriages[i][1]].constraints, "does not match (asn1c)")

							print("srsRAN", s.fields[marriages[i][1]], s.fields[marriages[i][1]].constraints)

							output[proj1binary][proj2binary][key1][key2]["1"]["elements"].append(field1)
							output[proj1binary][proj2binary][key1][key2]["2"]["elements"].append(field2)

						#print("srsRAN field", p2v, p2v.enum_idx, struct.fields[p2v.enum_idx], "all fields", struct.fields)
						self.recursivelyFind(struct.fields[p2v.enum_idx], 4)
						#print("srsRAN Field done")

			print("___________________Done Analyzing type", key1, key2)

			print(output)
			#ofile.write(json.dumps(output, indent=4))#, default=vars))



			# print("srsRAN typed constraints are:")
			# res = srsRAN_asn_class.match(key2)
			# if res != None:
			# 	prefix = res.group("class")
			# 	struct = proj.Types[prefix]

			# 	for field in struct.fields:
			# 		self.recursivelyFind(field)
			# print("Done", key1, key2)


	def find_first_available_preference(self, marriages, preferences):
		if len(marriages) == 0:
			#print("(1) Giving", preferences[0][0], "from", preferences)
			return preferences[0][0]

		for marriage in marriages:
			for i in range(0, len(preferences)):
				if preferences[i][0] == marriage[0]:
					continue
				else:
					#print("(2) Giving", i, preferences[i], "from", preferences)
					return preferences[i][0]

	def does_preference_exist(self, marriages, pref):
		for marriage in marriages:
			if marriage[1][0] == pref[0]:
				return True

		return False

	def find_stable_marriage(self, parent, elements, preferences):
		marriages = []
		for i in range(0, len(elements)):
			pref = self.find_first_available_preference(marriages, preferences[i])

			marriages.append((i, pref))

		return marriages

	def findFieldMatches(self,
					element: asn_type, # asn1c element
					fields # srsRAN fields
	):
		fields_count = len(fields)
		matches = []

		if fields_count != 0:
			for i in range(0, fields_count): # loop through all srsRAN
				# Determine the preferences for element -> fields[j] marriage.
				if "_present" in fields[i].name and fields[i].type == "bool": # ie_exts_present, or "exts": these fields are in all the classes and have no mapping to asn1c.
					continue

				if i not in matches:
					matches.append((i, longest_common_subsequence(element.name, fields[i].name)))

			matches.sort(key=lambda x: x[1], reverse=True)

		# else:
		# 	print(element, "No fields to match against, we match to the parent?")

		#print("We think the matches for", element.name, "and", fields, "is", matches)

		return matches


	def recursivelyFindASN1C(self, element, parents, fields, element_name: str = "", indent = 0):
		# print(str("-" * indent), type(element), fields, element.name, element.constraints)
		# if element.encoding_constraints.per_constraints.value.ptr != 0:
		# 	if element.encoding_constraints.per_constraints.value.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
		# 		print(str("-" * indent), element.name, "element PER Constraints value", element.encoding_constraints.per_constraints.value.lower_bound, element.encoding_constraints.per_constraints.value.upper_bound)

		# if element.encoding_constraints.per_constraints.size.ptr != 0:
		# 	if element.encoding_constraints.per_constraints.size.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
		# 		print(str("-" * indent), element.name, "element PER Constraints size", element.encoding_constraints.per_constraints.size.lower_bound, element.encoding_constraints.per_constraints.size.upper_bound)

			#print(field.name, field.constraints)

		results = {}

		# Go recursively in the type.
		if type(element) == asn_type:
			preferences = {}
			if element.name in KnownNameTranslation:
				element.name = KnownNameTranslation[element.name]

			# if element.elements_count == 0:
			# 	print(element.name, "Element count is none", fields)
			if fields != None and len(fields) > 0:
				matches = []
				for i in range(0, len(fields)):
					if fields[i].name in SkipNames: # or (parents in self.fChosen and fields[i].name in self.fChosen[parents]):
						continue

					#self.fieldChosen(parents, matches[0][1])
					s = Structure.find_structure(fields[i].name)
					if s is not None and element.elements_count > 0:

						for e in range(0, element.elements_count):
							if len(element_name) != 0:
								results[e] = self.recursivelyFindASN1C(element.elements[e], parents + "." + element_name, s.fields, element_name, indent + 4)
							elif len(element.elements[e].name) != 0:
								results[e] = self.recursivelyFindASN1C(element.elements[e], parents + "." + element.elements[e].name, s.fields, element_name, indent + 4)
							else:
								results[e] = self.recursivelyFindASN1C(element.elements[e], parents, s.fields, element_name, indent + 4)

				#print("Options for find.fieldmatches:", element.name, "fields are", fields, "the results are", results)
				#preferences[element.name] = self.findFieldMatches(element, fields)

				#matching_fields = self.find_stable_marriage(element, preferences)

				#return matching_fields

			else:
				for e in range(0, element.elements_count):
					self.recursivelyFindASN1C(element.elements[e], parents, fields, element_name, indent + 4)

			if element.elements_count == 0:
				print("Element", element.name, "has no subfields, done with recursion")

			#print(element.name, "is a type, therefore, we're going to not find field matches.")
			#print("Elements results:", results)


		elif type(element) == asn_member:
			self.recursivelyFindASN1C(element.type, parents, fields, element.name, indent + 4)

			#element, parents, fields, element_name: str = "", indent = 0

			return self.findFieldMatches(element, fields)

		#print("Done with recursion on element", element, parents, fields)

	def recursivelyFind(self, field: Field, indent = 0):
		#print(str("-" * indent), field.name, field.type, field.constraints)

		s = Structure.find_structure(field.type)

		if s is None:
			print(s, field.type)
			return

		for f in s.fields:
			#print(field.name, field.constraints)
			self.recursivelyFind(f, indent + 4)

	def convert_constraints(self, proj):
		# srsRAN requires converting the parsed types into constraints. for example, if a variable is uint8_t, the constraints are (0, 255)
		#print(proj.Types)

		if proj.get_author() == "srsRAN":
			for key in proj.Types.keys():
				srsKey = "asn1::s1ap::" + key + "::"
				if srsKey in proj.Protocols.keys():
					self.parseSRSType([], proj.Types[key])
		elif proj.get_compiler() == "asn1c":
			for key, value in proj.Protocols.items():
				pass
				#print(key, value)
				#print("Constraints", value.constraints)

	def find_template_constraints(self, typename, templated_values):
		#print("find_template_constraints", typename, templated_values)
		if typename == "bounded_bitstring":
			return (int(templated_values[0]), int(templated_values[1])) # lb, ub
		elif typename == "unbounded_bitstring":
			return (0, 4294967295) # 0, std::numeric_limits<uint32_t>::max
		elif typename == "fixed_bitstring":
			val = int(templated_values[0])
			return (val, val) # lb, ub, Only one size is allowed
		elif typename == "fixed_octstring":
			val = int(templated_values[0])
			#return (val * 2, val * 2) #     if (hexstr.size() != 2 * N) {
			return (val, val) #     if (hexstr.size() != 2 * N) {
		elif typename == "unbounded_octstring":
			return None # No constraints
		elif typename == "bounded_octstring":
			return (int(templated_values[0]), int(templated_values[1])) # lb, ub
		elif typename == "printable_string":
			return (22, 132, int(templated_values[0]), int(templated_values[1])) # lb, ub, alb(?), aub(?)
		elif typename == "integer":
			assert len(templated_values[0].keys()) == 1
			return (int(templated_values[1]), int(templated_values[2]))
		elif typename == "bounded_array":
			return (0, int(templated_values[1]))

	def parseASN1CConstraints(self, parents, value):
		pass

	def parseSRSType(self, parents, value):
		#print("fields", value.fields)
		if len(value.fields) == 0:
			return []

		# if value.name == "gbr_qos_info_ext_ies_container":
		# 	print("WE're HERE", value, value.fields)

		for i in range(0, len(value.fields)):
			field = value.fields[i]
			#print("considering field", field, field.type, field.template_specifiers)
			if field.type in type_limits:
				#print("its in type_limits")
				field.constraints = type_limits[field.type]
				#return type_limits[field.type]
			elif field.type in templated_types:
				if field.type == "bounded_array":
					#print(field, field.template_specifiers)
					field.constraints = self.find_template_constraints(field.type, field.template_specifiers)
					continue
				elif field.type == "ie_field_s":
					outer_continue = False
					#print("its an ie_field_s", field)
					if type(field.template_specifiers) == list and len(field.template_specifiers) > 0:
						for t in field.template_specifiers:
							#print("t is", t, type(t))
							if type(t) == dict:
								for key in t.keys():
									#print("key is", key)
									if key in templated_types:
										#print("finding type", key, "templated args: ", t[key])
										value.fields[i].constraints = self.find_template_constraints(key, t[key])
										#print("(1) field.constraints", value.fields[i], value.fields[i].constraints)
										outer_continue = True
										break
										#return field.constraints
									else:
										s = Structure.find_structure(key)

										if s is None:
											print(s, field.type)
											raise Exception("Problem 1!")
											#continue

										new_parents = parents + [s]

										#print("(2) recursivelty parsing type", parents, s)
										self.parseSRSType(new_parents, s)
										continue
							else:
								raise Exception("Problem!")
					else:
						raise Exception("problem!")


					if outer_continue == True:
						continue
				value.fields[i].constraints = self.find_template_constraints(field.type, field.template_specifiers)
				#print("(2) field.constraints", field.constraints)
				#return field.constraints
			else:
				#print("Couldn't find the field, checking its structure recursivelty")
				# It's a complex type and we need to think about looking at this structure recursively.
				s = Structure.find_structure(field.type)

				if s is None:
					print(s, field.type)
					raise Exception("Problem 2!")
					#continue

				new_parents = parents + [s]

				if s.constraints != None and s.constraints != []:
					value.fields[i].constraints = s.constraints
				else:
					#print("(2) recursivelty parsing type", parents, s)
					#value.fields[i].constraints =
					self.parseSRSType(new_parents, s)