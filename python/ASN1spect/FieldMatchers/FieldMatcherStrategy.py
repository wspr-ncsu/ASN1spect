class FieldMatcherStrategy():
	def __init__(self, pIE1, pIE2):
		self.pIE1 = pIE1
		self.pIE2 = pIE2
		self.structureMatches = {}
		self.keyMapping = {}

	def match(self):
		for k, pIEList in self.pIE1.items():
			#print(k)
			#print(pIEValue)
			for protocolIE, pIEValue in pIEList.items():
				#print(srsRANProtocols["asn1::s1ap::supported_tas_item_ext_ies_o::"])
				# Check if the id exists in srsRANProtocols
				for protocolIE2, pVIEalue2 in self.pIE2.items():
					# print(protocolIE2)
					# print(pVIEalue2)
					if protocolIE in pVIEalue2.keys():

						if k not in self.structureMatches:
							self.structureMatches[k] = {}

						if protocolIE2 not in self.structureMatches[k]:
							self.structureMatches[k][protocolIE2] = 0


						if protocolIE == pVIEalue2[protocolIE].id and pIEValue.id == pVIEalue2[protocolIE].id and pIEValue.criticality == pVIEalue2[protocolIE].criticality and pIEValue.presence == pVIEalue2[protocolIE].presence:
							#print(k, "Found one!", key)

							#print("structure is", pVIEalue2[protocolIE])

							self.structureMatches[k][protocolIE2] += 1
		max_values_and_keys = {outer_key: [(k, v) for k, v in inner_dict.items() if v == max(inner_dict.values())] for outer_key, inner_dict in self.structureMatches.items()}


		for key, value in max_values_and_keys.items():

			# Check the length of each of the structures. Similar length = probably similar?
			#print(key)
			#print(value)

			# if key != "asn_IOS_ENBConfigurationUpdateAcknowledgeIEs_1_rows":
			# 	continue

			max_lcs = 0
			max_lcs_string = ""

			# # What are the differences between the best matching structures in both implementations?
			#print("ProtocolIEs", key, len(ProtocolIEs[key]))
			for k in value:
				# print("srsRANProtocols", key, k[0], ProtocolIEs[key], srsRANProtocols[k[0]])
				# print("Value:", value)
				#if len(ProtocolIEs[key]) == len(srsRANProtocols[k[0]]):
				max_lcs = 0
				max_lcs_string = ""
				string1 = key
				for string2 in value:
					if len(self.pIE1[key]) == len(self.pIE2[string2[0]]):
						#print(string1, string2)
						tmp_max = longest_common_subsequence(string1, string2[0])
						if tmp_max > max_lcs:
							#print(tmp_max, max_lcs, string1, string2)
							max_lcs_string = string2[0]
							max_lcs = tmp_max
					# for val in value:
					# 	if val[0] == max_lcs_string:
					# 		print("Found", val[1], "matches for", max_lcs_string, key)

			if max_lcs == 0:
				# No structure has the same length as this one?
				max_lcs = 0
				max_lcs_string = ""
				string1 = key
				for string2 in value:
					tmp_max = longest_common_subsequence(string1, string2[0])
					if len(self.pIE1[key]) <= len(self.pIE2[string2[0]]) / 3 or len(self.pIE2[string2[0]]) <= len(self.pIE1[key]) / 3:
						# Not even half of the structure matches. Don't trust this.
						continue
					if tmp_max > max_lcs:
						max_lcs_string = string2[0]
						max_lcs = tmp_max
				# for val in value:
				# 	if val[0] == max_lcs_string:
				# 		print("(2) Found", val[1], "matches for", max_lcs_string, key)

			#print(key, len(self.pIE1[key]))

			if max_lcs == 0:
				print("No match")
				continue

			#print(max_lcs_string, len(srsRANProtocols[max_lcs_string]), max_lcs)
			#print(key, max_lcs_string)
			#print("# Structure matches:", self.structureMatches[key][max_lcs_string])

			assert key not in self.keyMapping

			self.keyMapping[key] = max_lcs_string

			# res = srsRAN_asn_class.match(max_lcs_string)
			# if res != None:
			# 	prefix = res.group("class")
			# 	for k in self.pIE1[key].keys():
			# 		if k not in self.pIE2[max_lcs_string]:
			# 			print("Did not find", k, "in", self.pIE2[max_lcs_string])
			# 		else:
			# 			#print(srsRANProtocols[max_lcs_string][k])

			# 			print(self.pIE1[key][k].value.name, self.pIE1[key][k].value.constraints)
			# 			for memb in self.pIE1[key][k].value.elements:
			# 				print(memb.name, memb.constraints)
			# 				if memb.encoding_constraints.per_constraints.value.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
			# 					print("PER Constraints value", memb.encoding_constraints.per_constraints.value.lower_bound, memb.encoding_constraints.per_constraints.value.upper_bound)
			# 				elif memb.encoding_constraints.per_constraints.size.flags & ~asn_per_constraint_flags.APC_UNCONSTRAINED:
			# 					print("PER Constraints size", memb.encoding_constraints.per_constraints.size.lower_bound, memb.encoding_constraints.per_constraints.size.upper_bound)
			# 				else:
			# 					print("PER constraints: everything unconstrained")


			# else:
			# 	raise Exception("Couldn't find type " + prefix)

		return self.keyMapping