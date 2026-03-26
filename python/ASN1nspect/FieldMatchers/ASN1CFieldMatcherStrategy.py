import sys

def longest_common_subsequence(str1, str2):
	# Convert both strings to lowercase for case-insensitive comparison
	str1_lower = str1.lower()
	str2_lower = str2.lower()

	# Create a 2D array to store the length of LCS
	dp = [[0] * (len(str2_lower) + 1) for _ in range(len(str1_lower) + 1)]

	# Build the LCS matrix
	for i in range(1, len(str1_lower) + 1):
		for j in range(1, len(str2_lower) + 1):
			if str1_lower[i - 1] == str2_lower[j - 1]:
				dp[i][j] = dp[i - 1][j - 1] + 1
			else:
				dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

	# Length of the LCS is stored in the bottom-right cell
	return dp[len(str1_lower)][len(str2_lower)]

missing_types = {}

class ASN1CFieldMatcherStrategy():
	def __init__(self, p1, p2, verbose=False):
		self.p1 = p1
		self.p2 = p2
		self.symbolMap = {}
		self.keyMapping = []
		self.missing_types = {}
		self.verbose = verbose

	def _add_missing_type(self, binary, symbol_name):
		if binary not in self.missing_types:
			self.missing_types[binary] = []
		self.missing_types[binary].append(symbol_name)

	def match(self):
		# Match p1 types to p2
		for item in self.p1.Types:
			for item2 in self.p2.Types:
				if item.symbol.name == item2.symbol.name and item not in self.symbolMap:
					self.symbolMap[item] = item2
					self.keyMapping.append((item, item2))
					break
			else:
				binary = str(self.p2.get_binary())
				self._add_missing_type(binary, item.symbol.name)
				if self.verbose:
					print("Could not find", item, item.symbol, "Searched in the binary of (symbol is unrelated):", binary)

		# Match p2 types to p1
		for item2 in self.p2.Types:
			if item2 not in self.symbolMap:
				for item in self.p1.Types:
					if item2.symbol.name == item.symbol.name:
						self.symbolMap[item2] = item
						if (item, item2) not in self.keyMapping:
							self.keyMapping.append((item, item2))
						break
				else:
					try:
						binary = str(self.p1.get_binary())
						self._add_missing_type(binary, item2.symbol.name)
						if self.verbose:
							print("(2) Could not find", item2, item2.symbol, "Searched in the binary of (symbol is unrelated):", binary)
					except IndexError:
						if self.verbose:
							print("Warning:", item2, "was in the 2nd binary, but the first one actually had no types.")

		# Print missing types as error
		for binary, missing in self.missing_types.items():
			if self.verbose:
				print(f"ERROR: Binary {binary} is missing the following types:", file=sys.stderr)
				for type_name in missing:
					print(f"  - {type_name}", file=sys.stderr)

		if self.verbose:
			print(self.keyMapping)
		return self.keyMapping