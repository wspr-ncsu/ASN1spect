import traceback
from collections import defaultdict

from ASN1spect.ComparisonStrategies import ASN1CConstraintComparison
from ASN1spect.FieldMatchers.ASN1CFieldMatcherStrategy import \
    ASN1CFieldMatcherStrategy
from ASN1spect.Analysis.Analysis import Analysis

class ProjectComparator:
	"""
	A class to handle comparison of ASN1 projects.
	Manages grouping of related projects and performs constraint comparisons between them.
	"""
	def __init__(self, projects: list) -> None:
		"""
		Initialize the comparator with a list of projects to analyze.

		Args:
			projects: List of ASN1AngrProject objects to compare
		"""
		self.projects = projects
		self.projects_to_compare = self._group_bin_files()
		self.compared_projects: list = []
		self.non_compared_projects: list = []

	def _group_bin_files(self) -> dict:
		"""
		Groups binary files based on their base name (part before the last underscore).
		Only keeps groups with exactly 2 matching files.

		Returns:
			dict: Dictionary mapping base names to lists of paired projects
		"""
		# Dictionary to group files by the same starting part
		grouped_files = defaultdict(list)

		print("Projects are", self.projects)

		for proj in self.projects:
			# Extract the beginning part before the first "_"

			path = proj.get_binary().parent
			base_name = proj.get_binary().stem
			if len(str(base_name).rsplit('_', 1)) > 0: # There exists an _ in the base name, consider only the things before it.
				base_name = str(base_name).rsplit('_', 1)[0]

			print("Adding to group", str(base_name), "the project", str(proj.get_binary()))
			# Group by base_name
			grouped_files[base_name].append(proj)

		# Only keep groups with more than one match
		matched_files = {k: v for k, v in grouped_files.items() if len(v) > 1}

		print("matched files are", matched_files)
		for k, item in matched_files.items():
			for v in item:
				print("binary is", v.get_binary(), "key is", k)
			assert len(item) == 2

		return matched_files

	def print_comparison_groups(self) -> None:
		"""Print information about which projects will be compared."""
		for base_name, project_pair in self.projects_to_compare.items():
			print(f"Group {base_name}:")
			print(f"Comparing {project_pair[0].get_binary()} with {project_pair[1].get_binary()}")

	def identify_unmatched_projects(self) -> None:
		"""
		Identify which projects don't have comparison pairs.
		Populates compared_projects and non_compared_projects lists.
		"""
		for proj in self.projects:
			matched = False
			for proj1, proj2 in self.projects_to_compare.values():
				if proj == proj1 or proj == proj2:
					if proj not in self.compared_projects:
						self.compared_projects.append(proj)
						matched = True
						break
			if not matched:
				self.non_compared_projects.append(proj)

		# Print unmatched projects
		for proj in self.non_compared_projects:
			print(f"No comparison pair found for: {proj.get_project()}")

	def perform_comparisons(self) -> None:
		"""
		Perform constraint comparisons between paired projects.
		Handles exceptions and prints error messages if comparisons fail.
		"""
		for proj1, proj2 in self.projects_to_compare.values():
			#print("Comparing", proj1.get_binary(), "with", proj2.get_binary())
			try:
				ASN1CConstraintComparison(
					proj1,
					proj2,
					ASN1CFieldMatcherStrategy(proj1, proj2)
				)
				fms = ASN1CFieldMatcherStrategy(proj1, proj2)
				key_mapping = fms.match()
				for item1, item2 in key_mapping:
					#print("Comparing", item1.symbol.name, "with", item2.symbol.name)
					Analysis.run_all_differential_analyses(item1, item2)

			except Exception as e:
				print(f"Exception during constraint comparison between {proj1.get_binary()} and {proj2.get_binary()}")
				print(e)
				traceback.print_exception(e)

	def run(self) -> None:
		"""Execute the full comparison workflow."""
		self.print_comparison_groups()
		self.identify_unmatched_projects()
		self.perform_comparisons()
		print("[*] Comparison complete, exiting...")