# REWRITE THIS

import os
from pathlib import Path

from ASN1spect import ASN1AngrProject


class BinaryLoader:
	def __init__(self, binary_path: Path):
		"""Initialize BinaryLoader for a single binary file

		Args:
			binary_path (Path): Path to the binary file to analyze
		"""
		self.binary_path = binary_path

	def create_project(self) -> ASN1AngrProject:
		"""Create and load an ASN1AngrProject for the binary

		Returns:
			ASN1AngrProject: Loaded project instance
		"""
		if not self.binary_path.name.endswith('.bin'):
			raise ValueError(f"File {self.binary_path} is not a .bin file")

		project = ASN1AngrProject(self.binary_path)
		project.load_project()

		return project
