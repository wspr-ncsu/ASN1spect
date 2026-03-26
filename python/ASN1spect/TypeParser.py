import angr, archinfo, os
from pathlib import Path
import importlib.resources as resources
from typing import List

class TypeParser:
	def __init__(self):
		self.predefined_types = None
		self.predefined_parsed_types = None

		self.parse_predefined_types()
		#self.parse_folder_types()

	def parse_predefined_types(self) -> None:
		try:
			predefined_types = resources.read_text("ASN1spect.data", "types.cpp")
			self.predefined_types = predefined_types
			self.predefined_parsed_types = angr.types.parse_types(predefined_types, arch=archinfo.arch_amd64.ArchAMD64)
			angr.types.register_types(self.predefined_parsed_types)
		except ValueError:
			print("predefined types already registered")
		except Exception as e:
			print(f"Error reading predefined types: {e}")

	def __remove_common_keys(self, dict1: dict, dict2: dict) -> dict:
		"""
		Remove keys from dict2 that are present in dict1.

		:param dict1: First dictionary.
		:param dict2: Second dictionary from which keys will be removed.
		:return: A modified version of dict2 with common keys removed.
		"""
		keys_to_remove = set(dict1.keys()) & set(dict2.keys())
		for key in keys_to_remove:
			del dict2[key]
		return dict2

	def __get_skeletons(self) -> List[str]:
		skeletons = []
		try:
			skeleton_path = resources.files("ASN1spect.data.skeletons")
			if skeleton_path.exists():
				skeletons = [f.name for f in skeleton_path.iterdir() if f.is_file()]
		except Exception as e:
			print(f"Error accessing skeletons: {e}")
		return skeletons

	def __replace_content(self, file_contents: str) -> str:
		content = {
			"CC_NOTUSED = {": "= {",
			" CC_NOTUSED": "",
			"void CC_PRINTFLIKE(1, 2) ASN_DEBUG_f(const char *fmt, ...);": "",
			"CC_PRINTFLIKE(4, 5)": ""
		}

		for k, v in content.items():
			file_contents = file_contents.replace(k, v)

		return file_contents

	def parse_folder_types(self) -> None:
		skeletons = self.__get_skeletons()
		parsed_file = {}

		try:
			data_path = resources.files("ASN1spect.data.code")
			if not data_path.exists():
				raise FileNotFoundError("Data package not found")

			for file in data_path.iterdir():
				if file.name not in skeletons and file.name.endswith(".c"):
					print(f"Processing {file}")

					file_contents = file.read_text()
					file_contents = self.__replace_content(file_contents)

					try:
						parsed_file[file.name] = angr.types.parse_file(
							self.predefined_types + file_contents,
							arch=archinfo.arch_amd64.ArchAMD64
						)
					except ValueError as e:
						print("Types (likely) already registered.")
						print(e)
						pass

					if file.name in parsed_file:
						result = self.__remove_common_keys(
							self.predefined_parsed_types,
							parsed_file[file.name][1]
						)
						if len(result) > 0:
							angr.types.register_types(result)

			angr.types.register_types(self.predefined_parsed_types)
		except Exception as e:
			print(f"Error processing folder: {e}")
