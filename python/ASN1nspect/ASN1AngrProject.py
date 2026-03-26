import multiprocessing
import os
import re
import time
import traceback
from pathlib import Path

from ASN1nspect.AngrProject import AngrProject
from ASN1nspect.asn1c.Type import asn_type
from ASN1nspect.Checkpoint import Checkpoint
from tqdm import tqdm

asn_DEFs = re.compile(r"""^asn\_DEF\_(?!.*_tags|.*\_constraint|.*c2v|.*v2c|.*\_specs).*$""")


class ASN1AngrProject(AngrProject):
	def __init__(self, binary: Path=None, spec: str = None):
		self.Spec = spec
		self.checkpoint = Checkpoint(False)
		self.Types = None
		AngrProject.__init__(self, binary)


	def __del__(self):
		AngrProject.__del__(self)

	def get_asn_spec(self) -> str:
		assert self.Spec != None, "No spec is defined"
		return self.Spec

	def get_matching_binary(self, suffix: str = "_mouse07410") -> Path:
		"""Find matching binary with '_mouse07410' suffix in same directory. This assumes that the matching binary has already been generated.

		Returns:
			Path: Path to matching binary, or None if not found
		"""
		parent_dir = self.binary.parent
		base_name = self.binary.stem  # Get name without .bin extension
		matching_name = f"{base_name}{suffix}.bin"
		matching_path = parent_dir / matching_name

		if matching_path.exists():
			return matching_path
		else:
			raise FileNotFoundError(f"Matching binary {matching_path} not found. TODO: Generate the binary here.")

	def analyze(self):
		"""Analyze the binary."""
		# Try loading from checkpoint first
		project_types = self.checkpoint.load_project_types(str(self.binary.name))
		if project_types is not None:
			print(f"Loaded types from checkpoint for {self.binary}")
			return project_types

		# Get all ASN.1 type definition symbols
		proj = self.get_project()
		asn_symbols = list({
			sym for obj in proj.loader.all_objects
			for sym in obj.symbols
			if asn_DEFs.match(sym.name)
		})
		project_types = []
		start_time = time.time()

		try:
			simgr = self.create_simulation_manager()
			for i, sym in enumerate(tqdm(asn_symbols, desc=f"[*] {self.binary.stem} - Extracting ASN.1 symbols", position=1, leave=False)):
				# Check if we've exceeded the time limit
				# if time.time() - start_time > time_limit:
				# 	elapsed_time = time.time() - start_time
				# 	print(f"Warning: Analysis exceeded 24-hour time limit. Processing stopped after {len(project_types)} of {len(asn_symbols)} symbols.")
				# 	# Record the skipped binary information
				# 	self.checkpoint.record_skipped_binary(
				# 		str(self.binary.name),
				# 		len(project_types),
				# 		len(asn_symbols),
				# 		elapsed_time
				# 	)
				# 	break

				try:
					type_var = asn_type(self, sym)
					type_var.Analyze(self, simgr.active[0].mem[sym.rebased_addr].asn_TYPE_descriptor_t, [], sym)
					project_types.append(type_var)
				except Exception as e:
					traceback.print_exception(e)
		except Exception as e:
			traceback.print_exception(e)

		asn_type.run_all_nondifferential_analyses(self)

		elapsed_time = time.time() - start_time
		if elapsed_time < 60:
			time_str = f"{elapsed_time:.2f} seconds"
		else:
			days, remainder = divmod(int(elapsed_time), 86400)
			hours, remainder = divmod(remainder, 3600)
			minutes, seconds = divmod(remainder, 60)
			seconds += (elapsed_time - int(elapsed_time))

			# Format the string
			time_parts = []
			if days > 0:
				time_parts.append(f"{days} day{'s' if days != 1 else ''}")
			if hours > 0 or days > 0:
				time_parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
			if minutes > 0 or hours > 0 or days > 0:
				time_parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
			time_parts.append(f"{seconds:.2f} seconds")

			time_str = ", ".join(time_parts)

		print(f"ASN.1 symbol processing completed in {time_str}")

		self.Types = project_types

		return project_types
