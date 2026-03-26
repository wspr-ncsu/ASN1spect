import copy
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Type

import angr
import claripy
from ASN1spect import ASN1AngrProject


class Analysis():
	# Class variable to specify the analysis type
	# Set to True for differential analysis, False otherwise.
	# Subclasses can override this value.
	is_differential: bool = False

	# Registry to store all registered analysis classes
	_registry: Dict[str, Type['Analysis']] = {}

	@classmethod
	def register(cls, analysis_class: Type['Analysis']) -> Type['Analysis']:
		"""
		Register an analysis class to the registry.

		:param analysis_class: The analysis class to register.
		:return: The registered analysis class (for decorator use).
		"""
		cls._registry[analysis_class.__name__] = analysis_class
		return analysis_class

	@classmethod
	def get_registered_differential_analyses(cls) -> Dict[str, Type['Analysis']]:
		"""
		Get all registered analysis classes that perform differential analysis.

		:return: Dictionary of differential analysis class names to analysis classes.
		"""
		return {name: analysis_class for name, analysis_class in cls._registry.items()
				if analysis_class.is_differential}

	@classmethod
	def get_registered_nondifferential_analyses(cls) -> Dict[str, Type['Analysis']]:
		"""
		Get all registered analysis classes that perform differential analysis.

		:return: Dictionary of differential analysis class names to analysis classes.
		"""
		return {name: analysis_class for name, analysis_class in cls._registry.items()
				if not analysis_class.is_differential}

	@classmethod
	def run_all_nondifferential_analyses(cls, type1: "asn_type") -> Dict[str, Any]:
		"""
		Run all registered analyses on the given ASN.1 type(s).

		:param type1: The primary ASN.1 type to analyze.
		:return: Dictionary of analysis results keyed by analysis name.
		"""
		results = {}
		assert type1 is not None, "Type must be provided for differential analysis."

		for name, analysis_class in cls.get_registered_nondifferential_analyses().items():
			try:
				analysis_instance = analysis_class(type1)
				results[name] = analysis_instance.analyze()
			except Exception as e:
				results[name] = {"error": str(e)}
		return results

	@classmethod
	def run_all_differential_analyses(cls, type1: "asn_type", type2: "asn_type") -> Dict[str, Any]:
		"""
		Run all registered analyses on the given ASN.1 type(s).

		:param type1: The primary ASN.1 type to analyze.
		:param type2: The secondary ASN.1 type to analyze.
		:return: Dictionary of analysis results keyed by analysis name.
		"""
		results = {}
		assert type1 is not None and type2 is not None, "Both types must be provided for differential analysis."
		assert type1 != type2, "Both types must be different for differential analysis."

		if hasattr(type1, 'proj') and hasattr(type2, 'proj'):
			assert type1.proj.get_binary() != type2.proj.get_binary(), "Both types must not belong to the same binary."

		for name, analysis_class in cls.get_registered_differential_analyses().items():
			try:
				analysis_instance = analysis_class(type1, type2)
				results[name] = analysis_instance.analyze()
			except Exception as e:
				results[name] = {"error": str(e)}
		return results

	def __init__(self, type1: "asn_type", type2: Optional["asn_type"] = None, differential: bool = False):
		"""
		Initialize the Analysis class.
		:param differential: If True, sets the analysis to be differential.
		"""

		self.type1 = type1
		self.type2 = type2
		self.is_differential = differential

	def analyze(self):
		"""
		Analyze the ASN.1 type(s) and return a result.

		The behavior depends on the `is_differential` class variable:
		- If `is_differential` is False: Analyzes `type1`. `type2` should be None or is ignored.
		- If `is_differential` is True: Performs a differential analysis between `type1` and `type2`. Both must be provided.

		Subclasses must implement this method according to their specific analysis type
		and the value of `is_differential`.

		:param type1: The primary ASN.1 type.
		:param type2: The secondary ASN.1 type (required for differential analysis).
		:raises ValueError: If `is_differential` is True and `type2` is None.
		:raises NotImplementedError: This base method is not implemented.
		"""
		# Basic check in the base class for differential case
		if self.is_differential and type2 is None:
			raise ValueError("Differential analysis requires two types, but type2 was None.")

		# The core logic must be implemented by subclasses
		raise NotImplementedError("This method should be overridden by subclasses")
