import gc
import os
from pathlib import Path

import angr


class asn_INTEGER2long(angr.SimProcedure):
	def run(self):
		return 0

class check_permitted_alphabet_1(angr.SimProcedure):
	def run(self):
		return 0

class AngrProject:
	def __init__(self, binary: Path=None):
		self.binary = binary
		self.project = None
		self.state = None
		self.simulation_manager = None

		self.Protocols = None
		self.Types = None

		self.__set_options()

	def __del__(self):
		self.project = None
		self.binary = None
		self.state = None
		self.simulation_manager = None
		self.Protocols = None
		self.Types = None

		gc.collect()

	def __set_options(self):
		self.options = angr.options.resilience.union(angr.options.unicorn).union(angr.options.refs).union(angr.options.symbolic).union(angr.options.common_options)
		self.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
		self.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
		self.options.add(angr.options.CONCRETIZE)
		self.options.add(angr.options.UNICORN_AGGRESSIVE_CONCRETIZATION)
		self.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
		self.options.add(angr.options.UNICORN_THRESHOLD_CONCRETIZATION)
		self.options.add(angr.options.TRACK_SOLVER_VARIABLES)

	def load_project(self, binary: Path=None) -> None:
		if binary != None:
			self.binary = binary

		assert self.binary != None, "No binary defined"

		self.project = angr.Project(self.binary, main_opts={'base_addr': 0x0100000}, load_options={'auto_load_libs': True}, load_debug_info = True)
		self.project.kb.dvars.load_from_dwarf()

		# Hook symbols that take a long time in symbolic exec
		integer2long = self.hook_symbol_if_exists("asn_INTEGER2long", asn_INTEGER2long)
		#check_permitted_alphabet_1_hook = self.hook_symbol_if_exists("check_permitted_alphabet_1", check_permitted_alphabet_1)

	def get_project(self) -> angr.project:
		assert self.project != None, "No project is loaded"

		return self.project

	def get_binary(self) -> Path:
		assert self.binary != None, "No binary defined"

		return self.binary

	def get_simulation_manager(self) -> angr.sim_manager.SimulationManager:
		assert self.simulation_manager != None, "Simulation manager could not be created"
		return self.simulation_manager

	def create_simulation_manager(self, addr: int = 0) -> angr.sim_manager.SimulationManager:
		# For our simple_decode.cpp file, we expect a parameter on the command line. We don't really use this and it's just maintained because this was how the code was originally made.

		assert self.project != None, "No project is loaded"

		self.state = None
		if addr == 0:
			self.state = self.project.factory.entry_state(add_options=self.options, remove_options={angr.options.LAZY_SOLVES})
		else:
			self.state = self.project.factory.call_state(addr=addr, add_options=self.options, remove_options={angr.options.LAZY_SOLVES})

		assert self.state != None, "State could not be created"

		self.simulation_manager = self.project.factory.simulation_manager(self.state, save_unconstrained=True, save_unsat=True, completion_mode=all)

		#self.simulation_manager.use_technique(angr.exploration_techniques.Threading(threads=64)) # Causes IPython kernel crashes
		self.simulation_manager.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=2048))
		self.simulation_manager.use_technique(angr.exploration_techniques.Timeout(timeout=180))
		self.simulation_manager.use_technique(angr.exploration_techniques.Suggestions())

		assert self.simulation_manager != None, "Simulation manager could not be created"

		return self.simulation_manager

	def hook_symbol_if_exists(self, symbol_name, hook_class):
		sym = self.project.loader.find_symbol(symbol_name)
		if sym:
			return self.project.hook_symbol(symbol_name, hook_class())
		return None