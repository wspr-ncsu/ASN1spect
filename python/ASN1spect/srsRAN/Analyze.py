import re, angr, claripy, cxxfilt, cxxheaderparser
from ASN1spect.IOS import ProtocolIE, Criticality, Presence
from ASN1spect.srsRAN.Structure import Structure
from ASN1spect.srsRAN.Field import Field
from ASN1spect.ASN1AngrProject import ASN1AngrProject
from cxxheaderparser.simple import parse_file
from pathlib import Path
srsRANfuncs_asn_crit = re.compile(r"""(?P<class>^asn1::s1ap::.*::)get_crit\(unsigned int const&\)$""")
srsRANfuncs_asn_idx_to_id = re.compile(r"""(?P<class>^asn1::s1ap::.*::)idx_to_id\(unsigned int\)$""")
srsRANfuncs_asn_pres = re.compile(r"""(?P<class>^asn1::s1ap::.*::)get_presence\(unsigned int const&\)$""")


crit_opt = angr.types.parse_types("""struct crit_opts {
  enum options { reject, ignore, notify, nulltype } value;
};

struct value_c {
  struct types_opts {
    enum options { erab_info_list_item, nulltype } value;

    char* to_string();
  };
};""")

angr.types.register_types(crit_opt)

MAX_SYMBOLIC_VARS = 500

class SRSRANAnalyzer:
	def __init__(self, binary_path: Path, verbose: bool):
		self.protocols = {}
		self.symbolic_var_size = 4 * 8
		self.max_symbolic_vars = 500
		self.verbose = verbose

		self.project = ASN1AngrProject(binary_path)
		self.project.load_project()

	def _create_symbolic_var(self):
		"""Create a symbolic variable and pointer wrapper"""
		symbolic_var = claripy.BVS("symbolic_var", self.symbolic_var_size)
		ptr_to_symbolicvar = angr.PointerWrapper(symbolic_var)
		return symbolic_var, ptr_to_symbolicvar

	def _get_angr_options(self):
		"""Get common angr options used across functions"""
		options = angr.options.resilience.union(angr.options.refs).union(angr.options.symbolic).union(angr.options.common_options)
		options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
		options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
		options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
		options.add(angr.options.TRACK_SOLVER_VARIABLES)
		return options

	def _setup_angr_state(self, angrProject, f, symbolic_var, ptr_to_symbolicvar, prototype):
		"""Setup common angr state configuration"""
		options = self._get_angr_options()
		init_state = angrProject.factory.full_init_state(add_options=options)
		cc = angrProject.factory.cc()

		if ptr_to_symbolicvar:
			state = angrProject.factory.call_state(f.rebased_addr, ptr_to_symbolicvar, cc=cc, prototype=prototype, base_state=init_state)
		else:
			state = angrProject.factory.call_state(f.rebased_addr, symbolic_var, cc=cc, prototype=prototype, base_state=init_state)

		return state, cc, init_state

	def analyze(self):
		"""Analyze all srsRAN projects"""
		self.analyze_project_criticality()
		self.analyze_project_enum_numbers()
		self.analyze_project_presence()

	def analyze_project_criticality(self):
		"""Analyze criticality values for a single srsRAN project"""
		if self.verbose:
			print("Analyzing criticality values for srsRAN project")

		angrProject = self.project.get_project()
		protocols = {}

		for o in angrProject.loader.all_objects:
			for f in o.symbols:
				demangle = cxxfilt.demangle(f.name)
				res = srsRANfuncs_asn_crit.match(demangle)
				if res is None:
					continue

				prefix = res.group("class")
				if prefix not in protocols:
					protocols[prefix] = {}

				symbolic_var, ptr_to_symbolicvar = self._create_symbolic_var()
				prototype = angr.sim_type.SimTypeFunction([angr.sim_type.SimTypePointer(angr.sim_type.SimTypeInt(signed=False))], angr.sim_type.SimTypeInt(signed=False))
				state, cc, init_state = self._setup_angr_state(angrProject, f, symbolic_var, ptr_to_symbolicvar, prototype)

				simgr2 = angrProject.factory.simulation_manager(state, save_unconstrained=True, save_unsat=True, completion_mode=all)

				while len(simgr2.active) > 0:
					simgr2.step()

				for state2 in simgr2.deadended:
					if state2.solver.satisfiable(extra_constraints=[state2.regs.al < 3]):
						possible_values = state2.solver.eval_upto(symbolic_var, self.max_symbolic_vars, extra_constraints=[state2.regs.al < 3])
						for value in possible_values:
							protocols[prefix][value] = ProtocolIE(criticality=Criticality(state2.solver.eval(state2.regs.al)), id=value)

		self.protocols[self.project] = protocols
		return protocols

	def analyze_project_enum_numbers(self):
		"""Analyze enum number mappings for a single srsRAN project"""
		if self.verbose:
			print("Analyzing enum number mappings for srsRAN project")
		angrProject = self.project.get_project()
		obj = self.project.get_project().loader.all_objects

		# First find all map_enum_number addresses
		map_enum_addrs = self._find_map_enum_addrs(obj)

		# Then analyze idx_to_id functions
		for o in obj:
			for f in o.symbols:
				demangle = cxxfilt.demangle(f.name)
				res = srsRANfuncs_asn_idx_to_id.match(demangle)
				if res is not None:
					prefix = res.group("class")

					symbolic_var, _ = self._create_symbolic_var()
					prototype = angr.sim_type.SimTypeFunction([angr.sim_type.SimTypeInt(signed=False)], angr.sim_type.SimTypeInt(signed=False))
					state, cc, init_state = self._setup_angr_state(angrProject, f, symbolic_var, None, prototype)

					simgr2 = angrProject.factory.simulation_manager(state, save_unconstrained=True, save_unsat=True, completion_mode=all)

					while len(simgr2.active) > 0:
						simgr2.explore(find=map_enum_addrs)

					for state2 in simgr2.found:
						options = state2.mem[state2.regs.rdi].uint32_t.array(state2.solver.eval(state2.regs.esi))

						for i in range(0, state2.solver.eval(state2.regs.esi)):
							value = options[i].concrete
							self.protocols[self.project][prefix][value].enum_idx = i

	def _find_map_enum_addrs(self, obj):
		"""Find all map_enum_number addresses"""
		map_enum_addrs = []
		for o in obj:
			for f in o.symbols:
				demangle = cxxfilt.demangle(f.name)
				if "map_enum_number" in demangle:
					map_enum_addrs.append(f.rebased_addr)
		return map_enum_addrs

	def analyze_project_presence(self):
		"""Analyze presence values for a single srsRAN project"""
		if self.verbose:
			print("Analyzing presence values for srsRAN project")

		angrProject = self.project.get_project()
		obj = self.project.get_project().loader.all_objects

		for o in obj:
			for f in o.symbols:
				demangle = cxxfilt.demangle(f.name)
				res = srsRANfuncs_asn_pres.match(demangle)
				if res is not None:
					prefix = res.group("class")

					symbolic_var, ptr_to_symbolicvar = self._create_symbolic_var()
					prototype = angr.sim_type.SimTypeFunction([angr.sim_type.SimTypePointer(angr.sim_type.SimTypeInt(signed=False))], angr.sim_type.SimTypeInt(signed=False))
					state, cc, init_state = self._setup_angr_state(angrProject, f, symbolic_var, ptr_to_symbolicvar, prototype)

					simgr2 = angrProject.factory.simulation_manager(state, save_unconstrained=True, save_unsat=True, completion_mode=all)

					while len(simgr2.active) > 0:
						simgr2.step()

					for state2 in simgr2.deadended:
						if state2.solver.satisfiable(extra_constraints=[state2.regs.al < 3]):
							possible_values = state2.solver.eval_upto(symbolic_var, self.max_symbolic_vars, extra_constraints=[state2.regs.al < 3])

							for value in possible_values:
								self.protocols[self.project][prefix][value].presence = Presence(state2.solver.eval(state2.regs.al))

		self.project.Protocols = self.protocols[self.project]

class SRSRANHeaderParser:
	def __init__(self, header_path: Path):
		self.ignored_functions = [
			"type", "pack", "unpack", "to_json", "to_string", "idx_to_id",
			"is_id_valid", "get_crit", "get_ext", "get_presence", "set",
			"get_value", "destroy_", "operator=", "to_number", "to_number_string",
			"cause_c", "successful_outcome", "unsuccessful_outcome", "value_c",
			"~value_c", "set_local", "set_global", "local"
		]
		self.types = {}
		self.header_path = header_path

	def parse_header(self):
		"""Parse the srsRAN S1AP header file and extract type information"""
		result = parse_file(self.header_path)
		self._parse_typedefs(result)
		self._parse_aliases(result)
		self._parse_classes(result)
		return self.types

	def _get_template_arg_type(self, arg):
		"""Extract type information from template arguments

		Args:
			arg: Template argument to parse

		Returns:
			Dict or str containing extracted type info
		"""
		if type(arg.arg) == cxxheaderparser.types.Value:
			return arg.arg.tokens[0].value

		typename = arg.arg.typename
		to_add = {}

		if len(typename.segments) == 0:
			raise Exception("(2) Unknown type " + str(type(typename)) + " " + str(typename))

		segment = typename.segments[0]
		if type(segment) == cxxheaderparser.types.Value:
			to_add[segment.name] = [segment.tokens[0].value]
		elif type(segment) == cxxheaderparser.types.Type:
			for argument in arg.arg.typename.segments[0].specialization.args:
				to_add[self._get_template_arg_type(argument)] = [None]
		elif type(segment) == cxxheaderparser.types.NameSpecifier:
			if segment.specialization == None:
				to_add[segment.name] = None
			else:
				to_add[segment.name] = []
				for argument in arg.arg.typename.segments[0].specialization.args:
					to_add[segment.name].append(self._get_template_arg_type(argument))
		else:
			raise Exception("(1) Unknown type " + str(type(typename)) + " " + str(typename))

		return to_add

	def _get_field_type(self, field, name):
		"""Extract field type information

		Args:
			field: Field to parse
			name: Name of the field

		Returns:
			Field object with extracted type info
		"""
		if type(field) == cxxheaderparser.types.Field or type(field) == cxxheaderparser.types.UsingAlias:
			theType = field.type
		elif type(field) == cxxheaderparser.types.Type:
			theType = field

		segment = theType.typename.segments[0]
		if type(segment) == cxxheaderparser.types.NameSpecifier and segment.specialization:
			to_add = []
			for arg in segment.specialization.args:
				if type(arg.arg) == cxxheaderparser.types.Value:
					to_add.append(arg.arg.tokens[0].value)
				elif type(arg.arg) == cxxheaderparser.types.Type:
					result = self._get_template_arg_type(arg)
					if len(result) != 0:
						to_add.append(result)

			if len(to_add) != 0:
				return Field(name, segment.name, to_add)

		return Field(name, segment.name)

	def _handle_method_parsing(self, method, struct):
		"""Parse method and add fields to structure

		Args:
			method: Method to parse
			struct: Structure to add fields to
		"""
		if not method.return_type:
			return

		theType = method.return_type
		if type(theType) == cxxheaderparser.types.Reference:
			theType = theType.ref_to

		method_name = method.name.segments[0].name
		if method_name not in self.ignored_functions and not theType.const:
			struct.fields.append(self._get_field_type(theType, method_name))

	def _parse_typedefs(self, result):
		"""Parse typedef declarations"""
		s1ap = result.namespace.namespaces["asn1"].namespaces["s1ap"]
		for typedef in s1ap.typedefs:
			if typedef.type.typename.segments[0].name == "enumerated" and \
				type(typedef.type.typename.segments[0].specialization) == cxxheaderparser.types.TemplateSpecialization:

				s = Structure.find_structure(typedef.name)
				filtered_enum = [i for i in s1ap.classes
					if i.class_decl.typename.segments[0].name == typedef.type.typename.segments[0].specialization.args[0].arg.typename.segments[0].name]

				s.constraints = (0, len(filtered_enum[0].enums[0].values) - 2)
				self.types[typedef.name] = s
				Structure.set_structure(typedef.name, s)

	def _parse_aliases(self, result):
		"""Parse using alias declarations"""
		s1ap = result.namespace.namespaces["asn1"].namespaces["s1ap"]
		for alias in s1ap.using_alias:
			struct = Structure.find_structure(alias.alias)
			field = self._get_field_type(alias, alias.alias)

			struct.fields = [field] if type(field) != list else field
			self.types[alias.alias] = struct

	def _parse_classes(self, result):
		"""Parse class declarations"""
		s1ap = result.namespace.namespaces["asn1"].namespaces["s1ap"]
		for template in s1ap.classes:
			struct = Structure.find_structure(template.class_decl.typename.segments[0].name)

			if template.enums:
				struct.constraints = (0, len(template.enums[0].values) - 2)

			struct.fields = [self._get_field_type(field, field.name) for field in template.fields]

			for cls in template.classes:
				if cls.class_decl.typename.segments[0].name in ["value_c", "ext_c", "init_msg_c"]:
					for method in cls.methods:
						self._handle_method_parsing(method, struct)

			for method in template.methods:
				self._handle_method_parsing(method, struct)

			self.types[template.class_decl.typename.segments[0].name] = struct