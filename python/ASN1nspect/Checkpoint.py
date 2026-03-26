import json
import os
import pickle
import time
from importlib.resources import files
from pathlib import Path

from fasteners import InterProcessLock


class Checkpoint:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self._array_mismatches = None
        self._recursive_types = None
        self._NativeEnumerated_Types = None
        self._NativeEnumerated_Timeouts = None
        self._inherit_symbol_problems = None
        self._project_types = {}
        self._skipped_binaries = None
        self._constraints = None

        self.checkpoint_dir = files("ASN1nspect.data.checkpoints")

        self.recursive_types_pickle = self.checkpoint_dir / "recursive_types.pickle"
        self.array_mismatches_pickle = self.checkpoint_dir / "array_mismatches.pickle"
        self.NativeEnumerated_pickle = self.checkpoint_dir / "NativeEnumerated.pickle"
        self.NativeEnumeratedTimeouts_pickle = (
            self.checkpoint_dir / "NativeEnumeratedTimeouts.pickle"
        )
        self.inherit_symbol_pickle = self.checkpoint_dir / "inherit_symbol.pickle"
        self.skipped_binaries_pickle = self.checkpoint_dir / "skipped_binaries.pickle"
        self.constraints_pickle = self.checkpoint_dir / "constraints.pickle"

        # Create locks for each file
        self._locks = {
            str(self.recursive_types_pickle): InterProcessLock(
                str(self.recursive_types_pickle) + ".lock"
            ),
            str(self.array_mismatches_pickle): InterProcessLock(
                str(self.array_mismatches_pickle) + ".lock"
            ),
            str(self.NativeEnumerated_pickle): InterProcessLock(
                str(self.NativeEnumerated_pickle) + ".lock"
            ),
            str(self.NativeEnumeratedTimeouts_pickle): InterProcessLock(
                str(self.NativeEnumeratedTimeouts_pickle) + ".lock"
            ),
            str(self.inherit_symbol_pickle): InterProcessLock(
                str(self.inherit_symbol_pickle) + ".lock"
            ),
            str(self.skipped_binaries_pickle): InterProcessLock(
                str(self.skipped_binaries_pickle) + ".lock"
            ),
            str(self.constraints_pickle): InterProcessLock(
                str(self.constraints_pickle) + ".lock"
            ),
        }

    def _log(self, message):
        """Internal method to handle verbose printing"""
        if self.verbose:
            print(message)

    def _save_pickle(self, data, filepath):
        """Helper method to save pickle data and corresponding JSON"""
        self._log(f"Saving to {filepath}")
        lock = self._locks[str(filepath)]

        with lock:
            # Save pickle file
            with open(filepath, "wb") as f:
                pickle.dump(data, f)

    def _save_json(self, data, filepath):
        lock = self._locks[str(filepath)]

        with lock:
            # Save JSON file
            json_path = filepath.with_suffix(".json")
            self._log(f"Saving JSON to {json_path}")
            with open(json_path, "w") as f:
                json.dump(data, f, indent=4)

    def _load_pickle(self, filepath):
        """Helper method to safely load pickle data with locking"""
        if os.path.isfile(filepath):
            self._log(f"Loading {filepath}")
            lock = self._locks[str(filepath)]

            with lock:
                with open(filepath, "rb") as f:
                    return pickle.load(f)
        return None

    def _load_json(self, filepath):
        """Helper method to safely load JSON data with locking"""
        json_path = filepath.with_suffix(".json")
        if os.path.isfile(json_path):
            self._log(f"Loading JSON {json_path}")
            lock = self._locks[str(filepath)]

            with lock:
                with open(json_path, "r") as f:
                    return json.load(f)
        return None

    @property
    def array_mismatches(self):
        if self._array_mismatches is None:
            self._array_mismatches = self._load_pickle(self.array_mismatches_pickle)
            if self._array_mismatches is None:
                self._array_mismatches = {}
        return self._array_mismatches

    @array_mismatches.setter
    def array_mismatches(self, value):
        self._array_mismatches = value
        self._save_pickle(value, self.array_mismatches_pickle)
        self._save_json(value, self.array_mismatches_pickle)

    @property
    def recursive_types(self):
        if self._recursive_types is None:
            self._recursive_types = self._load_pickle(self.recursive_types_pickle)
            if self._recursive_types is None:
                self._recursive_types = {}
        return self._recursive_types

    @recursive_types.setter
    def recursive_types(self, value):
        self._recursive_types = value
        self._save_pickle(value, self.recursive_types_pickle)
        self._save_json(value, self.recursive_types_pickle)

    @property
    def inherit_symbol_problems(self):
        if self._inherit_symbol_problems is None:
            self._inherit_symbol_problems = self._load_pickle(
                self.inherit_symbol_pickle
            )
            if self._inherit_symbol_problems is None:
                self._inherit_symbol_problems = {}
        return self._inherit_symbol_problems

    @inherit_symbol_problems.setter
    def inherit_symbol_problems(self, value):
        self._inherit_symbol_problems = value
        self._save_pickle(value, self.inherit_symbol_pickle)
        self._save_json(value, self.inherit_symbol_pickle)

    @property
    def NativeEnumerated_Types(self):
        if self._NativeEnumerated_Types is None:
            self._NativeEnumerated_Types = self._load_pickle(
                self.NativeEnumerated_pickle
            )
            if self._NativeEnumerated_Types is None:
                self._NativeEnumerated_Types = {}
        return self._NativeEnumerated_Types

    @NativeEnumerated_Types.setter
    def NativeEnumerated_Types(self, value):
        self._NativeEnumerated_Types = value
        self._save_pickle(value, self.NativeEnumerated_pickle)
        self._save_json(value, self.NativeEnumerated_pickle)

    @property
    def NativeEnumerated_Timeouts(self):
        if self._NativeEnumerated_Timeouts is None:
            self._NativeEnumerated_Timeouts = self._load_json(
                self.NativeEnumeratedTimeouts_pickle
            )
            if self._NativeEnumerated_Timeouts is None:
                self._NativeEnumerated_Timeouts = {}
        return self._NativeEnumerated_Timeouts

    @NativeEnumerated_Timeouts.setter
    def NativeEnumerated_Timeouts(self, value):
        self._NativeEnumerated_Timeouts = value
        self._save_json(value, self.NativeEnumeratedTimeouts_pickle)

    @property
    def skipped_binaries(self):
        if self._skipped_binaries is None:
            self._skipped_binaries = self._load_pickle(self.skipped_binaries_pickle)
            if self._skipped_binaries is None:
                self._skipped_binaries = {}
        return self._skipped_binaries

    @skipped_binaries.setter
    def skipped_binaries(self, value):
        self._skipped_binaries = value
        self._save_json(value, self.skipped_binaries_pickle)

    @property
    def constraints(self):
        if self._constraints is None:
            loaded = self._load_json(self.constraints_pickle)
            self._constraints = loaded if loaded is not None else {}
        return self._constraints

    @constraints.setter
    def constraints(self, value):
        existing = self._load_json(self.constraints_pickle)
        if existing is None:
            existing = {}

        for b1, b2_map in value.items():
            if b1 not in existing:
                existing[b1] = {}
            existing[b1].update(b2_map)

        self._constraints = existing
        self._save_json(existing, self.constraints_pickle)

    def record_skipped_binary(
        self, binary_name, processed_count, total_count, elapsed_time
    ):
        """Record information about a binary that was partially processed due to time constraints

        gs:
                binary_name (str): Name of the binary
                processed_count (int): Number of symbols processed
                total_count (int): Total number of symbols in the binary
                elapsed_time (float): Time spent processing (in seconds)
        """
        skipped = self.skipped_binaries
        skipped[binary_name] = {
            "processed_count": processed_count,
            "total_count": total_count,
            "skipped_count": total_count - processed_count,
            "elapsed_time": elapsed_time,
            "timestamp": time.time(),
        }
        self.skipped_binaries = skipped
        self._log(
            f"Recorded skipped binary: {binary_name} - processed {processed_count}/{total_count} symbols"
        )

    def get_project_pickle_path(self, project_name):
        """Get the pickle file path for a specific project's types"""
        return self.checkpoint_dir / f"project_types_{project_name}.pickle"

    def load_project_types(self, project_name):
        """Load types for a specific project"""
        pickle_path = self.get_project_pickle_path(project_name)
        lock_path = str(pickle_path) + ".lock"

        if str(pickle_path) not in self._locks:
            self._locks[str(pickle_path)] = InterProcessLock(lock_path)

        return self._load_pickle(pickle_path)

    def save_checkpoints(self):
        """Save all checkpoint data that has been loaded or modified"""
        if self._recursive_types is not None:
            self._save_pickle(self._recursive_types, self.recursive_types_pickle)

        if self._array_mismatches is not None:
            self._save_pickle(self._array_mismatches, self.array_mismatches_pickle)

        if self._NativeEnumerated_Types is not None:
            self._save_pickle(
                self._NativeEnumerated_Types, self.NativeEnumerated_pickle
            )

        if self._NativeEnumerated_Timeouts is not None:
            self._save_json(
                self._NativeEnumerated_Timeouts, self.NativeEnumeratedTimeouts_pickle
            )

        if self._inherit_symbol_problems is not None:
            self._save_pickle(self._inherit_symbol_problems, self.inherit_symbol_pickle)
