import csv
import importlib.resources as resources
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Union

from ASN1nspect.RepoParser import RepoParser


class ParserReplacer:
    def __init__(
        self,
        spec_dir: str,
        csv_file: str,
        output_dir: str,
        asn1c_dir="/data/git/mouse07410/asn1c/asn1c/asn1c",
        verbose: bool = False,
        clone_root: str = "/data/git/ASN1Analysis/python/GitHub_Study/data/binaries",
    ):
        self.csv_file = csv_file
        self.spec_dir = spec_dir
        self.output_dir = output_dir
        self.asn1c_dir = Path(asn1c_dir)
        self.clone_root = Path(clone_root)
        self.repo_parser = RepoParser(csv_file, spec_dir, asn1c_dir)
        self.compile_script_path = str(
            resources.files("ASN1nspect.data").joinpath("compile_asn1c.sh")
        )
        self.asn1c_output_path = str(
            resources.files("ASN1nspect.data").joinpath("asn1c_output.txt")
        )
        self.base_cpp_path = str(
            resources.files("ASN1nspect.data").joinpath("base.cpp")
        )
        self.verbose = verbose

        # Load fallback CSV into memory
        self.fallback_specs = self._load_fallback_csv()

        self.compile_specs()

    def _load_fallback_csv(self) -> Dict[str, List[str]]:
        """Load the auto-generated asn1_spec_presence.csv into a dict.

        Returns:
            Dict mapping repository name to list of repo-relative spec file paths.
        """
        fallback_specs = {}
        try:
            with (
                resources.files("GitHub_Study.data")
                .joinpath("asn1_spec_presence.csv")
                .open("r") as f
            ):
                reader = csv.reader(f)
                next(reader)  # Skip header row
                for row in reader:
                    if len(row) >= 3:
                        repo_name = row[0]
                        has_specs = row[1].upper() == "TRUE"
                        spec_files_str = row[2]
                        if has_specs and spec_files_str:
                            # Split semicolon-separated paths
                            spec_files = [
                                p.strip()
                                for p in spec_files_str.split(";")
                                if p.strip()
                            ]
                            fallback_specs[repo_name] = spec_files
        except Exception as e:
            print(f"Warning: Could not load fallback CSV: {e}")
        return fallback_specs

    def _prepare_directory(self, path: Path) -> None:
        """
        Removes and recreates a directory safely.

        Args:
                path: Directory path to prepare
        """
        try:
            if path.exists():
                subprocess.run(["rm", "-r", str(path)], check=True)
            os.makedirs(str(path), exist_ok=True)
        except subprocess.CalledProcessError as e:
            print(f"Error preparing directory {str(path)}: {e}")
        except OSError as e:
            print(f"OS error while preparing directory {str(path)}: {e}")

    def _append_to_file(self, filepath: Union[Path, str], content: str) -> None:
        """
        Safely append content to a file.

        Args:
                filepath: Path to the file
                content: Content to append
        """
        try:
            with open(str(filepath), "a") as f:
                f.write(content)
        except IOError as e:
            print(f"Error writing to {str(filepath)}: {e}")

    def _run_subprocess(
        self, command: Union[List[str], str], output_file: Union[Path, str]
    ) -> bool:
        """
        Run a subprocess and log its output.

        Args:
                command: Command to execute as list of strings
                output_file: File to write output to
        """
        try:
            process = subprocess.run(command, text=True, check=True)
            print(f"Done executing command: {' '.join(command)}\n")
            return process.returncode == 0
        except subprocess.SubprocessError as e:
            print(f"Error executing command: {' '.join(command)}\n{str(e)}")
            return False

    def download_specs(self, row) -> List[Path]:
        downloaded_files = []
        includes = self.get_spec_includes(row)
        specs = self.get_spec_files(row)
        for i, (include_list, spec_list) in enumerate(zip(includes, specs)):
            # Process includes
            for include in include_list:
                if include and include.startswith("http"):
                    include_name = self.repo_parser.get_file_name(include)
                    include_path = os.path.join(
                        self.spec_dir, self.get_repository(row), "modules", include_name
                    )
                    downloaded_files.append(
                        self.repo_parser.download_file(include, include_path)
                    )

            # Process specs
            for spec in spec_list:
                if spec and spec.startswith("http"):
                    spec_name = self.repo_parser.get_file_name(spec)
                    spec_file_path = os.path.join(
                        self.spec_dir, self.get_repository(row), spec_name
                    )
                    downloaded_files.append(
                        self.repo_parser.download_file(spec, spec_file_path)
                    )

        return downloaded_files

    def get_local_specs(self, repo_name: str, spec_paths: List[str]) -> List[Path]:
        """Get ASN.1 spec files from local cloned repository.

        Args:
            repo_name: Repository name (owner/repo format)
            spec_paths: List of repo-relative paths to spec files

        Returns:
            List of Path objects to the spec files (in order)
        """
        local_files = []
        repo_dir = self.clone_root / repo_name

        for rel_path in spec_paths:
            full_path = repo_dir / rel_path
            if full_path.exists():
                local_files.append(full_path)
            else:
                print(f"Warning: Spec file not found: {full_path}")

        return local_files

    def compile_specs(self) -> None:
        # Create file with headers if it doesn't exist
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(
                    [
                        "Repository",
                        "Is Fork?",
                        "Last Updated",
                        "ASN1C Source Last Updated",
                        "Status",
                        "Abandonment Date",
                        "Stars",
                        "Forks",
                        "Type",
                        "ASN.1 spec include(s)",
                        "ASN.1 spec file(s)",
                        "Specification Reference",
                        "asn1c fork used",
                        "Notes",
                    ]
                )

        # Track repos processed from primary CSV
        processed_repos = set()

        # Process primary CSV (with HTTP URLs)
        with open(self.csv_file, "r") as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header row
            for row in reader:
                self.csv = row  # Store current row for helper methods
                repo_name = self.get_repository(row)
                processed_repos.add(repo_name)

                files = self.download_specs(row)
                if not files:
                    continue

                command = self.repo_parser.get_asn1c_command(
                    repo_name, files[:-1], files[-1]
                )
                spec = files[-1]
                print(f"Executing command: {command}")
                self.compile_binary(repo_name, command, spec)

        # Process fallback CSV (with local paths)
        for repo_name, spec_paths in self.fallback_specs.items():
            if repo_name in processed_repos:
                # Already processed from primary CSV, skip
                continue

            print(f"Processing fallback repo: {repo_name}")
            files = self.get_local_specs(repo_name, spec_paths)
            if not files:
                print(f"No spec files found for fallback repo: {repo_name}")
                continue

            # All files except the last are includes, last is the main spec
            includes = files[:-1] if len(files) > 1 else []
            spec = files[-1]

            command = self.repo_parser.get_asn1c_command(repo_name, includes, spec)
            print(f"Executing command: {command}")
            self.compile_binary(repo_name, command, spec)

    def compile_binary(self, repo: str, command: List[str], spec: Path) -> bool:
        """
        Run ASN1C compiler command and set up GCC compilation.

        Args:
                repo: Repository name
                command: ASN1C command to run
                spec: Specification file path
                spec_save_files: Base directory for spec files
        """
        spec_name = spec.name
        spec_path = Path(self.spec_dir) / repo / "generated" / spec_name

        repo_name = repo.split("/", 1)[1] if "/" in repo else None
        author = repo.split("/", 1)[0] if "/" in repo else None

        self._prepare_directory(spec_path)
        self._run_subprocess(command, self.asn1c_output_path)

        gcc_command = (
            f"gcc -O0 -g -include arpa/inet.h "
            f'-I"{self.spec_dir}/{repo}/generated/{spec_name}" '
            f'-I"{self.asn1c_dir.parent.parent / "skeletons"}" '
            f'"{self.asn1c_dir.parent.parent / "skeletons"}"/*.c '
            f'-o "{self.spec_dir}/{repo}/{author}.{repo_name}_comparison.bin" '
            f'"{self.spec_dir}/{repo}/generated/{spec_name}"/*.c '
            f"{self.base_cpp_path} -lm\n"
        )
        completion_message = f'echo "Done trying to compile binary \\"{self.spec_dir}/{repo}/{author}.{repo_name}.bin\\""\n'

        if os.path.exists(self.compile_script_path):
            os.remove(self.compile_script_path)
        self._append_to_file(self.compile_script_path, gcc_command)
        self._append_to_file(self.compile_script_path, completion_message)
        self._append_to_file(
            self.compile_script_path,
            f'mv "{self.spec_dir}/{repo}/{author}.{repo_name}_comparison.bin" "{self.output_dir}"',
        )

        self._run_subprocess(["sh", self.compile_script_path], self.asn1c_output_path)
        return True

    def get_repository(self, row) -> str:
        """Get repository name from CSV row"""
        return row[0]

    def is_fork(self, row) -> bool:
        """Get fork status from CSV row"""
        return row[1].upper() == "TRUE"

    def get_last_updated(self, row) -> str:
        """Get last updated date from CSV row"""
        return row[2]

    def get_stars(self, row) -> int:
        """Get star count from CSV row"""
        return int(row[3])

    def get_forks(self, row) -> int:
        """Get fork count from CSV row"""
        return int(row[4])

    def get_type(self, row) -> str:
        """Get repository type from CSV row"""
        return row[5]

    def get_spec_includes(self, row) -> List[List[str]]:
        """Get ASN.1 spec includes from CSV row"""
        return self.repo_parser.process_spec_urls(row[9])

    def get_spec_files(self, row) -> List[List[str]]:
        """Get ASN.1 spec files from CSV row"""
        return self.repo_parser.process_spec_urls(row[10])

    def get_spec_reference(self, row) -> str:
        """Get specification reference from CSV row"""
        return row[11]
