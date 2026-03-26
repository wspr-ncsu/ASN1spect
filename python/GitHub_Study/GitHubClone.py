import csv
import importlib.resources as resources
import os
import shutil
import subprocess
from datetime import datetime
from itertools import chain
from pathlib import Path

from github import Auth, Github


class GitHubClone:
    ASN1_SPEC_EXTENSIONS = {".asn1", ".asn"}

    def __init__(self, token: str, as_of_date: datetime):
        self.auth = Auth.Token(token)
        self.g = Github(auth=self.auth)
        self.as_of_date = as_of_date

    def _find_header_folders(self, root: Path, files: list[Path]) -> Path | None:
        """Check if directory contains ASN.1 header files

        Args:
                root: Current directory path being checked
                files: List of file paths in current directory

        Returns:
                Path | None: Path to folder containing header files, or None if not found
        """
        for file in files:
            if file.name == "asn_internal.h":
                return file.parent
        return None

    def _find_source_folders(self, root: Path, files: list[Path]) -> Path | None:
        """Check if directory contains ASN.1 source files

        Args:
                root: Current directory path being checked
                files: List of file paths in current directory

        Returns:
                Path | None: Path to folder containing source files, or None if not found
        """
        for file in files:
            if file.name in ("asn_internal.c", "asn_SET_OF.c"):
                return file.parent
        return None

    def _find_asn1_spec_files(self, files: list[Path]) -> list[Path]:
        found = []
        for file in files:
            # Use suffix and normalize to lowercase for case-insensitive matching.
            if file.suffix.lower() in self.ASN1_SPEC_EXTENSIONS:
                found.append(file)

        return found

    def _write_asn1_spec_presence_csv(self, repos: dict, clone_root: Path) -> None:
        """Write a CSV documenting which repositories contain ASN.1 specification files.

        The CSV is written into the packaged data directory so downstream steps can
        reference it consistently (similar to the other CSV artifacts produced by
        this project).

        Columns:
        - Repository: owner/name
        - Has ASN.1 Specs: TRUE/FALSE
        - ASN.1 Spec Files: semicolon-separated list of repo-relative paths to spec files
        """
        filename = "asn1_spec_presence.csv"
        with resources.path("GitHub_Study.data", filename) as file_path:
            # Overwrite to ensure deterministic output for repeat runs.
            if os.path.isfile(file_path):
                os.remove(file_path)

            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Repository", "Has ASN.1 Specs", "ASN.1 Spec Files"])

                for repo_name, code_locs in repos.items():
                    asn1_spec_files = []
                    if isinstance(code_locs, list) and len(code_locs) >= 3:
                        asn1_spec_files = code_locs[2] or []

                    # Convert to repo-relative paths for stable reporting.
                    repo_dir = clone_root / repo_name
                    rel_paths = []
                    for p in asn1_spec_files:
                        try:
                            rel_paths.append(str(Path(p).relative_to(repo_dir)))
                        except Exception:
                            # Fall back to string form if relative conversion fails.
                            rel_paths.append(str(p))

                    writer.writerow(
                        [
                            repo_name,
                            "TRUE" if len(asn1_spec_files) > 0 else "FALSE",
                            ";".join(sorted(rel_paths)),
                        ]
                    )

    def _check_for_files(
        self, repo_dir: Path
    ) -> tuple[list[Path], list[Path], list[Path]]:
        header_folder, source_folder, asn1_spec_files = [], [], []

        for path in chain([repo_dir], repo_dir.rglob("*")):
            try:
                is_dir = path.is_dir()
            except PermissionError:
                print(f"Permission denied accessing path {path}, continuing...")
                continue
            if is_dir:
                try:
                    files = []
                    for f in path.iterdir():
                        try:
                            if f.is_file():
                                files.append(f)
                        except PermissionError:
                            print(
                                f"Permission denied accessing file {f}, continuing..."
                            )
                            continue

                    temp_header = self._find_header_folders(path, files)
                    if temp_header is not None:
                        header_folder.append(temp_header)
                    temp_source = self._find_source_folders(path, files)
                    if temp_source is not None:
                        source_folder.append(temp_source)

                    # Collect ASN.1 spec files in this directory (if any).
                    asn1_spec_files.extend(self._find_asn1_spec_files(files))
                except PermissionError:
                    print(
                        f"Permission denied accessing directory {path}, continuing..."
                    )

        return header_folder, source_folder, asn1_spec_files

    def _read_repository_data(self) -> list:
        """Read repository data from CSV file

        Returns:
                list: List of rows from the CSV file
        """
        with resources.open_text("GitHub_Study.data", "repository_data.csv") as f:
            return list(csv.reader(f))

    def _should_clone_repository(self, repo_data: list) -> bool:
        """Check if repository meets criteria for cloning

        Returns:
                bool: True if repository should be cloned, False otherwise
        """
        return (
            repo_data[1] == "False"
            and (
                repo_data[4] == "Active"
                # or repo_data[4] == "ActiveLessThan10CommitsThisYear"
            )
            # and int(repo_data[6]) >= 10
        )

    def _checkout_as_of(self, repo_dir: Path) -> bool:
        """Checkout repository to the latest commit at or before as_of_date."""
        date_str = self.as_of_date.isoformat()
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_dir),
                "rev-list",
                "-n",
                "1",
                f"--before={date_str}",
                "HEAD",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(
                f"Failed to resolve commit for {repo_dir} at or before {date_str}: {result.stderr}"
            )
            return False

        commit = result.stdout.strip()
        if not commit:
            print(f"No commit found at or before {date_str} for {repo_dir}")
            return False

        checkout = subprocess.run(["git", "-C", str(repo_dir), "checkout", commit])
        if checkout.returncode != 0:
            print(f"Failed to checkout {commit} for {repo_dir}")
            return False

        return True

    def _clone_single_repository(self, repo_name: str, path: Path) -> Path | None:
        """Clone a single repository

        Args:
                repo_name: Name of repository to clone (owner/repo format)
                path: Base path to clone repositories into

        Returns:
                str: Path to cloned repository
        """
        ssh_site = f"git@github.com:{repo_name}.git"
        https_site = f"https://github.com/{repo_name}.git"
        folder = path / repo_name

        if not folder.is_dir():
            print(f"Cloning repository {repo_name} to {folder}")

            # Try SSH first to avoid interactive username/password prompts.
            # BatchMode=yes ensures SSH will not block on prompts (it will fail fast instead).
            ssh_result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.sshCommand=ssh -o BatchMode=yes",
                    "clone",
                    ssh_site,
                    str(folder),
                ],
                check=False,
            )

            if ssh_result.returncode != 0:
                print(
                    f"SSH clone failed for {repo_name} (exit {ssh_result.returncode}); trying HTTPS next"
                )

                # If SSH failed (e.g., repo doesn't exist, no SSH access), fall back to HTTPS while still avoiding prompts.
                # GIT_TERMINAL_PROMPT=0 prevents Git from prompting for credentials interactively.
                if folder.exists():
                    shutil.rmtree(folder, ignore_errors=True)

                https_result = subprocess.run(
                    ["git", "clone", https_site, str(folder)],
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                    check=False,
                )

                if https_result.returncode != 0:
                    print(
                        f"HTTPS clone failed for {repo_name} (exit {https_result.returncode}); skipping"
                    )
                    if folder.exists():
                        shutil.rmtree(folder, ignore_errors=True)
                    return None

            # Only chmod after a successful clone created the directory.
            if folder.is_dir():
                subprocess.run(["chmod", "-R", "a+r", str(folder)])
            else:
                return None
        # else:
        # 	print(f"Repository {repo_name} already exists in {folder}, pulling latest changes")
        # 	subprocess.run(["git", "-C", str(folder), "pull"])

        # Never attempt checkout/chdir if clone didn't create the folder
        if not folder.is_dir():
            return None

        if not self._checkout_as_of(folder):
            if folder.is_dir():
                shutil.rmtree(folder, ignore_errors=True)
            return None

        return folder

    def clone_repositories(self, path: Path) -> dict:
        """Clone repositories from CSV data that meet criteria and check for ASN.1 files

        Args:
                path: Base path to clone repositories into

        Returns:
                dict: Dictionary mapping repository names to lists of
                      [header_folders, source_folders, asn1_spec_files]
        """
        repos = {}

        for row in self._read_repository_data():
            if self._should_clone_repository(row):
                repo_folder = self._clone_single_repository(row[0], path)
                if repo_folder is None:
                    continue

                header_folders, source_folders, asn1_spec_files = self._check_for_files(
                    repo_folder
                )
                repos[row[0]] = [header_folders, source_folders, asn1_spec_files]

        # Persist a CSV documenting ASN.1 specification presence/locations.
        self._write_asn1_spec_presence_csv(repos, path)

        return repos
