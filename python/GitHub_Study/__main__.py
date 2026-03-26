import gc
import importlib.resources as resources
import json
import logging
import os
import traceback
from collections import defaultdict
from pathlib import Path
from typing import Optional

import click
from ASN1spect import (IOS, AngrProject, ASN1AngrProject, BinaryLoader,
                        Checkpoint, ParserReplacer, TypeParser)
from GitHub_Study.GitHubAnalysis import GitHubAnalysis
from GitHub_Study.GitHubClone import GitHubClone
from GitHub_Study.GitHubCompile import GitHubCompile
from GitHub_Study.ProjectComparator import ProjectComparator
from tqdm import tqdm

logging.getLogger('angr.knowledge_plugins.debug_variables').setLevel(logging.ERROR)


@click.command()
@click.option('-b', '--binary', metavar='<str>', required=True, help='Path to folder containing binary files')
@click.option('-v', '--verbose', metavar='<bool>', type=bool, is_flag=True, help='Verbose logging')
# @click.option('-p', '--processes', metavar='<int>', default=None, type=int, help='Number of processes to use (defaults to CPU count)')
@click.option('--compile', is_flag=True, help='Compile cloned repositories before analysis, also clones if not already cloned')
@click.option('--github-token', metavar='<str>', help='GitHub API token for cloning repositories')
@click.option('--clone-dir', metavar='<str>', type=click.Path(), help='Directory to clone repositories to (defaults to binary directory)')
@click.option('--I_READ_THE_WARNING', is_flag=True, help='Automatically accept the long running process warning')
@click.option('--asn1-specs-path', metavar='<str>', default="/data/asn1_specs", help='Path to save downloaded ASN.1 specifications')
@click.option('--asn1-repo-csv', metavar='<str>', default="", help='Path to CSV file containing repository ASN.1 mapping')
#@click.option('-t', '--timelimit', metavar='<int>', required=False, default=86400, help='Time limit in seconds to analyze. Default is 24 hours.')

def main(binary: str, compile: bool, verbose: bool, github_token: str, clone_dir: str, i_read_the_warning: bool, asn1_specs_path: str, asn1_repo_csv: str):
	"""
	Main entry point for the GitHub Study application.
	"""
	p = Path(binary)

	# Create a cache file path relative to the binary directory
	cache_file = p / "processed_files_cache.json"

	# Load the cache if it exists
	processed_files_cache = []
	if cache_file.exists():
		try:
			with open(cache_file, 'r') as cache:
				processed_files_cache = json.load(cache)
				if verbose:
					click.echo(f"[*] Loaded cache with {len(processed_files_cache)} processed files")
		except json.JSONDecodeError:
			click.echo("[*] Warning: Cache file is corrupted, starting with empty cache", err=True)
			processed_files_cache = []

	clone_path = Path(clone_dir) if clone_dir else p

	# Warn user about long processing time and get confirmation
	if not i_read_the_warning:
		click.echo("[!] Warning: This process can take a very long time to complete and cannot be interrupted. Use --I_READ_THE_WARNING to skip this warning.")
		click.echo("[!] Type 'Y' to continue or any other key to abort...")
		confirmation = input().strip()
		if confirmation.upper() != 'Y':
			click.echo("[*] Operation aborted by user")
			return
	else:
		click.echo("[*] Automatically accepted the long running process warning with -y flag")

	if compile:
		if not github_token:
			click.echo("[*] Error: GitHub token is required for cloning repositories", err=True)
			return

		click.echo("[*] Analyzing GitHub repositories to find asn1c") #, asn1scc, and esnacc code...")
		analyzer = GitHubAnalysis(github_token)
		analyzer.analyze_asn1c()
		analyzer.analyze_asn1scc()
		analyzer.analyze_esnacc()

		click.echo("[*] Cloning asn1c GitHub repositories...")
		cloner = GitHubClone(github_token)
		repos = cloner.clone_repositories(clone_path)

		click.echo("[*] Compiling cloned repositories...")
		compiler = GitHubCompile(repos, clone_path, p)
		compiler.compile_repositories()

		click.echo("[*] Compiling ASN.1 specifications into ASN.1 parsers for projects")
		if len(asn1_repo_csv) == 0:
			asn1_repo_csv = str(resources.files('GitHub_Study.data').joinpath("asn1c_repos.csv"))

		replacer = ParserReplacer(asn1_specs_path, asn1_repo_csv, binary, verbose=verbose)

	if not p.is_dir():
		click.echo(f"[*] Error: {binary} is not a directory", err=True)
		return

	# Get list of binary files
	binary_files = sorted(list(p.glob('*.bin')))

	if not binary_files:
		click.echo(f"[*] No .bin files found in {binary}", err=True)
		return

	# Initialize type parser
	parser = TypeParser()

	click.echo(f"[*] Processing {len(binary_files)} files")

	# Process files in parallel with proper progress bar handling
	projects = []
	results = []
	for file in tqdm(binary_files, desc="Processing files"):
		try:
			file = Path(os.path.abspath(os.path.realpath(file)))
			file_path_str = str(file)

			# Check if file has already been processed
			if file_path_str in processed_files_cache:
				if verbose:
					click.echo(f"[*] Skipping {file.name} (already processed)")
				continue

			# Load the binary file
			loader = BinaryLoader(file)
			proj = loader.create_project()

			# Create checkpoint for analysis results
			checkpoint = Checkpoint(False)

			# # Analyze the binary
			proj.analyze()

			# # Add successful project to the list
			projects.append(proj)

			comparator = ProjectComparator(projects)
			comparator.run()

			for k, v in comparator.projects_to_compare.items():
				for i in v:
					print("Removing project ", i.get_binary(), "because we compared it to another project.")
					projects.remove(i)
					# Update cache with successfully processed file
					processed_files_cache.append(str(i.get_binary()))
					# Save the updated cache
					with open(cache_file, 'w') as cache:
						json.dump(processed_files_cache, cache, indent=2)
						if verbose:
							click.echo(f"[*] Updated cache file with {i.get_binary().name}")
					del i

			if comparator.non_compared_projects:
				# Keep only the last item in the list
				for i in comparator.non_compared_projects[:-1]:
					print("Removing project ", i.get_binary(), "because it has no compared project.")
					projects.remove(i)
					# Update cache with successfully processed file
					processed_files_cache.append(str(i.get_binary()))
					# Save the updated cache
					with open(cache_file, 'w') as cache:
						json.dump(processed_files_cache, cache, indent=2)
						if verbose:
							click.echo(f"[*] Updated cache file with {i.get_binary().name}")
					del i


			if verbose:
				click.echo(f"[*] Analysis complete for {file}.")

		except Exception as e:
			click.echo(f"[*] Error processing {file}: {str(e)}", err=True)
			if verbose:
				traceback.print_exc()

	click.echo(f"[*] Analysis complete for {len(projects)} files.")

	# Create and run the comparator


if __name__ == "__main__":
	main()
