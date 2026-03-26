#!/usr/bin/env python3
import argparse
import datetime
import importlib.resources as resources
import json
import multiprocessing
import os
import pickle
import re
import traceback
from collections import defaultdict
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, List, Optional, Tuple

import click
import redis
from ASN1spect import *
from ASN1spect.Checkpoint import Checkpoint
from ASN1spect.ComparisonStrategies import ASN1CConstraintComparison
from ASN1spect.FieldMatchers.ASN1CFieldMatcherStrategy import \
    ASN1CFieldMatcherStrategy
from ASN1spect.IOS import IOSAnalyzer
from ASN1spect.TypeParser import TypeParser
from tqdm import tqdm


@click.command()
@click.option('-b', '--binary', metavar='<str>', required=True, help='Binary file to analyze')
@click.option('-c', '--compare-binary', metavar='<str>', required=False, help='Full path to binary to compare against')
@click.option('-srs', '--srsran', metavar='<str>', required=False, help='Path to "libs1ap_asn1.a" file provided by srsRAN')
@click.option('-srs-header', '--srsran-header', metavar='<str>', required=False, help='Path to "s1ap_no_preprocessor.h" file provided by srsRAN')
@click.option('-v', '--verbose', metavar='<bool>', is_flag=True, help="Enable verbose printing")
@click.option('--asn1-specs-path', metavar='<str>', default="/data/asn1_specs", help='Path to save downloaded ASN.1 specifications')
@click.option('--asn1-repo-csv', metavar='<str>', default="", help='Path to CSV file containing repository ASN.1 mapping')
@click.option('-t', '--timelimit', metavar='<int>', required=False, default=86400, help='Time limit in seconds to analyze. Default is 24 hours.')
def main(binary: str, compare_binary: Optional[str], verbose: bool, srsran: Optional[str], srsran_header: Optional[str], asn1_specs_path: str, asn1_repo_csv: str, timelimit: Optional[int]) -> None:

	# Validate binary file exists

	if not binary or not compare_binary:
		click.echo(f"[*] Error: --binary and --compare-binary are required", err=True)
		return

	p_binary = Path(binary)
	if not p_binary.is_file():
		click.echo(f"[*] Error: {binary} does not exist", err=True)
		return
	else:
		click.echo(f"[*] asn1c: {binary} exists, loading...")

	p_compare_binary = Path(compare_binary)
	if not p_compare_binary.is_file():
		if srsran and srsran_header:
			click.echo(f"[*] Error: {compare_binary} does not exist, performing srsRAN analysis", err=True)
		else:
			click.echo(f"[*] Error: {compare_binary} does not exist, trying to create it.", err=True)
			spec_path = Path(asn1_specs_path)
			csv = Path(asn1_repo_csv)
			if not csv.is_file():
				click.echo(f"[*] Error: {str(csv)} does not exist. Cannot continue without manual mapping of projects to ASN.1 specs", err=True)

			if not spec_path.is_dir():
				click.echo(f"[*] Error: {str(spec_path)} does not exist. Creating it...", err=True)
				spec_path.mkdir(parents=True, exist_ok=True)

			replacer = ParserReplacer(asn1_specs_path, asn1_repo_csv, compare_binary, verbose=verbose)

	else:
		click.echo(f"[*] asn1c: {compare_binary} exists, loading...")

	# Before loading the project, we need to augment angr with the C++ type definitions of asn1c.
	# This helps when looking at the symbolic memory later.
	type_parser = TypeParser()

	# Initialize checkpoint manager once at the start
	checkpoint = Checkpoint(verbose)

	header_future, analyzer_future = process_srsran(srsran, srsran_header, verbose)

	# Regex to match ASN.1 type definitions, excluding tags/constraints/conversion functions

	# Create process pool
	with ProcessPoolExecutor(max_workers=2) as executor:
		futures = []

		# Load and process first binary
		futures.append(executor.submit(process_binary, p_binary, verbose, asn_DEFs, timelimit))

		# Load and process matching binary if it exists
		if p_compare_binary.is_file():
			futures.append(executor.submit(process_binary, p_compare_binary, verbose, asn_DEFs, timelimit))

		# Wait for all processes to complete
		results = []
		for future in as_completed(futures):
			try:
				result = future.result()
				if result is not None:
					results.append(result)
			except Exception as e:
				print(f"Process failed: {str(e)}")
				return

		if len(results) == 0:
			return

		project = results[0]
		project2 = results[1] if len(results) > 1 else None

	########## MAIN IOS
	ios_analyzer = IOSAnalyzer(project)
	protocols = ios_analyzer.get_protocols()

	# Handle compiling another binary here for the differential analysis.

	if srsran and srsran_header:
		header_result = header_future.result()
		analyzer_result = analyzer_future.result()

	# Perform constraint comparisons sequentially
	try:
		ASN1CConstraintComparison(
			project,
			project2,
			ASN1CFieldMatcherStrategy(project, project2, verbose=verbose)
		)
	except Exception as e:
		print(f"Exception occurred during constraint comparison between {project.get_binary()} and {project2.get_binary()}")
		print(e)
		if verbose:
			traceback.print_exception(e)

	print("Done comparing constraints!")

def load_binary(binary_path: Path, verbose: bool) -> Optional[ASN1AngrProject]:
	"""Helper function to load a single binary"""
	try:
		loader = BinaryLoader(binary_path)
		project = loader.create_project()
		if verbose:
			click.echo(f"Successfully loaded project for {binary_path}")
		return project
	except Exception as e:
		click.echo(f"Failed to load {binary_path}: {str(e)}", err=True)
		if verbose:
			traceback.print_exc()
		return None

def process_binary(binary_path: Path, verbose: bool, asn_DEFs: re.Pattern, timelimit: int) -> Optional[ASN1AngrProject]:
	project = load_binary(binary_path, verbose)
	if project is None:
		return None

	project.analyze(timelimit)

	return project

def parse_header(srsran_header: Path) -> dict:
	"""Parse the srsRAN header file"""
	header_parser = SRSRANHeaderParser(srsran_header)
	return header_parser.parse_header()

def srsran_analyze(srsran: Path, verbose: bool) -> None:
	"""Analyze the srsRAN binary and header files in parallel"""
	analyze = SRSRANAnalyzer(srsran, verbose)
	analyze.analyze()

def process_srsran(srsran: Optional[str], srsran_header: Optional[str], verbose: bool) -> Optional[Tuple[Future, Future]]:
	"""Process srsRAN binary and header files in parallel"""
	if srsran_header and not srsran or not srsran_header and srsran:
		click.echo(f"[*] Error: --srs-header requires --srs and --srs requires --srs-header", err=True)
		return None, None

	if srsran:
		if srsran_header:
			srsran_header_path = Path(srsran_header)
			if not srsran_header_path.is_file():
				click.echo(f"[*] Error: {srsran_header_path} does not exist", err=True)
				return
			else:
				click.echo(f"[*] srsRAN header: {srsran_header_path} exists, loading...")

			# Create a process pool for parallel execution
			with ProcessPoolExecutor(max_workers=2) as executor:
				# Submit header parsing task
				header_future = executor.submit(parse_header, srsran_header_path)

				# Check if srsRAN binary exists
				srsran_path = Path(srsran)
				if not srsran_path.is_file():
					click.echo(f"[*] Error: {srsran_path} does not exist", err=True)
					return
				else:
					click.echo(f"[*] srsRAN: {srsran_path} exists, loading...")

				# Submit analyzer task
				analyzer_future = executor.submit(srsran_analyze, srsran_path, verbose)

				return header_future, analyzer_future
	return None, None

if __name__ == "__main__":
	main()
