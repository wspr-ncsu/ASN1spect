import csv
import os
import shutil
import subprocess
import zlib
from pathlib import Path
from typing import List, Tuple

import requests


class RepoParser:
    def __init__(
        self,
        csv_file: str,
        spec_save_path: str,
        asn1c_path: str = "/data/git/mouse07410/asn1c/asn1c/asn1c",
    ):
        """Initialize RepoParser with CSV file and specification save path

        Args:
                csv_file: Path to CSV file containing repository data
                spec_save_path: Path to save downloaded ASN.1 specifications
                asn1c_path: Path to asn1c compiler executable
        """
        self.csv_file = csv_file
        self.spec_save_path = spec_save_path
        self.asn1c_path = Path(asn1c_path)
        self.spec_file_to_binary = {}

    def get_asn1c_command(self, repo: str, includes: List[Path], spec: Path) -> list:
        """Build asn1c command for compiling specifications

        Args:
                repo: Repository name
                includes: List of include files
                spec: Path to specification file

        Returns:
                list: Command arguments for asn1c
        """
        command = []
        spec_name = spec.name

        base_command = [
            str(self.asn1c_path),
            "-pdu=all",
            "-fcompound-names",
            "-findirect-choice",
            "-fno-include-deps",
            # "-fincludes-quoted",
            "-no-gen-example",
            "-D",
            f"{self.spec_save_path}/{repo}/generated/{spec_name}",
        ]

        if includes:
            command = base_command.copy()
            for include in includes:
                if include.is_file():
                    fname = include.name
                    command.append(f"{self.spec_save_path}/{repo}/modules/{fname}")
            command.append(str(spec))
        else:
            command = base_command + [str(spec)]

        return command

    def download_file(self, url: str, filename: str) -> Path:
        """Download file from URL and save to filename

        Args:
                url: URL to download from
                filename: Path to save downloaded file
        """
        print(f"Downloading {url} Saving at {filename}")

        path = Path(filename)
        p2 = subprocess.Popen(["mkdir", "-p", str(path.parent.absolute())])
        stdout, stderr = p2.communicate()
        print(f"stdout: {stdout} stderr: {stderr}")

        response = requests.get(url, stream=True)

        if response.status_code == 200:
            with open(filename, "wb") as file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
            print(f"File downloaded successfully: {filename}")
        else:
            print(f"Failed to download file. Status code: {response.status_code}")

        return path

    def get_file_name(self, url: str) -> str:
        """Extract filename from URL

        Args:
                url: URL to extract filename from

        Returns:
                str: Filename from URL
        """
        return url.split("/")[-1]

    def process_spec_urls(self, urls: str) -> list[list[str]]:
        """Process specification URLs from pipe and comma separated string

        Args:
                urls: Pipe and comma separated string of URLs

        Returns:
                list[list[str]]: Processed URLs grouped by pipe separator
        """
        pipe_parts = urls.split("|")
        result = []

        for pipe_part in pipe_parts:
            if "," in pipe_part:
                comma_parts = pipe_part.split(",")
                result.append(comma_parts)
            else:
                result.append([pipe_part])
        return result
