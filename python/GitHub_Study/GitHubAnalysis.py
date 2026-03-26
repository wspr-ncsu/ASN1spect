import csv
import importlib.resources as resources
import os
from datetime import datetime, timedelta, timezone
from typing import Dict

import github
from github import Auth, Github


class GitHubAnalysis:
    def __init__(self, token: str, as_of_date: datetime):
        self.auth = Auth.Token(token)
        self.g = Github(auth=self.auth)
        self.as_of_date = as_of_date
        self.repos: Dict[str, Repo] = {}  # Using dict to prevent duplicates

    def analyze_repositories(
        self, search_query: str, base_filename: str, save_results: bool = True
    ):
        """Generic method to analyze repositories based on a search query"""
        search_results = self.g.search_code(search_query)

        # Process each unique repository
        for item in search_results:
            repo = item.repository
            if repo.full_name not in self.repos:
                try:
                    repo_obj = Repo(repo, self.as_of_date)
                    if repo_obj.is_empty_as_of:
                        print(
                            f"Skipping {repo.full_name} (no commits before {self.as_of_date})"
                        )
                        continue
                    self.repos[repo.full_name] = repo_obj
                    # repo_obj.get_all_forks(repo, self.repos)
                    print(f"Processed {repo_obj}")
                except Exception as e:
                    print(f"Error processing repository {repo.full_name}: {e}")

        # Save results
        if save_results:
            self._save_results(base_filename)
            self._print_statistics()

    def analyze_asn1c(self):
        """Analyze repositories containing ASN1C code"""
        self.repos.clear()  # Clear any existing repos
        self.analyze_repositories(
            "define    ASN_INTERNAL_H", "repository_data", save_results=False
        )
        self.analyze_repositories(
            "ASN_APPLICATION_H", "repository_data", save_results=True
        )

    def analyze_asn1scc(self):
        """Analyze repositories containing ASN1SCC code"""
        self.repos.clear()  # Clear any existing repos
        self.analyze_repositories(
            "define ASN1SCC_ASN1CRT_H_", "asn1scc_repository_data"
        )

    def analyze_esnacc(self):
        """Analyze repositories containing ESNACC code"""
        self.repos.clear()  # Clear any existing repos
        self.analyze_repositories("asn-incl.h", "esnacc_repository_data")

    def _save_results(self, base_filename: str):
        """Save results to CSV files"""
        base_repos = [repo for repo in self.repos.values() if not repo.repo.fork]

        # Remove existing files if they exist
        base_file = f"{base_filename}.csv"
        fork_file = f"{base_filename}_forks.csv"

        for filename in [base_file, fork_file]:
            with resources.path("GitHub_Study.data", filename) as file_path:
                if os.path.isfile(file_path):
                    os.remove(file_path)

        # Write base repositories
        with resources.path("GitHub_Study.data", base_file) as file_path:
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(
                    [
                        "Repository",
                        "Is Fork",
                        "Last Updated",
                        "ASN1C Source Last Updated",
                        "Status",
                        "Abandonment Date",
                        "Stars",
                        "Forks",
                    ]
                )
                for repo in base_repos:
                    self._write_repo_to_csv(repo, writer)

        # Write fork repositories
        with resources.path("GitHub_Study.data", fork_file) as file_path:
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(
                    [
                        "Repository",
                        "Is Fork",
                        "Last Updated",
                        "ASN1C Source Last Updated",
                        "Status",
                        "Abandonment Date",
                        "Stars",
                        "Forks",
                    ]
                )
                for repo in self.repos.values():
                    if repo not in base_repos:
                        self._write_repo_to_csv(repo, writer)

    def _write_repo_to_csv(self, repo: "Repo", writer):
        """Write repository data to CSV writer"""
        writer.writerow(
            [
                repo.repo.full_name,
                repo.repo.fork,
                repo.last_update,
                repo.asn1c_source_last_update,
                repo.status,
                repo.abandonment_date,
                repo.stars,
                len(repo.forks),
            ]
        )

    def _print_statistics(self):
        """Print repository statistics"""
        base_repos = [repo for repo in self.repos.values() if not repo.repo.fork]
        print(f"Total repos: {len(self.repos)}")
        print(f"Base repos: {len(base_repos)}")
        print(f"Total forks: {sum(len(repo.forks) for repo in self.repos.values())}")
        print(f"Total stars: {sum(repo.stars for repo in self.repos.values())}")


class Repo:
    def __init__(self, repo: github.Repository.Repository, as_of_date: datetime):
        self.repo = repo
        self.as_of_date = as_of_date
        self.forks = []
        self.stars = self.repo.stargazers_count  # Get stars directly in init
        self.commits = list(self.repo.get_commits(until=self.as_of_date))
        self.is_empty_as_of = len(self.commits) == 0
        if self.is_empty_as_of:
            self.asn1c_source_last_update = None
            self.last_update = None
            self.status = "UnknownNoCommitsBeforeDate"
            self.abandonment_date = None
            return

        self.asn1c_source_last_update = self._get_asn1c_source_last_update()
        self.last_update = self.commits[0].commit.author.date
        self.status, self.abandonment_date = self._check_abandonment_status()

    def _get_asn1c_source_last_update(self):
        """Find the last commit date for ASN1C source files (asn_internal.c or asn_SET_OF.c)"""
        try:
            tree = self.repo.get_git_tree(self.repo.default_branch, recursive=True)
            for item in tree.tree:
                if item.path.endswith(("asn_internal.c", "asn_SET_OF.c")):
                    commits = self.repo.get_commits(
                        path=item.path, until=self.as_of_date
                    )
                    if commits.totalCount > 0:
                        return commits[0].commit.author.date
        except Exception as e:
            print(
                f"Error getting ASN1C source last update for {self.repo.full_name}: {e}"
            )
        return None

    def _check_abandonment_status(self):
        """Check if repo is active, abandoned, or unknown based on activity patterns."""
        try:
            now = self.as_of_date
            two_years_ago = now - timedelta(days=730)
            four_years_ago = now - timedelta(days=1460)
            created_at = self.repo.created_at

            commits = self.commits
            if not commits:
                return "UnknownNoCommitsBeforeDate", None

            repo_age_days = (now - created_at).days
            if repo_age_days < 0:
                return "UnknownFutureRepo", None

            total_commits = len(commits)

            # Young repo (under 2 years): active if 10+ commits
            if repo_age_days < 730:
                if total_commits >= 10:
                    return "Active", None
                return "YoungRepo", None

            # Count events per year for the last 4 years
            def count_events_in_period(start, end):
                count = 0
                for commit in commits:
                    commit_date = commit.commit.author.date
                    if start <= commit_date < end:
                        count += 1
                return count

            # Check for 2 years of inactivity (abandonment phase)
            events_last_2_years = count_events_in_period(two_years_ago, now)

            if events_last_2_years == 0:
                # Check pre-abandonment: 2 years before with 10+ events/year
                events_year_3 = count_events_in_period(
                    four_years_ago, four_years_ago + timedelta(days=365)
                )
                events_year_4 = count_events_in_period(
                    four_years_ago + timedelta(days=365), two_years_ago
                )

                if events_year_3 >= 10 or events_year_4 >= 10:
                    # Find abandonment date (last commit before inactivity)
                    for commit in commits:
                        if commit.commit.author.date < two_years_ago:
                            return "Abandoned", commit.commit.author.date
                    return "Abandoned", None

            # Has recent activity
            if events_last_2_years > 10:
                return "Active", None

            if events_last_2_years > 0:
                return "ActiveLessThan10CommitsThisYear", None

            return "Abandoned", None

        except Exception as e:
            print(f"Error checking abandonment for {self.repo.full_name}: {e}")
            return "UnknownException", None

    def get_all_forks(self, result, repos: Dict[str, "Repo"]) -> None:
        """Recursively collect all forks of the repository"""
        try:
            for fork in result.get_forks():
                if fork.full_name not in repos:  # Skip if already processed
                    repo_fork = Repo(fork, self.as_of_date)
                    self.forks.append(repo_fork)
                    repos[fork.full_name] = repo_fork
                    repo_fork.get_all_forks(fork, repos)
        except Exception as e:
            print(f"Error processing forks for {result.full_name}: {e}")

    def __str__(self) -> str:
        return f"{self.repo.full_name} ({self.stars} stars, {len(self.forks)} forks)"
