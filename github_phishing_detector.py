#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import time
from datetime import datetime
import os
import csv
import sys
from typing import List, Dict, Any


class GitHubPhishingDetector:
    """
    Class for detecting and analyzing phishing attacks using GitHub issues.
    Designed to run at regular intervals and update data incrementally.
    """

    def __init__(self, search_term: str, token: str = None):
        """
        Initializes the phishing detector.

        Args:
            search_term: Search term to identify compromised issues
            token: GitHub personal token (optional, but recommended to avoid rate limits)
        """
        self.search_term = search_term
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            self.headers["Authorization"] = f"token {token}"

        # Directory to store data
        self.data_dir = "data"
        os.makedirs(self.data_dir, exist_ok=True)

        # Files to store information
        self.issues_file = os.path.join(self.data_dir, "phishing_issues.csv")
        self.users_file = os.path.join(self.data_dir, "compromised_users.csv")
        self.stats_file = os.path.join(self.data_dir, "attack_stats.json")
        self.last_run_file = os.path.join(self.data_dir, "last_run_data.json")

        # Initialize files if they don't exist
        self._init_files()

        # Load data from the last processing
        self.last_run_data = self._load_last_run_data()

    def _init_files(self):
        """Initializes CSV files if they don't exist."""
        if not os.path.exists(self.issues_file):
            with open(self.issues_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "issue_id",
                        "repo",
                        "title",
                        "creator",
                        "created_at",
                        "url",
                        "processed_at",
                    ]
                )

        if not os.path.exists(self.users_file):
            with open(self.users_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "username",
                        "first_detected",
                        "repos_affected",
                        "issues_created",
                        "last_updated",
                    ]
                )

        if not os.path.exists(self.last_run_file):
            with open(self.last_run_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "last_issue_id": None,
                        "last_run_time": None,
                        "total_issues_processed": 0,
                    },
                    f,
                    indent=2,
                )

    def _load_last_run_data(self) -> Dict[str, Any]:
        """Loads data from the last execution."""
        if os.path.exists(self.last_run_file):
            with open(self.last_run_file, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    print("Error: Last run file is corrupted. Starting from scratch.")

        return {
            "last_issue_id": None,
            "last_run_time": None,
            "total_issues_processed": 0,
        }

    def _save_last_run_data(self, last_issue_id: int = None):
        """Saves data from the current execution."""
        self.last_run_data["last_issue_id"] = (
            last_issue_id if last_issue_id else self.last_run_data["last_issue_id"]
        )
        self.last_run_data["last_run_time"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        with open(self.last_run_file, "w", encoding="utf-8") as f:
            json.dump(self.last_run_data, f, indent=2)

    def search_issues(self, page: int = 1, per_page: int = 100) -> Dict[str, Any]:
        """
        Searches for issues on GitHub containing the search term.

        Args:
            page: Results page
            per_page: Number of results per page

        Returns:
            Dictionary with the results
        """
        url = f"https://api.github.com/search/issues"
        query = f"{self.search_term} is:issue"
        params = {
            "q": query,
            "per_page": per_page,
            "page": page,
            "sort": "created",
            "order": "desc",
        }

        response = requests.get(url, headers=self.headers, params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error searching for issues: {response.status_code}")
            print(response.text)
            return {"items": [], "total_count": 0}

    def process_issues(
        self, max_pages: int = 5, incremental: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Processes issues found in the search, optionally incrementally.

        Args:
            max_pages: Maximum number of pages to process
            incremental: If True, only processes new issues since the last execution

        Returns:
            List of processed issues
        """
        all_issues = []
        compromised_users = set()
        new_issues_count = 0
        newest_issue_id = None

        print(f"Starting {'incremental' if incremental else 'full'} processing...")

        if incremental and self.last_run_data["last_issue_id"]:
            print(
                f"Looking for issues more recent than ID: {self.last_run_data['last_issue_id']}"
            )

        for page in range(1, max_pages + 1):
            print(f"Processing page {page}...")
            results = self.search_issues(page=page)

            if not results["items"]:
                print("No more results found.")
                break

            # Save the most recent issue ID (only on the first page)
            if page == 1 and results["items"]:
                newest_issue_id = results["items"][0]["id"]
                print(f"Most recent issue found: ID {newest_issue_id}")

            # Process issues
            stop_processing = False
            for issue in results["items"]:
                # If we're in incremental mode, check if we've already processed this issue
                if incremental and self.last_run_data["last_issue_id"]:
                    if int(issue["id"]) <= int(self.last_run_data["last_issue_id"]):
                        print(
                            f"Reached already processed issue (ID: {issue['id']}). Stopping processing."
                        )
                        stop_processing = True
                        break

                # Extract relevant data
                issue_data = {
                    "issue_id": issue["id"],
                    "repo": issue["repository_url"].replace(
                        "https://api.github.com/repos/", ""
                    ),
                    "title": issue["title"],
                    "creator": issue["user"]["login"],
                    "created_at": issue["created_at"],
                    "url": issue["html_url"],
                    "processed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }

                all_issues.append(issue_data)
                compromised_users.add(issue["user"]["login"])

                # Save issue to CSV
                self._append_issue(issue_data)
                new_issues_count += 1

            # If we should stop processing, exit the page loop
            if stop_processing:
                break

            # Wait to avoid exceeding rate limits
            time.sleep(1)

        # Update the total count of processed issues
        self.last_run_data["total_issues_processed"] += new_issues_count

        # Update compromised users
        self._update_compromised_users(compromised_users)

        # Save statistics
        self._update_statistics()

        # Save data from this execution if we found new issues
        if newest_issue_id:
            self._save_last_run_data(newest_issue_id)

        print(f"Processing completed. {new_issues_count} new issues found.")
        return all_issues

    def _append_issue(self, issue_data: Dict[str, Any]):
        """Adds an issue to the CSV file if it doesn't already exist."""
        # Check if the issue already exists
        issue_exists = False
        if os.path.exists(self.issues_file) and os.path.getsize(self.issues_file) > 0:
            with open(self.issues_file, "r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 1 and str(row[0]) == str(issue_data["issue_id"]):
                        issue_exists = True
                        break

        # Only add if it doesn't exist
        if not issue_exists:
            with open(self.issues_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        issue_data["issue_id"],
                        issue_data["repo"],
                        issue_data["title"],
                        issue_data["creator"],
                        issue_data["created_at"],
                        issue_data["url"],
                        issue_data["processed_at"],
                    ]
                )

    def _update_compromised_users(self, new_users: set):
        """Updates the list of compromised users."""
        # Read existing users
        existing_users = {}
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if os.path.exists(self.users_file) and os.path.getsize(self.users_file) > 0:
            with open(self.users_file, "r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 5:
                        existing_users[row[0]] = {
                            "first_detected": row[1],
                            "repos_affected": int(row[2]),
                            "issues_created": int(row[3]),
                            "last_updated": row[4] if len(row) > 4 else current_time,
                        }

        # Count issues per user
        user_issues_count = {}
        user_repos = {}

        with open(self.issues_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                if len(row) >= 6:
                    username = row[3]
                    repo = row[1]

                    if username not in user_issues_count:
                        user_issues_count[username] = 0
                        user_repos[username] = set()

                    user_issues_count[username] += 1
                    user_repos[username].add(repo)

        # Update users file
        with open(self.users_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "username",
                    "first_detected",
                    "repos_affected",
                    "issues_created",
                    "last_updated",
                ]
            )

            # Combine existing and new users
            all_users = set(list(existing_users.keys()) + list(new_users))

            for username in all_users:
                # If it's a new user, use current date, otherwise keep the existing one
                first_detected = existing_users.get(username, {}).get(
                    "first_detected", current_time
                )

                # If the user is in the newly found ones, update the date
                last_updated = (
                    current_time
                    if username in new_users
                    else existing_users.get(username, {}).get(
                        "last_updated", current_time
                    )
                )

                repos_affected = len(user_repos.get(username, set()))
                issues_created = user_issues_count.get(username, 0)

                writer.writerow(
                    [
                        username,
                        first_detected,
                        repos_affected,
                        issues_created,
                        last_updated,
                    ]
                )

    def _update_statistics(self):
        """Updates attack statistics based on all collected data."""
        # Read all issues
        issues = []
        with open(self.issues_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                if len(row) >= 6:
                    issues.append(
                        {
                            "issue_id": row[0],
                            "repo": row[1],
                            "title": row[2],
                            "creator": row[3],
                            "created_at": row[4],
                            "url": row[5],
                        }
                    )

        # Collect information
        users = set()
        affected_repos = set()

        for issue in issues:
            users.add(issue["creator"])
            affected_repos.add(issue["repo"])

        # Get current date
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Create statistics
        stats = {
            "last_updated": current_time,
            "total_issues": len(issues),
            "compromised_users": len(users),
            "affected_repos": len(affected_repos),
            "users_list": list(users),
            "repos_list": list(affected_repos),
            "total_processed_since_start": self.last_run_data["total_issues_processed"],
        }

        # Add time statistics
        if issues:
            # Sort issues by creation date for temporal analysis
            sorted_issues = sorted(issues, key=lambda x: x["created_at"])
            stats["first_issue_date"] = sorted_issues[0]["created_at"]
            stats["latest_issue_date"] = sorted_issues[-1]["created_at"]

            # Count issues by day
            daily_counts = {}
            for issue in issues:
                date = issue["created_at"].split("T")[0]  # YYYY-MM-DD
                if date not in daily_counts:
                    daily_counts[date] = 0
                daily_counts[date] += 1

            stats["daily_counts"] = daily_counts

        # Save statistics
        with open(self.stats_file, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

    def get_statistics(self) -> Dict[str, Any]:
        """Gets current attack statistics."""
        if os.path.exists(self.stats_file):
            with open(self.stats_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def print_report(self):
        """Prints a report with current statistics."""
        stats = self.get_statistics()
        if not stats:
            print("No statistics available.")
            return

        print("\n" + "=" * 50)
        print(f"GITHUB PHISHING ATTACK REPORT")
        print("=" * 50)
        print(f"Last updated: {stats.get('last_updated', 'N/A')}")
        print(f"Total phishing issues: {stats.get('total_issues', 0)}")
        print(f"Compromised users: {stats.get('compromised_users', 0)}")
        print(f"Affected repositories: {stats.get('affected_repos', 0)}")
        print(
            f"Total processed since start: {stats.get('total_processed_since_start', 0)}"
        )

        if "first_issue_date" in stats and "latest_issue_date" in stats:
            print(f"First issue detected: {stats['first_issue_date']}")
            print(f"Latest issue detected: {stats['latest_issue_date']}")

        print("=" * 50)

        # Top 5 users with most issues
        users_issues = {}
        with open(self.users_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                if len(row) >= 4:
                    users_issues[row[0]] = int(row[3])

        top_users = sorted(users_issues.items(), key=lambda x: x[1], reverse=True)[:5]

        if top_users:
            print("\nTop 5 users with most issues:")
            for username, count in top_users:
                print(f"  - {username}: {count} issues")

        print("=" * 50 + "\n")

        # Incremental information
        print(f"Incremental processing status:")
        print(f"Last processed ID: {self.last_run_data.get('last_issue_id', 'None')}")
        print(f"Last execution: {self.last_run_data.get('last_run_time', 'Never')}")
        print("=" * 50 + "\n")


if __name__ == "__main__":
    # Process arguments
    incremental_mode = True  # By default, use incremental mode
    max_pages = 200  # Maximum pages to process

    # Check arguments
    if len(sys.argv) > 1:
        if "--full" in sys.argv:
            incremental_mode = False
            print("Full processing mode activated")

        if "--pages" in sys.argv:
            try:
                idx = sys.argv.index("--pages")
                if idx + 1 < len(sys.argv):
                    max_pages = int(sys.argv[idx + 1])
                    print(f"Processing maximum {max_pages} pages")
            except (ValueError, IndexError):
                pass

    # Search term
    search_term = "Ov23lit4gvZ7pVctYyZH"

    # Get token from environment variable
    github_token = os.environ.get("GITHUB_TOKEN")

    if github_token:
        print("GitHub token found in environment variables.")
        detector = GitHubPhishingDetector(search_term, token=github_token)
    else:
        print(
            "No GitHub token found in environment variables. Using standard rate limits."
        )
        detector = GitHubPhishingDetector(search_term)

    print(f"Searching for issues with term: {search_term}")
    detector.process_issues(max_pages=max_pages, incremental=incremental_mode)
    detector.print_report()
