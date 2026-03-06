#!/usr/bin/env python3
"""
List open PRs in suricata-verify labeled "requires suricata pr"
that are NOT referenced by any open PR in the suricata repository.

Uses the GitHub CLI (gh).
"""

import json
import re
import subprocess
import sys
from collections import defaultdict

VERIFY_REPO_OWNER = "OISF"
VERIFY_REPO_NAME = "suricata-verify"
SURICATA_REPO_OWNER = "OISF"
SURICATA_REPO_NAME = "suricata"
REQUIRED_LABEL = "requires suricata pr"


def run_gh_command(args):
    """Run a gh CLI command and return stdout."""
    try:
        result = subprocess.run(
            ["gh"] + args,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as error:
        print("Error running gh command:", file=sys.stderr)
        print(error.stderr, file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: 'gh' CLI tool not found. Please install it:", file=sys.stderr)
        print("  https://cli.github.com/", file=sys.stderr)
        sys.exit(1)


def get_open_verify_prs_with_label():
    """Fetch open PRs from suricata-verify with the required label."""
    output = run_gh_command(
        [
            "pr",
            "list",
            "--repo",
            f"{VERIFY_REPO_OWNER}/{VERIFY_REPO_NAME}",
            "--state",
            "open",
            "--label",
            REQUIRED_LABEL,
            "--json",
            "number,title,url,author,labels,body",
            "--limit",
            "1000",
        ]
    )
    return json.loads(output)


def get_open_suricata_prs():
    """Fetch open PRs from suricata repo."""
    output = run_gh_command(
        [
            "pr",
            "list",
            "--repo",
            f"{SURICATA_REPO_OWNER}/{SURICATA_REPO_NAME}",
            "--state",
            "open",
            "--json",
            "number,title,url,author,body",
            "--limit",
            "1000",
        ]
    )
    return json.loads(output)


def build_verify_mentions_index(suricata_prs):
    """Return mapping of verify PR numbers -> list of suricata PRs that mention them."""
    patterns = re.compile(
        r"(?:github\.com/)?(?:OISF/)?suricata-verify/pull/(\d+)"
        r"|(?:OISF/)?suricata-verify#(\d+)",
        re.IGNORECASE,
    )

    mentions = defaultdict(list)

    for pr in suricata_prs:
        text = f"{pr.get('title', '')}\n{pr.get('body', '') or ''}"
        for match in patterns.finditer(text):
            number = match.group(1) or match.group(2)
            if number:
                mentions[int(number)].append(pr)

    return mentions


def main():
    print(
        f"Fetching open PRs labeled '{REQUIRED_LABEL}' from "
        f"{VERIFY_REPO_OWNER}/{VERIFY_REPO_NAME}..."
    )
    verify_prs = get_open_verify_prs_with_label()

    print(
        f"Fetching open PRs from {SURICATA_REPO_OWNER}/{SURICATA_REPO_NAME}..."
    )
    suricata_prs = get_open_suricata_prs()

    if not verify_prs:
        print("No open PRs with the required label.")
        return 0

    mentions_index = build_verify_mentions_index(suricata_prs)

    missing_references = []

    print("\nChecking references...")
    for pr in verify_prs:
        pr_number = pr["number"]
        pr_title = pr["title"]
        pr_url = pr["url"]

        if pr_number in mentions_index:
            print(f"PR #{pr_number}: referenced")
            continue

        print(f"PR #{pr_number}: NOT referenced")
        missing_references.append(
            {
                "number": pr_number,
                "title": pr_title,
                "url": pr_url,
                "author": pr["author"]["login"],
            }
        )

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    if missing_references:
        print(
            f"\nFound {len(missing_references)} PR(s) with label "
            f"'{REQUIRED_LABEL}' that are NOT referenced by any open "
            f"PR in {SURICATA_REPO_OWNER}/{SURICATA_REPO_NAME}:\n"
        )
        for pr in missing_references:
            print(f"  PR #{pr['number']}: {pr['title']}")
            print(f"    Author: {pr['author']}")
            print(f"    URL: {pr['url']}")
            print()
        return 1

    print("\nAll labeled PRs are referenced by an open suricata PR.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
