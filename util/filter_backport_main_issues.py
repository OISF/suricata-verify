#!/usr/bin/env python3
"""
Filter Redmine backport data to find parent issues that:
- Have status "Resolved"
- Have a "7.0.x backport" subtask
- Do NOT have a "8.0.x backport" subtask

Input JSON should match the output format from check_redmine_backport_subtasks.py.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

REDMINE_URL = 'https://redmine.openinfosecfoundation.org'
REDMINE_API_KEY = os.environ.get('REDMINE_API_KEY')
SURICATA_PR_PATTERN = re.compile(r"https://github\.com/OISF/suricata/pull/\d+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Filter backport_data.json for parent issues by backport target'
    )
    parser.add_argument(
        'input',
        nargs='?',
        default='backport_data.json',
        help='Path to backport_data.json (default: backport_data.json)'
    )
    parser.add_argument(
        '--target',
        choices=['7', '8'],
        default='7',
        help='Backport target version to filter (7 or 8). Default: 7'
    )
    return parser.parse_args()


def load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: input file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    
    if not isinstance(data, dict):
        print("Error: expected top-level JSON object", file=sys.stderr)
        sys.exit(2)
    
    if 'parent_issues' not in data or not isinstance(data['parent_issues'], list):
        print("Error: JSON missing 'parent_issues' list", file=sys.stderr)
        sys.exit(2)
    
    return data


def get_headers() -> Dict[str, str]:
    headers = {
        'Content-Type': 'application/json',
    }
    if REDMINE_API_KEY:
        headers['X-Redmine-API-Key'] = REDMINE_API_KEY
    return headers


def fetch_issue_journals(issue_id: int) -> Optional[List[Dict[str, Any]]]:
    base_url = f"{REDMINE_URL}/issues/{issue_id}.json"
    query = urllib.parse.urlencode({'include': 'journals'})
    url = f"{base_url}?{query}"
    request = urllib.request.Request(url, headers=get_headers())

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                print(f"Error fetching issue #{issue_id}: {response.status}", file=sys.stderr)
                return None
            payload = response.read().decode('utf-8')
            issue = json.loads(payload).get('issue', {})
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        print(f"Error fetching issue #{issue_id}: {exc}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"Error parsing JSON for issue #{issue_id}: {exc}", file=sys.stderr)
        return None

    journals = issue.get('journals', [])
    if isinstance(journals, list):
        return journals
    return None


def extract_last_suricata_pr_url(journals: List[Dict[str, Any]]) -> Optional[str]:
    last_url = None
    for journal in journals:
        notes = journal.get('notes', '')
        if not notes:
            continue
        matches = SURICATA_PR_PATTERN.findall(notes)
        if matches:
            last_url = matches[-1]
    return last_url


def subject_has_backport(subject: str, version: str) -> bool:
    if not subject:
        return False
    return f"{version} backport" in subject.lower()


def qualifies(parent: Dict[str, Any], target: str) -> bool:
    status = (parent.get('status') or '').strip().lower()
    if status != 'resolved':
        return False

    children = parent.get('backport_subtasks', [])
    if not isinstance(children, list):
        return False

    needs_7 = any(
        subject_has_backport(child.get('subject', ''), '7.0.x')
        for child in children
        if isinstance(child, dict)
    )
    needs_8 = any(
        subject_has_backport(child.get('subject', ''), '8.0.x')
        for child in children
        if isinstance(child, dict)
    )

    if target == '7':
        return needs_7 and not needs_8
    return needs_8


def main() -> int:
    args = parse_args()
    data = load_json(args.input)
    parents: List[Dict[str, Any]] = data.get('parent_issues', [])
    
    qualifying_ids = []
    for parent in parents:
        if not isinstance(parent, dict):
            continue
        if qualifies(parent, args.target):
            parent_id = parent.get('id')
            if parent_id is not None:
                qualifying_ids.append(parent_id)
    
    if not REDMINE_API_KEY:
        print("Warning: REDMINE_API_KEY environment variable not set.", file=sys.stderr)
        print("This may limit access to private issues.", file=sys.stderr)

    for parent_id in qualifying_ids:
        journals = fetch_issue_journals(parent_id)
        if journals is None:
            continue
        pr_url = extract_last_suricata_pr_url(journals)
        if pr_url:
            print(f"{parent_id} {pr_url}")
        else:
            print(f"No Suricata PR URL found for issue #{parent_id}", file=sys.stderr)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
