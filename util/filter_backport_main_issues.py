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
from typing import Any, Dict, List, Optional

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

def get_backport_child_id(parent: Dict[str, Any], target: str) -> Optional[int]:
    children = parent.get('backport_subtasks', [])
    if not isinstance(children, list):
        return None
    
    version = '7.0.x' if target == '7' else '8.0.x'
    for child in children:
        if not isinstance(child, dict):
            continue
        subject = child.get('subject', '')
        if subject_has_backport(subject, version):
            child_id = child.get('id')
            if isinstance(child_id, int):
                return child_id
    return None


def main() -> int:
    args = parse_args()
    data = load_json(args.input)
    parents: List[Dict[str, Any]] = data.get('parent_issues', [])
    qualifying = []
    for parent in parents:
        if not isinstance(parent, dict):
            continue
        if qualifies(parent, args.target):
            parent_id = parent.get('id')
            child_id = get_backport_child_id(parent, args.target)
            pr_url = parent.get('last_suricata_pr')
            if parent_id is not None and child_id is not None and pr_url:
                qualifying.append((parent_id, child_id, pr_url))

    for parent_id, child_id, pr_url in qualifying:
        print(f"{parent_id} {child_id} {pr_url}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
