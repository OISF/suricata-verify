#!/usr/bin/env python3
"""
Script to find open Redmine issues that have subtasks with "backport" in the title.
Displays the status of the main issue and its subtasks.
"""

import requests
import sys
import os
import json
import argparse
from typing import Optional

# Configuration
REDMINE_URL = 'https://redmine.openinfosecfoundation.org'
REDMINE_API_KEY = os.environ.get('REDMINE_API_KEY')
BACKPORT_KEYWORD = 'backport'

def get_headers():
    """Get headers for Redmine API requests."""
    headers = {
        'Content-Type': 'application/json',
    }
    if REDMINE_API_KEY:
        headers['X-Redmine-API-Key'] = REDMINE_API_KEY
    return headers

def get_open_backport_issues(limit: int = 100) -> list:
    """Fetch all open issues with 'backport' in the title."""
    url = f'{REDMINE_URL}/issues.json'
    all_issues = []
    offset = 0
    
    while True:
        params = {
            'status_id': 'open',
            'limit': limit,
            'offset': offset,
            'subject': '~backport',
        }
        
        response = requests.get(url, headers=get_headers(), params=params)
        
        if response.status_code != 200:
            print(f"Error fetching issues: {response.status_code}", file=sys.stderr)
            print(response.text, file=sys.stderr)
            sys.exit(1)
        
        data = response.json()
        issues = data.get('issues', [])
        
        if not issues:
            break
        
        # Filter for issues with backport in the subject
        for issue in issues:
            if BACKPORT_KEYWORD in issue.get('subject', '').lower():
                all_issues.append(issue)
        
        # Check if we've fetched all issues
        total = data.get('total_count', 0)
        if offset + limit >= total:
            break
        print("Fetching issues : %d / %d" % (offset + limit, total))

        offset += limit
    
    return all_issues

def get_issue_details(issue_id: int) -> Optional[dict]:
    """Fetch detailed information for a specific issue."""
    url = f'{REDMINE_URL}/issues/{issue_id}.json'
    
    response = requests.get(url, headers=get_headers())
    
    if response.status_code != 200:
        print(f"Error fetching issue #{issue_id}: {response.status_code}", file=sys.stderr)
        return None
    
    return response.json().get('issue')

def main():
    """Main function to find backport issues and group them by parent issue."""
    parser = argparse.ArgumentParser(
        description='Find open Redmine issues with backport subtasks'
    )
    parser.add_argument(
        '-j', '--json',
        metavar='FILE',
        help='Write results as JSON to FILE for later processing'
    )
    args = parser.parse_args()
    
    if not REDMINE_API_KEY:
        print("Warning: REDMINE_API_KEY environment variable not set.", file=sys.stderr)
        print("This may limit access to private issues.", file=sys.stderr)
        print("Set REDMINE_API_KEY to use API authentication.\n", file=sys.stderr)
    
    print("Fetching open issues with 'backport' in the title from Redmine...")
    
    backport_issues = get_open_backport_issues()
    
    print(f"Found {len(backport_issues)} open backport issue(s).\n")
    
    # Group backport issues by parent
    issues_by_parent = {}
    standalone_issues = []
    
    for issue in backport_issues:
        parent_id = issue.get('parent', {}).get('id')
        
        if parent_id:
            if parent_id not in issues_by_parent:
                issues_by_parent[parent_id] = {
                    'parent': None,
                    'children': []
                }
            issues_by_parent[parent_id]['children'].append(issue)
        else:
            standalone_issues.append(issue)
    
    # Fetch parent issue details for each group
    for parent_id in issues_by_parent:
        parent_issue = get_issue_details(parent_id)
        if parent_issue:
            issues_by_parent[parent_id]['parent'] = parent_issue
    
    # Write JSON output to file if requested
    if args.json:
        try:
            with open(args.json, 'w') as f:
                result = {
                    'parent_issues': [],
                    'standalone_issues': []
                }
                
                # Add parent issues and their children
                for parent_id in sorted(issues_by_parent.keys()):
                    group = issues_by_parent[parent_id]
                    parent_issue = group['parent']
                    children = group['children']
                    
                    parent_entry = {
                        'id': parent_id,
                        'subject': parent_issue['subject'] if parent_issue else None,
                        'status': parent_issue['status']['name'] if parent_issue else None,
                        'url': f"{REDMINE_URL}/issues/{parent_id}",
                        'backport_subtasks': []
                    }
                    
                    for child in children:
                        child_entry = {
                            'id': child['id'],
                            'subject': child['subject'],
                            'status': child['status']['name'],
                            'url': f"{REDMINE_URL}/issues/{child['id']}"
                        }
                        parent_entry['backport_subtasks'].append(child_entry)
                    
                    result['parent_issues'].append(parent_entry)
                
                # Add standalone issues
                for issue in standalone_issues:
                    standalone_entry = {
                        'id': issue['id'],
                        'subject': issue['subject'],
                        'status': issue['status']['name'],
                        'url': f"{REDMINE_URL}/issues/{issue['id']}"
                    }
                    result['standalone_issues'].append(standalone_entry)
                
                json.dump(result, f, indent=2)
            print(f"JSON output written to {args.json}\n")
        except IOError as e:
            print(f"Error writing JSON to {args.json}: {e}", file=sys.stderr)
            return 1
    
    print("="*80)
    print("BACKPORT ISSUES GROUPED BY PARENT ISSUE")
    print("="*80)
    
    if issues_by_parent:
        print(f"\nFound {len(issues_by_parent)} parent issue(s) with backport subtask(s):\n")
        
        for parent_id in sorted(issues_by_parent.keys()):
            group = issues_by_parent[parent_id]
            parent_issue = group['parent']
            children = group['children']
            
            if parent_issue:
                parent_subject = parent_issue['subject']
                parent_status = parent_issue['status']['name']
                parent_url = f"{REDMINE_URL}/issues/{parent_id}"
                
                print(f"Parent Issue #{parent_id}: {parent_subject}")
                print(f"  Status: {parent_status}")
                print(f"  URL: {parent_url}")
                print(f"  Backport subtasks ({len(children)}):")
                
                for child in children:
                    child_id = child['id']
                    child_subject = child['subject']
                    child_status = child['status']['name']
                    child_url = f"{REDMINE_URL}/issues/{child_id}"
                    
                    print(f"    • #{child_id}: {child_subject}")
                    print(f"      Status: {child_status}")
                    print(f"      URL: {child_url}")
                
                print()
            else:
                print(f"Parent Issue #{parent_id} (details could not be fetched)")
                print(f"  Backport subtasks ({len(children)}):")
                for child in children:
                    child_id = child['id']
                    child_subject = child['subject']
                    child_status = child['status']['name']
                    child_url = f"{REDMINE_URL}/issues/{child_id}"
                    
                    print(f"    • #{child_id}: {child_subject}")
                    print(f"      Status: {child_status}")
                    print(f"      URL: {child_url}")
                print()
    
    if standalone_issues:
        print("\n" + "="*80)
        print("STANDALONE BACKPORT ISSUES (No parent issue)")
        print("="*80 + "\n")
        
        print(f"Found {len(standalone_issues)} standalone backport issue(s):\n")
        
        for issue in standalone_issues:
            issue_id = issue['id']
            issue_subject = issue['subject']
            issue_status = issue['status']['name']
            issue_url = f"{REDMINE_URL}/issues/{issue_id}"
            
            print(f"Backport Issue #{issue_id}: {issue_subject}")
            print(f"  Status: {issue_status}")
            print(f"  URL: {issue_url}")
            print()
    
    total_found = len(issues_by_parent) + len(standalone_issues)
    if not total_found:
        print("\nNo open issues with 'backport' in the title found.")
    
    return 0 if total_found > 0 else 1

if __name__ == '__main__':
    sys.exit(main())
