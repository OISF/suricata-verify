#!/usr/bin/env python3
"""
Script to list open PRs that need a rebase but don't have the "needs rebase" label.
Uses the GitHub CLI (gh) tool.
"""

import subprocess
import sys
import json
import time

# Configuration
REPO_OWNER = 'OISF'
REPO_NAME = 'suricata-verify'
NEEDS_REBASE_LABEL = 'needs rebase'

def run_gh_command(args):
    """Run a gh CLI command and return the output."""
    try:
        result = subprocess.run(
            ['gh'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running gh command: {e}", file=sys.stderr)
        print(f"stderr: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: 'gh' CLI tool not found. Please install it first:", file=sys.stderr)
        print("  https://cli.github.com/", file=sys.stderr)
        sys.exit(1)

def get_open_prs():
    """Fetch all open pull requests with mergeable status using gh CLI."""
    output = run_gh_command([
        'pr', 'list',
        '--repo', f'{REPO_OWNER}/{REPO_NAME}',
        '--state', 'open',
        '--json', 'number,title,url,author,labels,mergeable,mergeStateStatus',
        '--limit', '1000'
    ])
    
    return json.loads(output)

def needs_rebase(pr):
    """Check if a PR needs a rebase by checking its mergeable status.
    
    Returns:
        True: PR needs rebase (has conflicts)
        False: PR does not need rebase
        None: Status is unknown (GitHub still computing)
    """
    # mergeable can be: MERGEABLE, CONFLICTING, UNKNOWN
    # mergeStateStatus can be: DIRTY, UNSTABLE, BLOCKED, BEHIND, CLEAN, DRAFT, etc.
    
    mergeable = pr.get('mergeable', '').upper()
    merge_state = pr.get('mergeStateStatus', '').upper()
    
    # If GitHub hasn't computed it yet, return None to indicate unknown status
    if mergeable == 'UNKNOWN':
        return None
    
    # Return True if there are actual conflicts
    return mergeable == 'CONFLICTING' or merge_state == 'DIRTY'

def has_needs_rebase_label(pr):
    """Check if PR has the 'needs rebase' label."""
    labels = [label['name'].lower() for label in pr.get('labels', [])]
    return NEEDS_REBASE_LABEL.lower() in labels

def main():
    """Main function to find PRs that need rebase but don't have the label."""
    print(f"Fetching open PRs for {REPO_OWNER}/{REPO_NAME}...")
    prs = get_open_prs()
    print(f"Found {len(prs)} open PRs.\n")
    
    print("Checking rebase status for each PR...")
    prs_needing_label = []
    prs_with_unknown_status = []
    
    for i, pr in enumerate(prs, 1):
        pr_number = pr['number']
        pr_title = pr['title']
        pr_url = pr['url']
        
        print(f"[{i}/{len(prs)}] Checking PR #{pr_number}...", end=' ')
        
        has_label = has_needs_rebase_label(pr)
        
        if has_label:
            print("already labeled")
            continue
        
        rebase_status = needs_rebase(pr)
        
        if rebase_status is None:
            print("status unknown (will retry)")
            prs_with_unknown_status.append(pr)
        elif rebase_status:
            print("NEEDS REBASE!")
            prs_needing_label.append({
                'number': pr_number,
                'title': pr_title,
                'url': pr_url,
                'author': pr['author']['login']
            })
        else:
            print("OK")
    
    # Retry PRs with unknown status after a short delay
    if prs_with_unknown_status:
        print(f"\n{len(prs_with_unknown_status)} PR(s) had unknown status. Waiting 3 seconds and retrying...")
        time.sleep(3)
        
        # Fetch fresh data for unknown PRs
        for pr in prs_with_unknown_status:
            pr_number = pr['number']
            pr_title = pr['title']
            pr_url = pr['url']
            
            print(f"Retrying PR #{pr_number}...", end=' ')
            
            # Fetch updated status
            output = run_gh_command([
                'pr', 'view', str(pr_number),
                '--repo', f'{REPO_OWNER}/{REPO_NAME}',
                '--json', 'mergeable,mergeStateStatus'
            ])
            updated_pr = json.loads(output)
            rebase_status = needs_rebase(updated_pr)
            
            if rebase_status is None:
                print("still unknown (skipping)")
            elif rebase_status:
                print("NEEDS REBASE!")
                prs_needing_label.append({
                    'number': pr_number,
                    'title': pr_title,
                    'url': pr_url,
                    'author': pr['author']['login']
                })
            else:
                print("OK")
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    if prs_needing_label:
        print(f"\nFound {len(prs_needing_label)} PR(s) that need rebase but don't have the '{NEEDS_REBASE_LABEL}' label:\n")
        for pr in prs_needing_label:
            print(f"  PR #{pr['number']}: {pr['title']}")
            print(f"    Author: {pr['author']}")
            print(f"    URL: {pr['url']}")
            print()
    else:
        print(f"\nAll PRs are properly labeled! No PRs need the '{NEEDS_REBASE_LABEL}' label.")
    
    return 0 if not prs_needing_label else 1

if __name__ == '__main__':
    sys.exit(main())
