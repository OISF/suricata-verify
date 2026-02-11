#!/usr/bin/env python3
#
# Script to automate creation of backport PRs.
# Reads filtered Redmine issues, resolves PR commits, creates backport branch,
# and cherry-picks commits.

import sys
import os
import argparse
import subprocess
import re
import json
import urllib.error
import urllib.parse
# urllib.request only for Redmine, not GitHub
import urllib.request

REDMINE_URL = "https://redmine.openinfosecfoundation.org"
REDMINE_API_KEY = os.environ.get("REDMINE_API_KEY")
REMOTE_GIT = "catena"
GITHUB_USER = "catenacyber"

class BackportError(Exception):
    """Raised when backport workflow fails."""
    pass

def run_command(cmd, dry_run=False, capture=False):
    """Execute a shell command, optionally in dry-run mode."""
    if dry_run:
        print(f"[DRY-RUN] {cmd}")
        return ""
    else:
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise BackportError(f"Command failed: {cmd}\n{result.stderr}")
            return result.stdout.strip()
        else:
            print(f"$ {cmd}")
            result = subprocess.run(cmd, shell=True)
            if result.returncode != 0:
                raise BackportError(f"Command failed with exit code {result.returncode}")
            return ""

def resolve_pr_to_commits(pr_url, parent_id, dry_run=False, from_staging=False):
    """Extract PR number and return commits in PR not in main.
    
    Strategy:
    1. List commits present in pr/XXXXX but not in main
    2. Return those commit hashes in chronological order
    """
    match = re.search(r'/pull/(\d+)$', pr_url)
    if not match:
        raise BackportError(f"Invalid PR URL: {pr_url}")
    pr_number = match.group(1)
    pr_branch = f"pr/{pr_number}"

    # Validate PR is linked to Redmine ticket
    # Try to extract Redmine ticket from PR body/comments
    # Use gh CLI to fetch PR body and comments
    try:
        pr_json = run_command(f'gh pr view {pr_number} --repo OISF/suricata --json body', dry_run=False, capture=True)
        pr_data = json.loads(pr_json)
        pr_body = pr_data.get("body", "")
    except Exception as exc:
        raise BackportError(f"Could not fetch GitHub PR #{pr_number} via gh: {exc}")
    # Accept ticket links like https://redmine.openinfosecfoundation.org/issues/XXXXX
    redmine_ticket_pattern = re.compile(r'https://redmine\.openinfosecfoundation\.org/issues/(\d+)')
    linked_tickets = set(redmine_ticket_pattern.findall(pr_body))
    # Fetch PR comments for more links
    try:
        # lol run only one gh pr view command for both body and comments
        comments_json = run_command(f'gh pr view {pr_number} --repo OISF/suricata --json comments', dry_run=False, capture=True)
        comments_data = json.loads(comments_json)
        for comment in comments_data.get("comments", []):
            body = comment.get("body", "")
            linked_tickets.update(redmine_ticket_pattern.findall(body))
    except Exception:
        pass
    # Validate against parent/child ticket
    if parent_id not in linked_tickets:
        if from_staging:
            return []
    # ...existing code...
    
    # lol logic should be to first check if this is staging PR with pr_title.startswith("next/")
    # else handle this case same as a PR whose commits hashes are in main
    # Get commit hashes and subjects from the PR branch that are not in main
    cmd = f'git log origin/main..{pr_branch} --format=%H:%s --reverse'
    pr_commit_hashes = run_command(cmd, dry_run=False, capture=True)

    if not pr_commit_hashes:
        # Fallback: check if PR is a next/staging PR
        try:
            pr_json = run_command(f'gh pr view {pr_number} --repo OISF/suricata --json title,body', dry_run=False, capture=True)
            pr_data = json.loads(pr_json)
            pr_title = pr_data.get("title", "")
            pr_body = pr_data.get("body", "")
        except Exception as exc:
            raise BackportError(f"Could not fetch GitHub PR #{pr_number} via gh: {exc}")
        if pr_title.startswith("next/"):
            # Look for PR URLs in the body (first comment)
            pr_urls = re.findall(r'- #(\d+)', pr_body)
            all_hashes = []
            print(f"Trying to find sub PRs in staging : {pr_urls}")
            for sub_pr in pr_urls:
                sub_url = f"https://github.com/OISF/suricata/pull/{sub_pr}"
                try:
                    hashes = resolve_pr_to_commits(sub_url, parent_id, dry_run=dry_run,from_staging=True)
                    if len(hashes) > 0:
                        print(f"Found some in : {sub_url}")
                    all_hashes.extend(hashes)
                except Exception as exc:
                    print(f"Warning: Could not resolve sub-PR {sub_url}: {exc}", file=sys.stderr)
            if all_hashes:
                return all_hashes
            else:
                raise BackportError(f"No commits found for next/staging PR {pr_url} or its listed PRs {pr_body}.")
        else:
            # lol 10 is arbitrary
            cmd = f'git log -10 {pr_branch} --format="%H:%s|%d"'
            pr_commit_hashes = run_command(cmd, dry_run=False, capture=True)
            print(f"Inspecting first hashes {pr_commit_hashes}")

    commit_hashes = []
    for line in pr_commit_hashes.split('\n'):
        if not line.strip():
            continue
        if ':' not in line:
            continue
        commit_hash, subject = line.split(':', 1)
        subject_prs = re.findall(r'\bpr/(\d+)\b', subject)
        if subject_prs and pr_number not in subject_prs:
            break
        # lol we should know at this point if we have main hashes or if we should look for them
        title = subject.split('|')[0]
        print(f"Getting main commit for {title}")
        # lol this does not work if commits have the same title
        cmd = f'git log -1 origin/main --grep="{title}" --format="%H"'
        main_commit_hash = run_command(cmd, dry_run=False, capture=True)
        commit_hashes.append(main_commit_hash.strip())
    if not commit_hashes:
        raise BackportError(f"No commits found in {pr_branch} that are not already in main")
    
    return commit_hashes

# lol maybe we could import the script functionality instead of spawning a new process
def get_filter_script_path():
    """Locate the filter_backport_main_issues.py script."""
    # Assume it's in ../suricata-verify/util relative to suricata repo
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)  # Go up from scripts/ to repo root
    parent_dir = os.path.dirname(repo_root)  # Go up from suricata/ to prod/
    filter_script = os.path.join(parent_dir, "suricata-verify", "util", "filter_backport_main_issues.py")
    
    if not os.path.exists(filter_script):
        raise BackportError(f"Filter script not found: {filter_script}")
    
    return filter_script

def run_filter_script(target, json_file, dry_run=False):
    """Run filter_backport_main_issues.py and return list of (parent_id, child_id, pr_url) tuples."""
    filter_script = get_filter_script_path()
    cmd = f"python3 {filter_script} {json_file} --target {target}"
    
    output = run_command(cmd, dry_run=False, capture=True)
    
    results = []
    for line in output.strip().split('\n'):
        if not line:
            continue
        parts = line.split()
        if len(parts) == 3:
            parent_id, child_id, pr_url = parts
            results.append((parent_id, child_id, pr_url))
    
    return results

def create_backport_branch(target, issue_ids, dry_run=False):
    """Create a new backport branch with naming convention backport{7|8}-{id1}-{id2}-v1."""
    # lol maybe create v2 if v1 already exists
    branch_name = f"backport{target}-{'-'.join(issue_ids)}-v1"
    cmd = f"git checkout -b {branch_name}"
    run_command(cmd, dry_run=dry_run)
    return branch_name

def cherry_pick_commit(commit_hash, dry_run=False):
    if dry_run:
        print(f"[DRY-RUN] git cherry-pick -x {commit_hash}")
        return "clean"
    
    print(f"$ git cherry-pick -x {commit_hash}")
    result = subprocess.run(f"git cherry-pick -x {commit_hash}", shell=True)
    if result.returncode == 0:
        return "clean"
    # lol specific handling if commit is empty (means was already merged and ticket was not closed)
    
    head_check = subprocess.run("git rev-parse --verify CHERRY_PICK_HEAD", shell=True, capture_output=True, text=True)
    if head_check.returncode == 0:
        print("Cherry-pick conflict detected. Resolve conflicts, then stage changes.")
        input("Press Enter to continue with 'git cherry-pick --continue'...")
        continue_result = subprocess.run("git cherry-pick --continue", shell=True)
        if continue_result.returncode != 0:
            raise BackportError("Cherry-pick continue failed. Resolve conflicts and run 'git cherry-pick --continue' manually.")
        return "unclean"
    
    raise BackportError("Cherry-pick failed. Run 'git status' for details.")

def get_redmine_headers():
    headers = {
        "Content-Type": "application/json",
    }
    if REDMINE_API_KEY:
        headers["X-Redmine-API-Key"] = REDMINE_API_KEY
    return headers

def get_redmine_status_id(name):
    url = f"{REDMINE_URL}/issue_statuses.json"
    request = urllib.request.Request(url, headers=get_redmine_headers())
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read().decode("utf-8")
            statuses = json.loads(payload).get("issue_statuses", [])
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        raise BackportError(f"Failed to fetch Redmine statuses: {exc}")
    for status in statuses:
        if status.get("name") == name:
            return status.get("id")
    raise BackportError(f"Redmine status not found: {name}")

def update_redmine_issue(issue_id, status_id, note, dry_run=False):
    url = f"{REDMINE_URL}/issues/{issue_id}.json"
    payload = json.dumps({"issue": {"status_id": status_id, "notes": note}}).encode("utf-8")
    if dry_run:
        print(f"[DRY-RUN] PUT {url} status_id={status_id} note={note}")
        return
    # lol maybe add some logging
    request = urllib.request.Request(url, data=payload, headers=get_redmine_headers(), method="PUT")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status not in (200, 204):
                raise BackportError(f"Redmine update failed for issue #{issue_id}: {response.status}")
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise BackportError(f"Redmine update failed for issue #{issue_id}: {exc}")

def get_commit_subject(commit_hash, dry_run=False):
    return run_command(f"git log -n 1 --format=%s {commit_hash}", dry_run=False, capture=True)

def build_pr_title(target, issue_ids):
    return f"Backport{target} {' '.join(issue_ids)} v1"

def build_pr_body(child_ids, pr_entries):
    lines = []
    lines.append("Link to ticket: https://redmine.openinfosecfoundation.org/issues/")
    for child_id in child_ids:
        lines.append(f"https://redmine.openinfosecfoundation.org/issues/{child_id}")
    lines.append("")
    lines.append("Describe changes:")
    for pr_url, status, nb_hashes in pr_entries:
        plural = "s" if nb_hashes > 1 else ""
        lines.append(f"- backport of {pr_url} {status} cherry-pick{plural}")
    return "\n".join(lines)

def create_github_pr(title, body, base_branch, head_branch, dry_run=False):
    if dry_run:
        print("[DRY-RUN] gh pr create --base {} --head {} --title <title> --body <body>".format(base_branch, head_branch))
        return None
    
    gh_check = subprocess.run("command -v gh", shell=True, capture_output=True, text=True)
    if gh_check.returncode != 0:
        compare_url = f"https://github.com/OISF/suricata/compare/{base_branch}...{head_branch}?expand=1"
        print("GitHub CLI (gh) not found. Create the PR manually using:")
        print(compare_url)
        print("\nTitle:")
        print(title)
        print("\nBody:")
        print(body)
        pr_url = input("\nEnter the created PR URL (or leave blank to skip Redmine update): ").strip()
        return pr_url or None
    
    result = subprocess.run(
        ["gh", "pr", "create", "--base", base_branch, "--head", "{}:".format(GITHUB_USER)+head_branch, "--title", title, "--body", body],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise BackportError("Failed to create GitHub PR with gh:", result.stderr)
    return result.stdout.strip() or None

def prompt_commit_selection(commit_hashes, dry_run=False):
    if not commit_hashes:
        return [], False
    
    subjects = [get_commit_subject(h, dry_run=dry_run) for h in commit_hashes]
    print("  Review commits to cherry-pick:")
    for i, (commit_hash, subject) in enumerate(zip(commit_hashes, subjects), 1):
        print(f"    {i}. {commit_hash[:8]} {subject}")
    
    while True:
        selection = input("Enter commit numbers to remove (comma-separated), or press Enter to keep all: ").strip()
        if not selection:
            return commit_hashes, False
        
        try:
            remove_ids = set(int(x.strip()) for x in selection.split(',') if x.strip())
        except ValueError:
            print("Invalid input. Use numbers like: 2,3")
            continue
        
        if any(i < 1 or i > len(commit_hashes) for i in remove_ids):
            print("Invalid selection. Choose numbers from the list above.")
            continue
        
        filtered = [h for i, h in enumerate(commit_hashes, 1) if i not in remove_ids]
        return filtered, True

def main():
    parser = argparse.ArgumentParser(
        description="Automate creation of backport PRs from Redmine issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # Create backport for 7.0.x
  %(prog)s --target 7 backport_data.json

  # Dry-run for 8.0.x
  %(prog)s --target 8 backport_data.json --dry
        """
    )
    parser.add_argument('json_file', 
                        help='JSON file from check_redmine_backport_subtasks.py')
    parser.add_argument('--target', type=int, choices=[7, 8], required=True,
                        help='Target version: 7 for 7.0.x, 8 for 8.0.x')
    parser.add_argument('--dry', '-n', action='store_true',
                        help='Print commands without executing')
    
    args = parser.parse_args()
    
    try:
        # Step 1: Run filter script to get qualifying issues
        print(f"Filtering issues for {args.target}.0.x backport...")
        issues = run_filter_script(args.target, args.json_file, dry_run=args.dry)
        
        if not issues:
            print("No issues found requiring backport.")
            return 0
        
        print(f"Found {len(issues)} issue(s) requiring backport:")
        for parent_id, child_id, pr_url in issues:
            print(f"  Issue #{parent_id} (child #{child_id}): {pr_url}")
        print()
        # lol maybe add an interactive prompt to remove some tickets
        
        # Step 2: Checkout target branch
        target_branch = f"main-{args.target}.0.x"
        print(f"Checking out {target_branch}...")
        run_command(f"git checkout {target_branch}", dry_run=args.dry)
        
        # Update the branch
        if not args.dry:
            print("Pulling latest changes...")
            run_command(f"git pull", dry_run=args.dry)
        
        # Step 3: Create backport branch
        issue_ids = [parent_id for parent_id, _, _ in issues]
        child_ids = [child_id for _, child_id, _ in issues]
        branch_name = create_backport_branch(args.target, issue_ids, dry_run=args.dry)
        print(f"Created branch: {branch_name}\n")
        
        # Step 4: Resolve PR URLs to commit hashes and cherry-pick
        print("Resolving PRs to commits and cherry-picking...")
        total_commits = 0
        pr_entries = []
        for parent_id, child_id, pr_url in issues:
            print(f"\nProcessing Issue #{parent_id} (child #{child_id}) ({pr_url}):")
            commit_hashes = resolve_pr_to_commits(pr_url, parent_id, dry_run=args.dry)
            print(f"  Found {len(commit_hashes)} commit(s)")
            commit_hashes, removed_any = prompt_commit_selection(commit_hashes, dry_run=args.dry)
            if not commit_hashes:
                print("  No commits selected; skipping this issue.")
                continue
            print(f"  After validation: {len(commit_hashes)} commit(s)")
            
            # Cherry-pick all commits with -x to add reference
            status = "clean"
            for i, commit_hash in enumerate(commit_hashes, 1):
                print(f"  [{i}/{len(commit_hashes)}] Cherry-picking {commit_hash[:8]}...")
                result = cherry_pick_commit(commit_hash, dry_run=args.dry)
                if result == "unclean":
                    status = "unclean"
            if removed_any:
                status = "unclean_incomplete" if status == "unclean" else "incomplete"
            
            total_commits += len(commit_hashes)
            pr_entries.append((pr_url, status, len(commit_hashes)))
        
        print("\n" + "="*60)
        print("Backport branch created successfully!")
        print(f"Branch: {branch_name}")
        print(f"Issues processed: {len(issues)}")
        print(f"Commits cherry-picked: {total_commits}")
        print("="*60)
        
        pr_title = build_pr_title(args.target, issue_ids)
        pr_body = build_pr_body(child_ids, pr_entries)
        
        if not args.dry:
            print("\nNext steps:")
            print(f"  1. Review the changes: git log {target_branch}..{branch_name}")
            print(f"  2. Push the branch: git push {REMOTE_GIT}")
            print("\nProposed PR:")
            print(f"  Title: {pr_title}")
            print("  Body:")
            print(pr_body)
            create_pr = input("\nCreate the GitHub PR now? (y/N): ").strip().lower()
            if create_pr == "y":
                run_command(f"git push {REMOTE_GIT}", dry_run=args.dry)
                pr_url = create_github_pr(pr_title, pr_body, target_branch, branch_name, dry_run=args.dry)
                if pr_url:
                    status_id = 7 # get_redmine_status_id("In Review")
                    for child_id in child_ids:
                        update_redmine_issue(child_id, status_id, f"Backport PR: {pr_url}", dry_run=args.dry)
                else:
                    print("Skipping Redmine update (no PR URL available).")
        else:
            print("\n[DRY-RUN] Proposed PR:")
            print(f"  Title: {pr_title}")
            print("  Body:")
            print(pr_body)
        
        return 0
        
    except BackportError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
