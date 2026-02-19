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
    """Extract PR number and return commits in PR not in main, plus SV PR URL if present.
    
    Strategy:
    1. List commits present in pr/XXXXX but not in main
    2. Return (commit_hashes, sv_pr_url) tuple where sv_pr_url is extracted from PR body if present
    3. Return ([], None) for staging PRs or if validation fails
    """
    match = re.search(r'/pull/(\d+)$', pr_url)
    if not match:
        raise BackportError(f"Invalid PR URL: {pr_url}")
    pr_number = match.group(1)
    pr_branch = f"pr/{pr_number}"

    # Validate PR is linked to Redmine ticket
    # Try to extract Redmine ticket from PR body/comments
    # Use gh CLI to fetch PR body and comments
    sv_pr_url = None
    try:
        pr_json = run_command(f'gh pr view {pr_number} --repo OISF/suricata --json body', dry_run=False, capture=True)
        pr_data = json.loads(pr_json)
        pr_body = pr_data.get("body", "")
    except Exception as exc:
        raise BackportError(f"Could not fetch GitHub PR #{pr_number} via gh: {exc}")
    
    # Extract SV_BRANCH URL from PR body if present
    sv_match = re.search(r'SV_BRANCH=(https://github\.com/OISF/suricata-verify/pull/\d+)', pr_body)
    if sv_match:
        sv_pr_url = sv_match.group(1)
    
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
            return [], None
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
                    hashes, _ = resolve_pr_to_commits(sub_url, parent_id, dry_run=dry_run,from_staging=True)
                    if len(hashes) > 0:
                        print(f"Found some in : {sub_url}")
                    all_hashes.extend(hashes)
                except Exception as exc:
                    print(f"Warning: Could not resolve sub-PR {sub_url}: {exc}", file=sys.stderr)
            if all_hashes:
                return all_hashes, sv_pr_url
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
    
    return commit_hashes, sv_pr_url

# lol maybe we could import the script functionality instead of spawning a new process
def get_filter_script_path():
    """Locate the filter_backport_main_issues.py script."""
    # Assume it's in ../suricata-verify/util relative to suricata repo
    repo_root = os.path.dirname(os.path.abspath(__file__))  # Go up from scripts/ to repo root
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
    """Create a new backport branch with naming convention backport{7|8}-{id1}-{id2}-v1.
    
    Auto-increments version number if previous versions already exist.
    For example, if backport7-1234-5678-v1 exists, creates v2 instead.
    """
    base_name = f"backport{target}-{'-'.join(issue_ids)}"
    
    # Find the next available version number
    version = 1
    while True:
        branch_name = f"{base_name}-v{version}"
        # Check if branch exists (locally or remotely)
        check_cmd = f"git rev-parse --verify {branch_name}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            # Branch doesn't exist, we can use this version
            break
        
        version += 1
    
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

def build_pr_body(child_ids, pr_entries, sv_pr_url=None):
    lines = []
    lines.append("Link to ticket: https://redmine.openinfosecfoundation.org/issues/")
    for child_id in child_ids:
        lines.append(f"https://redmine.openinfosecfoundation.org/issues/{child_id}")
    lines.append("")
    lines.append("Describe changes:")
    for pr_url, status, nb_hashes in pr_entries:
        plural = "s" if nb_hashes > 1 else ""
        lines.append(f"- backport of {pr_url} {status} cherry-pick{plural}")
    if sv_pr_url:
        lines.append("")
        lines.append(f"SV_BRANCH={sv_pr_url}")
    return "\n".join(lines)

def create_github_pr(title, body, base_branch, head_branch, dry_run=False, labels=None):
    print("[DRY-RUN] gh pr create --base {} --head {} --title <title> --body <body>".format(base_branch, head_branch))
    if labels:
        print(f"[DRY-RUN] --label {' --label '.join(labels)}")
    
    gh_check = subprocess.run("command -v gh", shell=True, capture_output=True, text=True)
    if gh_check.returncode != 0:
        compare_url = f"https://github.com/OISF/suricata/compare/{base_branch}...{head_branch}?expand=1"
        print("GitHub CLI (gh) not found. Create the PR manually using:")
        print(compare_url)
        print("\nTitle:")
        print(title)
        print("\nBody:")
        print(body)
        if labels:
            print("\nLabels:")
            print(", ".join(labels))
        pr_url = input("\nEnter the created PR URL (or leave blank to skip Redmine update): ").strip()
        return pr_url or None
    
    cmd = ["gh", "pr", "create", "--base", base_branch, "--head", "{}:".format(GITHUB_USER)+head_branch, "--title", title, "--body", body]
    if labels:
        for label in labels:
            cmd.extend(["--label", label])
    
    result = subprocess.run(cmd, text=True, capture_output=True)
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

def get_test_yaml_files_from_sv_pr(sv_pr_url):
    """Get list of test.yaml files modified in a suricata-verify PR.
    
    Args:
        sv_pr_url: SV PR URL
    
    Returns:
        List of file paths to test.yaml files
    """
    try:
        match = re.search(r'/pull/(\d+)$', sv_pr_url)
        if not match:
            return []
        pr_number = match.group(1)
        
        # Get list of modified files
        files_json = run_command(f'gh pr view {pr_number} --repo OISF/suricata-verify --json files', dry_run=False, capture=True)
        files_data = json.loads(files_json)
        files = files_data.get("files", [])
        
        test_yaml_files = []
        for file_obj in files:
            file_path = file_obj.get("path", "")
            if file_path.endswith("test.yaml"):
                test_yaml_files.append(file_path)
        
        return test_yaml_files
    except Exception as e:
        print(f"Warning: Could not get files from {sv_pr_url}: {e}", file=sys.stderr)
    
    return []

def update_min_version_in_file(file_path, target, sv_dir):
    """Update min-version in a test.yaml file for the backport target.
    
    Replaces `min-version: 9` with target-specific version:
    - target 8: `min-version: 8.0.4`
    - target 7: `min-version: 7.0.15`
    
    Args:
        file_path: Path to test.yaml file (relative to repo)
        target: Version target (7 or 8)
        sv_dir: suricata-verify working directory
    
    Returns:
        True if file was modified, False otherwise
    """
    target_version = {
        7: "7.0.15",
        8: "8.0.4"
    }.get(target, "")
    
    if not target_version:
        return False
    
    full_path = os.path.join(sv_dir, file_path)
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace min-version: 9 with target version
        updated_content = re.sub(r'min-version:\s*9\b', f'min-version: {target_version}', content)
        
        if content != updated_content:
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            return True
    except Exception as e:
        print(f"Warning: Could not update {file_path}: {e}", file=sys.stderr)
    
    return False

def create_sv_backport_commits(target, issues_with_sv, sv_dir, dry_run=False):
    """Create backport commits in suricata-verify by updating test.yaml files.
    
    For each issue, uses the SV PR URL that was already extracted during resolve_pr_to_commits,
    gets test.yaml files, and creates a commit updating min-version.
    
    Args:
        target: Version target (7 or 8)
        issues_with_sv: List of (parent_id, child_id, pr_url, sv_pr_url) tuples
        sv_dir: suricata-verify working directory
        dry_run: Dry-run mode
    
    Returns:
        True if at least one commit was created, False otherwise
    """
    commits_created = False
    
    for parent_id, child_id, pr_url, sv_pr_url in issues_with_sv:
        print(f"\nProcessing Issue #{parent_id} for SV backport:")
        
        # SV PR URL was already extracted during resolve_pr_to_commits
        if not sv_pr_url:
            print(f"  No SV_BRANCH found in {pr_url}")
            continue
        
        print(f"  Found SV PR: {sv_pr_url}")
        
        # Get test.yaml files from SV PR
        test_yaml_files = get_test_yaml_files_from_sv_pr(sv_pr_url)
        if not test_yaml_files:
            print(f"  No test.yaml files found in {sv_pr_url}")
            continue
        
        print(f"  Found {len(test_yaml_files)} test.yaml file(s):")
        for f in test_yaml_files:
            print(f"    - {f}")
        
        # Update all test.yaml files
        files_updated = []
        for file_path in test_yaml_files:
            if update_min_version_in_file(file_path, target, sv_dir):
                files_updated.append(file_path)
        
        if files_updated:
            # Create commit
            files_arg = ' '.join(files_updated)
            cmd = f"git add {files_arg}"
            run_command(cmd, dry_run=dry_run)
            
            commit_msg = f"backport: support issue {child_id} tests for {target}"
            cmd = f'git commit -m "{commit_msg}"'
            run_command(cmd, dry_run=dry_run)
            
            print(f"  Created commit updating {len(files_updated)} file(s)")
            commits_created = True
        else:
            print(f"  No test.yaml files required updating")
    
    return commits_created

def prompt_issue_selection(issues):
    """Interactively prompt user to remove issues from the backport list.
    
    Args:
        issues: List of (parent_id, child_id, pr_url) tuples
    
    Returns:
        Filtered list of issues
    """
    if not issues:
        return issues
    
    while True:
        selection = input("Enter issue numbers to remove (comma-separated), or press Enter to keep all: ").strip()
        if not selection:
            return issues
        
        try:
            remove_ids = set(int(x.strip()) for x in selection.split(',') if x.strip())
        except ValueError:
            print("Invalid input. Use numbers like: 2,3")
            continue
        
        if any(i < 1 or i > len(issues) for i in remove_ids):
            print("Invalid selection. Choose numbers from the list above.")
            continue
        
        filtered = [issue for i, issue in enumerate(issues, 1) if i not in remove_ids]
        
        # Show what will remain
        print(f"\nRemaining {len(filtered)} issue(s):")
        for i, (parent_id, child_id, pr_url) in enumerate(filtered, 1):
            print(f"  {i}. Issue #{parent_id} (child #{child_id}): {pr_url}")
        
        confirm = input("\nConfirm this selection? (y/N): ").strip().lower()
        if confirm == "y":
            return filtered
        print("Returning to issue list selection.")
        # Re-display original list
        for i, (parent_id, child_id, pr_url) in enumerate(issues, 1):
            print(f"  {i}. Issue #{parent_id} (child #{child_id}): {pr_url}")


def create_suricata_verify_pr(target, branch_name, child_ids, issues_with_sv, dry_run=False):
    """Create a backport PR in suricata-verify repository.
    
    Steps:
    1. Save current directory and change to suricata-verify
    2. Checkout master branch
    3. Pull latest changes
    4. Create backport branch (same naming as suricata)
    5. Create commits by updating test.yaml files in SV PRs
    6. Create GitHub PR with "requires backport" label
    7. Return SV PR URL
    8. Switch back to suricata working directory
    
    Args:
        target: Version target (7 or 8)
        branch_name: Branch name from suricata (e.g., backport7-1234-5678-v1)
        child_ids: List of child Redmine issue IDs
        issues_with_sv: List of (parent_id, child_id, pr_url, sv_pr_url) tuples
        dry_run: Dry-run mode
    
    Returns:
        PR URL of created suricata-verify PR, or None if skipped
    """
    current_dir = os.getcwd()
    
    try:
        # Step 1: Change to suricata-verify directory
        repo_root = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(repo_root)
        sv_dir = os.path.join(parent_dir, "suricata-verify")
        
        if not os.path.isdir(sv_dir):
            print(f"Warning: suricata-verify directory not found at {sv_dir}")
            print("Skipping suricata-verify PR creation.")
            return None
        
        print(f"\nSwitching to suricata-verify directory: {sv_dir}")
        os.chdir(sv_dir)
        
        # Step 2: Checkout master
        target_branch = "master"
        print(f"Checking out {target_branch}...")
        run_command(f"git checkout {target_branch}", dry_run=dry_run)
        
        # Step 3: Pull latest changes
        if not dry_run:
            print("Pulling latest changes...")
            run_command(f"git pull", dry_run=dry_run)
        
        # Step 4: Create backport branch (same naming convention)
        print(f"Creating backport branch: {branch_name}")
        sv_branch_name = branch_name
        
        # Find next available version if branch exists
        base_name = branch_name.rsplit('-v', 1)[0]  # Get base without version
        version = int(branch_name.rsplit('-v', 1)[1]) if '-v' in branch_name else 1
        
        while True:
            check_branch = f"{base_name}-v{version}"
            check_cmd = f"git rev-parse --verify {check_branch}"
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                sv_branch_name = check_branch
                break
            
            version += 1
        
        cmd = f"git checkout -b {sv_branch_name}"
        run_command(cmd, dry_run=dry_run)
        
        # Step 5: Create commits in suricata-verify by updating test.yaml files
        print(f"Creating backport commits in suricata-verify...")
        print(f"Branch: {sv_branch_name}")
        commits_created = create_sv_backport_commits(target, issues_with_sv, sv_dir, dry_run=dry_run)
        
        if not commits_created:
            print("No backport commits were created (no test.yaml files found)")
            if not dry_run:
                response = input("Continue with PR creation anyway? (y/N): ").strip().lower()
                if response != "y":
                    os.chdir(current_dir)
                    print("Skipped suricata-verify PR creation.")
                    return None
            elif dry_run:
                # In dry-run mode, still proceed to show what would happen
                pass
            else:
                os.chdir(current_dir)
                return None
        
        # Step 6: Create GitHub PR with label
        sv_pr_title = f"Backport{target} {branch_name.split('-', 1)[1].rsplit('-v', 1)[0]} v{version}"
        # Build body with Redmine ticket references
        sv_pr_body_lines = []
        for child_id in child_ids:
            sv_pr_body_lines.append(f"Redmine ticket: https://redmine.openinfosecfoundation.org/issues/{child_id}")
        sv_pr_body_lines.append("")
        sv_pr_body_lines.append(f"Backport for suricata branch: {branch_name}")
        sv_pr_body = "\n".join(sv_pr_body_lines)
        
        if dry_run or commits_created:
            print("\nPushing suricata-verify branch...")
            run_command(f"git push {REMOTE_GIT}", dry_run=dry_run)
            print(f"\nCreating suricata-verify PR...")
            sv_pr_url = create_github_pr(sv_pr_title, sv_pr_body, target_branch, sv_branch_name, dry_run=dry_run, labels=["requires backport"])
            
            if sv_pr_url:
                print(f"Created suricata-verify PR: {sv_pr_url}")
        else:
            sv_pr_url = None
        
        # Step 8: Switch back to suricata
        print(f"\nSwitching back to suricata directory: {current_dir}")
        os.chdir(current_dir)
        
        return sv_pr_url
        
    except Exception as e:
        # Always try to switch back to original directory
        try:
            os.chdir(current_dir)
        except Exception:
            pass
        raise BackportError(f"Failed to create suricata-verify PR: {e}")

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
        for i, (parent_id, child_id, pr_url) in enumerate(issues, 1):
            print(f"  {i}. Issue #{parent_id} (child #{child_id}): {pr_url}")
        print()
        
        # Step 1.5: Interactive prompt to remove issues
        issues = prompt_issue_selection(issues)
        if not issues:
            print("No issues selected for backport.")
            return 0
        print()
        
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
        issues_with_sv = []  # Store (parent_id, child_id, pr_url, sv_pr_url) tuples for SV processing
        for parent_id, child_id, pr_url in issues:
            print(f"\nProcessing Issue #{parent_id} (child #{child_id}) ({pr_url}):")
            commit_hashes, sv_pr_url = resolve_pr_to_commits(pr_url, parent_id, dry_run=args.dry)
            print(f"  Found {len(commit_hashes)} commit(s)")
            if sv_pr_url:
                print(f"  Found SV PR: {sv_pr_url}")
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
            if sv_pr_url:
                issues_with_sv.append((parent_id, child_id, pr_url, sv_pr_url))
        
        print("\n" + "="*60)
        print("Backport branch created successfully!")
        print(f"Branch: {branch_name}")
        print(f"Issues processed: {len(issues)}")
        print(f"Commits cherry-picked: {total_commits}")
        print("="*60)
        
        # Step 5: Create suricata-verify backport PR
        sv_pr_url = None
        if not args.dry:
            create_sv = input("\nCreate suricata-verify backport PR? (y/N): ").strip().lower()
            if create_sv == "y":
                sv_pr_url = create_suricata_verify_pr(args.target, branch_name, child_ids, issues_with_sv, dry_run=args.dry)
        
        pr_title = build_pr_title(args.target, issue_ids)
        pr_body = build_pr_body(child_ids, pr_entries, sv_pr_url=sv_pr_url)
        
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
