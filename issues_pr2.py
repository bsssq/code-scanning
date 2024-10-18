import os
import requests
from jira import JIRA
import sys
import time

# env variables
github_token = os.getenv('GITHUB_TOKEN')
jira_url = os.getenv('JIRA_URL')
jira_email = os.getenv('JIRA_EMAIL')
jira_api_token = os.getenv('JIRA_API_TOKEN')

# Check for environment variables
if not all([github_token, jira_email, jira_api_token, jira_url]):
    print("Please ensure GITHUB_TOKEN, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_URL environment variables are set.")
    sys.exit(1)

# GitHub API headers
github_headers = {'Authorization': f'token {github_token}'}

# Initialize Jira client
try:
    jira = JIRA(server=jira_url, basic_auth=(jira_email, jira_api_token))
except Exception as e:
    print(f"ERROR: Failed to connect to Jira. Error: {str(e)}")
    sys.exit(1)

def handle_rate_limit(response):
    if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        if remaining == 0:
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()
            print(f"Rate limit hit. Sleeping for {int(reset_time)} seconds.")
            time.sleep(max(reset_time, 0))
    return response

def check_repo_permissions(org, repo):
    url = f"https://api.github.com/repos/{org}/{repo}"
    response = requests.get(url, headers=github_headers)
    if response.status_code == 200:
        repo_info = response.json()
        permissions = repo_info.get('permissions', {})
        print(f"Your permissions for {org}/{repo}:")
        print(f"Admin: {permissions.get('admin', False)}")
        print(f"Push: {permissions.get('push', False)}")
        print(f"Pull: {permissions.get('pull', False)}")
        return permissions
    else:
        print(f"Failed to fetch repository information. Status code: {response.status_code}")
        return None

def get_default_branch(org, repo):
    url = f"https://api.github.com/repos/{org}/{repo}"
    response = requests.get(url, headers=github_headers)
    if response.status_code == 200:
        return response.json()['default_branch']
    else:
        print(f"Failed to get default branch. Status code: {response.status_code}")
        return None

def get_branch_sha(org, repo, branch):
    url = f"https://api.github.com/repos/{org}/{repo}/git/ref/heads/{branch}"
    response = requests.get(url, headers=github_headers)
    if response.status_code == 200:
        return response.json()['object']['sha']
    else:
        print(f"Failed to get branch SHA. Status code: {response.status_code}")
        return None

def check_branch_exists(org, repo, branch_name):
    url = f"https://api.github.com/repos/{org}/{repo}/git/refs/heads/{branch_name}"
    response = requests.get(url, headers=github_headers)
    return response.status_code == 200

def get_or_create_branch(org, repo, branch_name, base_branch):
    if check_branch_exists(org, repo, branch_name):
        print(f"Branch '{branch_name}' already exists. Using existing branch.")
        return True
    
    base_sha = get_branch_sha(org, repo, base_branch)
    if not base_sha:
        return False

    return create_github_branch(org, repo, branch_name, base_sha)

def create_github_branch(org, repo, branch_name, sha):
    url = f"https://api.github.com/repos/{org}/{repo}/git/refs"
    data = {
        "ref": f"refs/heads/{branch_name}",
        "sha": sha
    }
    response = requests.post(url, headers=github_headers, json=data)
    response = handle_rate_limit(response)
    
    if response.status_code == 201:
        print(f"Branch '{branch_name}' created successfully.")
        return True
    else:
        print(f"Failed to create branch '{branch_name}'. Status code: {response.status_code}")
        print(response.json())
        return False

def fetch_github_alerts(org, repo):
    all_alerts = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/repos/{org}/{repo}/code-scanning/alerts?state=open&per_page={per_page}&page={page}"
        response = requests.get(url, headers=github_headers)
        response = handle_rate_limit(response)

        if response.status_code == 200:
            alerts = response.json()
            all_alerts.extend(alerts)
            if len(alerts) < per_page:
                break
            page += 1
        else:
            print(f"Failed to fetch code scanning alerts for {org}/{repo}. Status code: {response.status_code}")
            return None

    return all_alerts

def fetch_dependabot_alerts(org, repo):
    all_alerts = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/repos/{org}/{repo}/dependabot/alerts?state=open&per_page={per_page}&page={page}"
        response = requests.get(url, headers=github_headers)
        response = handle_rate_limit(response)

        if response.status_code == 200:
            alerts = response.json()
            all_alerts.extend(alerts)
            if len(alerts) < per_page:
                break
            page += 1
        else:
            print(f"Failed to fetch Dependabot alerts for {org}/{repo}. Status code: {response.status_code}")
            return None

    return all_alerts

def fetch_secret_scanning_alerts(org, repo):
    all_alerts = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/repos/{org}/{repo}/secret-scanning/alerts?state=open&per_page={per_page}&page={page}"
        response = requests.get(url, headers=github_headers)
        response = handle_rate_limit(response)

        if response.status_code == 200:
            alerts = response.json()
            all_alerts.extend(alerts)
            if len(alerts) < per_page:
                break
            page += 1
        else:
            print(f"Failed to fetch secret scanning alerts for {org}/{repo}. Status code: {response.status_code}")
            return None

    return all_alerts

def filter_alerts_by_severity(alerts, severity):
    return [alert for alert in alerts if alert.get('rule', {}).get('security_severity_level', '').lower() in severity]

def check_existing_jira_issue(jira, project_key, summary, rule_id, parent_ticket):
    jql_query = f'project = {project_key} AND summary ~ "\'{rule_id}\'" AND parent = {parent_ticket} AND status != Closed'
    issues = jira.search_issues(jql_query)
    return issues[0] if issues else None

def create_or_update_jira_subtask(jira_project_key, repo, alerts, group_by, parent_ticket):
    rule_name = alerts[0].get('rule', {}).get('name', 'Unknown')
    rule_id = alerts[0].get('rule', {}).get('id', 'Unknown')
    issue_summary = f"Grouped Vulnerabilities in {repo} - '{rule_id}'"

    existing_issue = check_existing_jira_issue(jira, jira_project_key, issue_summary, rule_id, parent_ticket)

    if existing_issue:
        print(f"Existing Jira issue found under parent {parent_ticket}: {jira_url}/browse/{existing_issue.key}")
        return existing_issue

    alert_details = "\n".join([
        f"- {alert.get('rule', {}).get('name', 'Unknown')}: {alert.get('rule', {}).get('description', 'No description')}\n  "
        f"Location: {alert.get('html_url', 'No URL')}"
        for alert in alerts
    ])

    severity = alerts[0].get('rule', {}).get('security_severity_level', 'Medium').lower()
    priority = map_severity_to_priority(severity)

    issue_dict = {
        "project": {"key": jira_project_key},
        "summary": issue_summary,
        "description": f"Vulnerabilities found in {repo}.\n\nDetails:\n{alert_details}\n\n",
        "issuetype": {"name": "Sub-task"},
        "parent": {"key": parent_ticket},
        "priority": {"name": priority},
        "labels": ["vulnerability", "security", "auto-generated"]
    }

    try:
        new_issue = jira.create_issue(fields=issue_dict)
        print(f"Jira sub-task created under {parent_ticket}: {jira_url}/browse/{new_issue.key}")
        return new_issue
    except Exception as e:
        print(f"Failed to create Jira sub-task. Error: {str(e)}")
        return None

def map_severity_to_priority(severity):
    priority_mapping = {
        "critical": "Blocker",
        "high": "Critical",
        "medium": "Major",
        "low": "Minor",
        "informational": "Trivial"
    }
    return priority_mapping.get(severity.lower(), "Major")


def create_commit(org, repo, branch, message, content):
    url = f"https://api.github.com/repos/{org}/{repo}/git/refs/heads/{branch}"
    response = requests.get(url, headers=github_headers)
    if response.status_code != 200:
        print(f"Failed to get latest commit. Status code: {response.status_code}")
        return None
    sha = response.json()['object']['sha']

    blob_url = f"https://api.github.com/repos/{org}/{repo}/git/blobs"
    blob_data = {
        "content": content,
        "encoding": "utf-8"
    }
    blob_response = requests.post(blob_url, headers=github_headers, json=blob_data)
    if blob_response.status_code != 201:
        print(f"Failed to create blob. Status code: {blob_response.status_code}")
        return None
    blob_sha = blob_response.json()['sha']

    tree_url = f"https://api.github.com/repos/{org}/{repo}/git/trees"
    tree_data = {
        "base_tree": sha,
        "tree": [
            {
                "path": "vulnerability_fix.md",
                "mode": "100644",
                "type": "blob",
                "sha": blob_sha
            }
        ]
    }
    tree_response = requests.post(tree_url, headers=github_headers, json=tree_data)
    if tree_response.status_code != 201:
        print(f"Failed to create tree. Status code: {tree_response.status_code}")
        return None
    tree_sha = tree_response.json()['sha']

    commit_url = f"https://api.github.com/repos/{org}/{repo}/git/commits"
    commit_data = {
        "message": message,
        "tree": tree_sha,
        "parents": [sha]
    }
    commit_response = requests.post(commit_url, headers=github_headers, json=commit_data)
    if commit_response.status_code != 201:
        print(f"Failed to create commit. Status code: {commit_response.status_code}")
        return None
    new_commit_sha = commit_response.json()['sha']

    ref_url = f"https://api.github.com/repos/{org}/{repo}/git/refs/heads/{branch}"
    ref_data = {
        "sha": new_commit_sha
    }
    ref_response = requests.patch(ref_url, headers=github_headers, json=ref_data)
    if ref_response.status_code != 200:
        print(f"Failed to update reference. Status code: {ref_response.status_code}")
        return None

    print(f"Commit created successfully in branch {branch}")
    return new_commit_sha

def create_github_pr(org, repo, branch_name, pr_title, pr_body):
    permissions = check_repo_permissions(org, repo)
    if not permissions or not permissions.get('push', False):
        print("You don't have push access to this repository. Cannot create PR.")
        return None

    default_branch = get_default_branch(org, repo)
    if not default_branch:
        return None

    if not get_or_create_branch(org, repo, branch_name, default_branch):
        print(f"Failed to get or create branch '{branch_name}'. Cannot create PR.")
        return None

    commit_message = f"Fix {pr_title}"
    commit_content = f"This commit addresses the following vulnerability:\n\n{pr_body}"
    if not create_commit(org, repo, branch_name, commit_message, commit_content):
        print("Failed to create commit. Cannot create PR.")
        return None

    existing_pr = check_existing_pr(org, repo, branch_name, default_branch)
    if existing_pr:
        print(f"PR already exists: {existing_pr}")
        return existing_pr

    pr_url = f"https://api.github.com/repos/{org}/{repo}/pulls"
    pr_data = {
        "title": pr_title,
        "head": branch_name,
        "base": default_branch,
        "body": pr_body,
        "draft": True
    }

    response = requests.post(pr_url, headers=github_headers, json=pr_data)
    response = handle_rate_limit(response)

    if response.status_code == 201:
        pr_url = response.json()['html_url']
        print(f"Pull Request created for {repo}: {pr_url}")
        return pr_url
    else:
        print(f"Failed to create PR for {repo}. Status code: {response.status_code}")
        print(response.json())
        return None

def check_existing_pr(org, repo, head_branch, base_branch):
    url = f"https://api.github.com/repos/{org}/{repo}/pulls"
    params = {
        "head": f"{org}:{head_branch}",
        "base": base_branch,
        "state": "open"
    }
    response = requests.get(url, headers=github_headers, params=params)
    if response.status_code == 200:
        prs = response.json()
        if prs:
            return prs[0]['html_url']
    return None

def group_alerts(alerts, group_by):
    grouped_alerts = {}
    for alert in alerts:
        if group_by == "rule":
            group_key = alert.get('rule', {}).get('id', 'Unknown')
        
        if group_key not in grouped_alerts:
            grouped_alerts[group_key] = []
        grouped_alerts[group_key].append(alert)
    return grouped_alerts

def process_vulnerabilities(org, repo, jira_project_key, parent_ticket):
    code_scanning_alerts = fetch_github_alerts(org, repo)
    dependabot_alerts = fetch_dependabot_alerts(org, repo)
    secret_scanning_alerts = fetch_secret_scanning_alerts(org, repo)

    all_alerts = []
    if code_scanning_alerts:
        all_alerts.extend(code_scanning_alerts)
    if dependabot_alerts:
        all_alerts.extend(dependabot_alerts)
    if secret_scanning_alerts:
        all_alerts.extend(secret_scanning_alerts)

    if not all_alerts:
        print("No alerts found.")
        return

    severity_choice = input("Which severity do you want to look at? (1: critical, 2: high, 3: both): ")
    if severity_choice == "1":
        severity = ["critical"]
    elif severity_choice == "2":
        severity = ["high"]
    elif severity_choice == "3":
        severity = ["critical", "high"]
    else:
        print("Invalid choice. Exiting.")
        return

    filtered_alerts = filter_alerts_by_severity(all_alerts, severity)

    if not filtered_alerts:
        print("No alerts found for the selected severity.")
        return

    grouped_alerts = group_alerts(filtered_alerts, "rule")
    rules = list(grouped_alerts.keys())

    print("Available rules:")
    for idx, rule in enumerate(rules, start=1):
        rule_name = grouped_alerts[rule][0].get('rule', {}).get('name', 'Unknown')
        rule_severity = grouped_alerts[rule][0].get('rule', {}).get('security_severity_level', 'Unknown')
        print(f"{idx}. {rule_name} ({len(grouped_alerts[rule])} vulnerabilities, Severity: {rule_severity})")

    rule_choices = input("Select the rules you want to process (enter numbers separated by commas): ").split(',')
    selected_rules = [rules[int(choice.strip()) - 1] for choice in rule_choices if choice.strip().isdigit() and 0 < int(choice.strip()) <= len(rules)]

    for selected_rule in selected_rules:
        selected_alerts = grouped_alerts[selected_rule]
        rule_name = selected_alerts[0].get('rule', {}).get('name', 'Unknown')
        print(f"\nProcessing Rule: {rule_name}")
        print(f"Number of vulnerabilities: {len(selected_alerts)}")

        jira_issue = create_or_update_jira_subtask(jira_project_key, repo, selected_alerts, "rule", parent_ticket)
        if not jira_issue:
            print("Failed to create or update Jira issue.")
            continue

        branch_name = f"fix/{rule_name.replace(' ', '-').lower()}"
        pr_title = f"Fix {rule_name} vulnerabilities in {repo}"
        pr_body = f"Fixes the following vulnerabilities in {repo}:\n\n" + "\n".join(
            [f"- {alert.get('rule', {}).get('name', 'Unknown')} in {alert.get('most_recent_instance', {}).get('location', {}).get('path', 'Unknown')}" for alert in selected_alerts]
        )

        pr_url = create_github_pr(org, repo, branch_name, pr_title, pr_body)
        if pr_url:
            print(f"GitHub PR created: {pr_url}")
            
            jira_issue.update(description=jira_issue.fields.description + f"\nPull Request: {pr_url}")
            print(f"Jira issue updated with PR link: {jira_url}/browse/{jira_issue.key}")
        else:
            print("Failed to create GitHub PR.")

if __name__ == "__main__":
    org = input("Enter the GitHub organization name: ")
    repo = input("Enter the GitHub repository name: ")
    jira_project_key = input("Enter the JIRA project key: ")
    parent_ticket = input("Enter the parent ticket key: ")

    process_vulnerabilities(org, repo, jira_project_key, parent_ticket)