import os
import requests
import json
from github import Github
from jira import JIRA

# Configs
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
JIRA_SERVER = "https://numerator.atlassian.net"
JIRA_USER = os.getenv("JIRA_USER")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = "SEC"
ORG_NAME = "infoscout"
HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"}

# Git + Jira clients
github_client = Github(GITHUB_TOKEN)
jira_client = JIRA(server=JIRA_SERVER, basic_auth=(JIRA_USER, JIRA_API_TOKEN))

# Collecting alerts of critical/high severity
def collect_alerts(repo_name, severity=["critical", "high"]):
    url = f"https://api.github.com/repos/{ORG_NAME}/{repo_name}/code-scanning/alerts"
    response = requests.get(url, headers=HEADERS)
    
    # Check if the response is successful
    if response.status_code != 200:
        print(f"Failed to fetch alerts for {repo_name}: {response.status_code} - {response.json().get('message', 'Unknown error')}")
        return []

    alerts = response.json()

    # Ensure we're working with a list of alerts
    if not isinstance(alerts, list):
        print(f"No alerts found or malformed response for {repo_name}")
        return []

    # Filter for relevant severity
    relevant_alerts = [alert for alert in alerts if alert.get('rule', {}).get('security_severity_level', '').lower() in severity]
    
    return relevant_alerts

# Fixes (Placeholder)
def generate_fix_for_alert(alert, repo_name):
    if "format string" in alert['rule']['description'].lower():
        return generate_format_string_fix(alert, repo_name)
    elif "command line" in alert['rule']['description'].lower():
        return generate_command_line_fix(alert, repo_name)
    return None

def generate_format_string_fix(alert, repo_name):
    repo = github_client.get_repo(f"{ORG_NAME}/{repo_name}")
    file_path = alert['most_recent_instance']['location']['path']
    file_content = repo.get_contents(file_path, ref="main").decoded_content.decode()

    # Implement fix logic based on alert details
    fixed_content = file_content.replace(alert['most_recent_instance']['message'], "String.format(\"%s\", value)")

    branch_name = commit_changes(repo, file_path, fixed_content, f"Fix {alert['rule']['id']}: {alert['rule']['description']}")
    return branch_name

def generate_command_line_fix(alert, repo_name):
    repo = github_client.get_repo(f"{ORG_NAME}/{repo_name}")
    file_path = alert['most_recent_instance']['location']['path']
    file_content = repo.get_contents(file_path, ref="main").decoded_content.decode()

    # Implement fix logic based on alert details
    fixed_content = file_content.replace(alert['most_recent_instance']['message'], 'subprocess.run(["cmd", arg1, arg2])')

    branch_name = commit_changes(repo, file_path, fixed_content, f"Fix {alert['rule']['id']}: {alert['rule']['description']}")
    return branch_name

def commit_changes(repo, file_path, content, message):
    branch_name = f"fix/{message.replace(' ', '_')}"
    main_ref = repo.get_branch("main")
    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=main_ref.commit.sha)

    repo.update_file(
        path=file_path,
        message=message,
        content=content,
        branch=branch_name
    )
    return branch_name

def create_pull_request(repo_name, branch_name, alert):
    repo = github_client.get_repo(f"{ORG_NAME}/{repo_name}")
    pr_title = f"Fix for {alert['rule']['id']}: {alert['rule']['description']}"
    pr_body = f"Automated fix for {alert['rule']['description']}. This PR addresses the issue at {alert['most_recent_instance']['location']['path']}."
    pr = repo.create_pull(title=pr_title, body=pr_body, head=branch_name, base="main")
    return pr

def create_jira_issue(alert, pr_url):
    issue_summary = f"[{alert['rule']['security_severity_level']}] Fix {alert['rule']['id']}: {alert['rule']['description']}"
    issue_description = f"""
    A fix has been created for the following issue:
    - **Repository**: {alert['repository']['full_name']}
    - **File**: {alert['most_recent_instance']['location']['path']}
    - **Severity**: {alert['rule']['security_severity_level']}
    - **Description**: {alert['rule']['description']}

    Pull Request: {pr_url}
    """
    issue = jira_client.create_issue(
        project=JIRA_PROJECT_KEY,
        summary=issue_summary,
        description=issue_description,
        issuetype={"name": "Bug"},
        labels=["security", alert['rule']['security_severity_level']],
        )
    return issue

def handle_alert(repo_name, alert):
    # Step 1: Generate fix and get the branch name
    branch_name = generate_fix_for_alert(alert, repo_name)

    if not branch_name:
        print(f"Could not create branch for {alert['rule']['id']} in {repo_name}")
        return

    # Step 2: Generate PR
    pr = create_pull_request(repo_name, branch_name, alert)

    # Step 3: Create JIRA issue linked to PR
    jira_issue = create_jira_issue(alert, pr.html_url)
    print(f"Jira Issue {jira_issue.key} created for alert {alert['rule']['id']}")

def process_repo_alerts(repo_name):
    alerts = collect_alerts(repo_name)
    for alert in alerts:
        handle_alert(repo_name, alert)

def process_all_repos():
    for repo in github_client.get_organization(ORG_NAME).get_repos():
        process_repo_alerts(repo.name)

if __name__ == "__main__":
    # Process all repos in org
    process_all_repos()
