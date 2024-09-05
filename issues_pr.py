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
jira_project_key = 'MAESTRO'  # specific to Maestro team
jira_parent_ticket = 'MAESTRO-446'
repo = 'nmr-maestro'

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

# Handle GitHub API rate limits
def handle_rate_limit(response):
    if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        if remaining == 0:
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()
            print(f"Rate limit hit. Sleeping for {int(reset_time)} seconds.")
            time.sleep(max(reset_time, 0))
    return response

# Fetch GitHub vulnerability alerts
def fetch_github_alerts(org, repo):
    url = f"https://api.github.com/repos/{org}/{repo}/code-scanning/alerts"
    response = requests.get(url, headers=github_headers)
    response = handle_rate_limit(response)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch alerts for {org}/{repo}. Status code: {response.status_code}")
        return None

# Filter only high-severity alerts
def filter_high_severity_alerts(alerts):
    return [alert for alert in alerts if alert['rule'].get('security_severity_level', '').lower() == 'high']

# Check if a Jira issue already exists for a vulnerability
def jira_issue_exists(issue_summary):
    query = f'project={jira_project_key} AND summary~"{issue_summary}"'
    issues = jira.search_issues(query)
    return len(issues) > 0

# Map CVSS severity to Jira priority
def map_severity_to_priority(severity):
    priority_mapping = {
        "critical": "Blocker",
        "high": "Critical",
        "medium": "Major",
        "low": "Minor",
        "informational": "Trivial"
    }
    return priority_mapping.get(severity.lower(), "Major")

# Create Jira issue for grouped vulnerability alerts
def create_jira_subtask(repo, alerts, group_by, parent_ticket):
    alert_details = "\n".join([f"- {alert['rule']['name']}: {alert['rule']['description']}" for alert in alerts])

    # Grouping by rule or file for title
    if group_by == "rule":
        title_group = alerts[0]['rule']['name']
    elif group_by == "file":
        title_group = alerts[0]['most_recent_instance']['location']['path']

    # Check if issue already exists
    issue_summary = f"Grouped Vulnerabilities in {repo} - {title_group}"
    if jira_issue_exists(issue_summary):
        print(f"Jira issue '{issue_summary}' already exists, skipping creation.")
        return

    # Use security_severity_level or fallback to severity
    severity = alerts[0]['rule'].get('security_severity_level', alerts[0]['rule'].get('severity', 'Medium')).lower()
    priority = map_severity_to_priority(severity)

    # Prepare issue data
    issue_dict = {
        "project": {"key": jira_project_key},
        "summary": issue_summary,
        "description": f"Vulnerabilities found in {repo}.\n\nDetails:\n{alert_details}",
        "issuetype": {"name": "Sub-task"},
        "parent": {"key": parent_ticket},
        "priority": {"name": priority},
        "labels": ["vulnerability", "security", "auto-generated"]
    }

    try:
        # Create the sub-task under the parent ticket
        jira.create_issue(fields=issue_dict)
        print(f"Jira sub-task created under {parent_ticket}")
    except Exception as e:
        print(f"Failed to create Jira sub-task. Error: {str(e)}")

# Create a GitHub PR
def create_github_pr(org, repo, branch_name, pr_title, pr_body):
    pr_url = f"https://api.github.com/repos/{org}/{repo}/pulls"
    pr_data = {
        "title": pr_title,
        "head": branch_name,
        "base": "main",  # Use the correct base branch
        "body": pr_body
    }

    response = requests.post(pr_url, headers=github_headers, json=pr_data)
    response = handle_rate_limit(response)

    if response.status_code == 201:
        print(f"Pull Request created for {repo}: {pr_title}")
    else:
        print(f"Failed to create PR for {repo}. Status code: {response.status_code}")
        print(response.json())

# Group alerts by vulnerability rule or file
def group_alerts(alerts, group_by):
    grouped_alerts = {}
    for alert in alerts:
        if group_by == "rule":
            group_key = alert['rule']['name']
        elif group_by == "file":
            group_key = alert['most_recent_instance']['location']['path']
        
        if group_key not in grouped_alerts:
            grouped_alerts[group_key] = []
        grouped_alerts[group_key].append(alert)
    return grouped_alerts

# Process vulnerabilities for repo
def process_vulnerabilities(org, repo, group_by, parent_ticket):
    alerts = fetch_github_alerts(org, repo)

    if alerts:
        # Filter only high-severity alerts
        high_severity_alerts = filter_high_severity_alerts(alerts)

        # Group alerts by rule or file
        grouped_alerts = group_alerts(high_severity_alerts, group_by)

        for group_key, grouped_alerts_list in grouped_alerts.items():
            # Create Jira sub-task for each group
            create_jira_subtask(repo, grouped_alerts_list, group_by, parent_ticket)

            # Create branch + PR for each group
            branch_name = f"fix/{group_key.replace(' ', '-').lower()}"
            pr_title = f"Fix {group_key} vulnerabilities in {repo}"
            pr_body = f"Fixes the following vulnerabilities in {repo}:\n\n" + "\n".join(
                [f"- {alert['rule']['name']} in {alert['most_recent_instance']['location']['path']}" for alert in grouped_alerts_list]
            )

            # Create PR for grouped vulnerabilities
            create_github_pr(org, repo, branch_name, pr_title, pr_body)

if __name__ == "__main__":
    org = "infoscout"
    repo = "nmr-maestro"
    process_vulnerabilities(org, repo, group_by="rule", parent_ticket=jira_parent_ticket)
