import os
import requests
import json
import sys
import time

# env variables
github_token = os.getenv('GITHUB_TOKEN')
jira_user = os.getenv('JIRA_ACCOUNT_ID')
jira_token = os.getenv('JIRA_API_TOKEN')
jira_domain = 'https://numerator.atlassian.net'
jira_project_key = 'MAESTRO'  # specific to Maestro team
jira_parent_ticket = 'MAESTRO-446'
repo = 'nmr-maestro'

if not all([github_token, jira_user, jira_token]):
    print("please set GITHUB_TOKEN, JIRA_ACCOUNT_ID, JIRA_API_TOKEN environment variables")
    sys.exit(1)

# git API headers
github_headers = {'Authorization': f'token {github_token}'}

# jira API headers
jira_headers = {
    'Authorization': f'Basic {jira_user}:{jira_token}',
    'Content-Type': 'application/json'
}

# handle github API rate limits
def handle_rate_limit(response):
    if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        if remaining == 0:
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()
            print(f"rate limit hit. sleeping for {int(reset_time)} seconds.")
            time.sleep(max(reset_time, 0))
    return response

# fetch github vulnerability alerts
def fetch_github_alerts(org, repo):
    url = f"https://api.github.com/repos/{org}/{repo}/code-scanning/alerts"
    response = requests.get(url, headers=github_headers)
    response = handle_rate_limit(response)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"failed to fetch alerts for {org}/{repo}. status code: {response.status_code}")
        return None

# Safely handle missing 'severity' key
def get_alert_severity(alert):
    return alert.get('severity', 'High')  # Defaulting to 'High' if severity is not found

# create Jira issue for grouped vulnerability alerts
def create_jira_task(repo, alerts, team_name, group_by, parent_ticket):
    issue_url = f"{jira_domain}/rest/api/3/issue"

    alert_details = "\n".join([f"- {alert['rule']['name']}: {alert['rule']['description']}" for alert in alerts])
    if group_by == "rule":
        title_group = alerts[0]['rule']['name']
    elif group_by == "file":
        title_group = alerts[0]['most_recent_instance']['location']['path']

    issue_data = {
        "fields": {
            "project": {"key": jira_project_key},
            "parent": {"key": parent_ticket},  # Assigning to parent ticket
            "summary": f"[{team_name}] Grouped Vulnerabilities in {repo} - {title_group}",
            "description": f"Vulnerabilities found in {repo}.\n\nDetails:\n{alert_details}",
            "issuetype": {"name": "Sub-task"},  # Sub-task under the parent ticket
            "assignee": {"name": team_name},
            "priority": {"name": "High" if any(get_alert_severity(alert) == 'critical' for alert in alerts) else 'Medium'},
            "labels": ["vulnerability", "security", "auto-generated"]
        }
    }

    response = requests.post(issue_url, headers=jira_headers, json=issue_data)
    response = handle_rate_limit(response)

    if response.status_code == 201:
        print(f"Jira sub-task created for {repo} grouped by {group_by}")
    else:
        print(f"Failed to create Jira sub-task for {repo}. Status code: {response.status_code}")
        print(response.json())


# Create a new branch for the PR
def create_github_branch(org, repo, branch_name):
    # Get the default branch reference (usually main/master)
    ref_url = f"https://api.github.com/repos/{org}/{repo}/git/refs/heads"
    response = requests.get(ref_url, headers=github_headers)
    response = handle_rate_limit(response)
    
    if response.status_code == 200:
        refs = response.json()
        default_branch_ref = refs[0]['ref']
        sha = refs[0]['object']['sha']  # Get the latest commit SHA of the default branch

        # Create a new branch with the SHA of the latest commit
        branch_url = f"https://api.github.com/repos/{org}/{repo}/git/refs"
        branch_data = {
            "ref": f"refs/heads/{branch_name}",
            "sha": sha
        }
        create_branch_response = requests.post(branch_url, headers=github_headers, json=branch_data)
        create_branch_response = handle_rate_limit(create_branch_response)
        
        if create_branch_response.status_code == 201:
            print(f"Branch {branch_name} created successfully.")
        elif create_branch_response.status_code == 422:
            print(f"Branch {branch_name} already exists.")
        else:
            print(f"Failed to create branch {branch_name}. Status code: {create_branch_response.status_code}")
            print(create_branch_response.json())
    else:
        print(f"Failed to fetch default branch for {repo}. Status code: {response.status_code}")

# Create a PR
def create_github_pr(org, repo, branch_name, pr_title, pr_body):
    # Ensure the branch exists first
    create_github_branch(org, repo, branch_name)
    
    pr_url = f"https://api.github.com/repos/{org}/{repo}/pulls"
    pr_data = {
        "title": pr_title,
        "head": branch_name,  # The branch name you created
        "base": "master",  # Ensure this is the correct base branch (adjust as needed)
        "body": pr_body
    }

    response = requests.post(pr_url, headers=github_headers, json=pr_data)
    response = handle_rate_limit(response)

    if response.status_code == 201:
        print(f"Pull Request created for {repo}: {pr_title}")
    else:
        print(f"Failed to create PR for {repo}. Status code: {response.status_code}")
        print(response.json())

# group alerts by vulnerability rule or file
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

# process vulnerabilities for repo
def process_vulnerabilities(org, repo, team_name, group_by, parent_ticket):
    alerts = fetch_github_alerts(org, repo)

    if alerts:
        # group alerts based on specified method (by rule or file)
        grouped_alerts = group_alerts(alerts, group_by)

        for group_key, grouped_alerts_list in grouped_alerts.items():
            # create Jira issue for each group of alerts
            create_jira_task(repo, grouped_alerts_list, team_name, group_by, parent_ticket)

            # create branch + PR for each group
            branch_name = f"fix/{group_key.replace(' ', '-').lower()}"
            pr_title = f"Fix {group_key} vulnerabilities in {repo}"
            pr_body = f"Fixes the following vulnerabilities in {repo}:\n\n" + "\n".join(
                [f"- {alert['rule']['name']} in {alert['most_recent_instance']['location']['path']}" for alert in grouped_alerts_list]
            )

            # create PR for grouped vulnerabilities
            create_github_pr(org, repo, branch_name, pr_title, pr_body)

if __name__ == "__main__":
    org = "infoscout"  # replace with your org name
    repo = "nmr-maestro"

    # process vulnerabilities for nmr-maestro repo
    team_name = "maestro-team"  # adjust as needed
    process_vulnerabilities(org, repo, team_name, group_by="rule", parent_ticket=jira_parent_ticket)  # grouping by rule
