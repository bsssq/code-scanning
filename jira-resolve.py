import os
import requests
import sys
import json
from jira import JIRA
import urllib3
import warnings
from requests.auth import HTTPBasicAuth

## this script resolves issues where code scanning is enabled
## it checks if there's an assignee, assigns one (you) if there isn't, then checks if the issue should be resolved or not

# git config
github_token = os.environ.get('GITHUB_TOKEN')
if not github_token:
    print("ERROR: GITHUB_TOKEN environment variable is not set.")
    sys.exit(1)

orgs = ['infoscout', 'MarketTrack']

# jira config
jira_url = os.environ.get('JIRA_URL')
jira_email = os.environ.get('JIRA_EMAIL')
jira_api_token = os.environ.get('JIRA_API_TOKEN')
jira_project = 'SEC'
jira_epic_key = 'SEC-7211'
jira_account_id = "712020:dc80dea2-d61b-41cb-9af0-cf6267e3886d"  # account id: https://numerator.atlassian.net/rest/api/3/myself

# init jira client
try:
    jira = JIRA(server=jira_url, basic_auth=(jira_email, jira_api_token))
except Exception as e:
    print(f"ERROR: Failed to connect to Jira. Please check your Jira configuration. Error: {str(e)}")
    sys.exit(1)

def get_org_repos(org):
    repos = []
    page = 1
    while True:
        url = f"https://api.github.com/orgs/{org}/repos?page={page}&per_page=100"
        response = requests.get(url, headers={'Authorization': f'token {github_token}'})
        if response.status_code == 200:
            new_repos = response.json()
            if not new_repos:
                break
            repos.extend(new_repos)
            page += 1
        elif response.status_code == 403:  # rate limit hit
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()
            print(f"rate limit hit, sleeping for {reset_time} seconds")
            time.sleep(max(reset_time, 0))
        else:
            print(f"error fetching repos for {org}: {response.status_code}")
            break
    return repos

def is_code_scanning_enabled(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    response = requests.get(url, headers={'Authorization': f'token {github_token}'})
    return response.status_code != 404

def assign_issue(issue_key):
    url = f"{jira_url}/rest/api/2/issue/{issue_key}/assignee"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = json.dumps({
        "accountId": jira_account_id
    })
    auth = HTTPBasicAuth(jira_email, jira_api_token)
    
    response = requests.put(url, headers=headers, data=payload, auth=auth)
    
    if response.status_code == 204:
        print(f"Successfully assigned issue {issue_key}")
    else:
        print(f"Failed to assign issue {issue_key}: {response.text}")

def get_transition_id(issue, target_status):
    transitions = jira.transitions(issue)
    for t in transitions:
        if target_status.lower() in t['name'].lower():
            return t['id']
    return None

def transition_issue(issue_key, transition_id):
    url = f"{jira_url}/rest/api/2/issue/{issue_key}/transitions"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = json.dumps({
        "transition": {"id": transition_id},
        "fields": {
            "resolution": {
                "name": "Fixed"
            }
        },
        "update": {
            "comment": [
                {
                    "add": {
                        "body": "Issue has been resolved as code scanning is enabled."
                    }
                }
            ]
        }
    })
    auth = HTTPBasicAuth(jira_email, jira_api_token)
    
    response = requests.post(url, headers=headers, data=payload, auth=auth)
    
    if response.status_code == 204:
        print(f"Successfully transitioned issue {issue_key} to DONE")
    else:
        print(f"Failed to transition issue {issue_key}: {response.text}")

def fetch_jira_issues():
    all_issues = []
    start_at = 0
    max_results = 100  # increase this to fetch more issues per API call

    print("fetching Jira issues...")
    
    while True:
        issues = jira.search_issues(f'project={jira_project} AND "Epic Link" = {jira_epic_key} AND status != "Done"',
                                    startAt=start_at, maxResults=max_results)
        all_issues.extend(issues)
        
        if len(issues) < max_results:
            break

        start_at += len(issues)

    print(f"Fetched {len(all_issues)} issues.")
    return all_issues

def process_jira_issues():
    all_repos = []

    for org in orgs:
        repos = get_org_repos(org)
        for repo in repos:
            repo_full_name = f"{org}/{repo['name']}"
            scanning_enabled = is_code_scanning_enabled(org, repo['name'])
            all_repos.append((repo_full_name, scanning_enabled))
    
    issues = fetch_jira_issues()

    for issue in issues:
        summary = issue.fields.summary
        try:
            if "'" in summary:
                repo_name = summary.split("'")[1]
            elif "`" in summary:
                repo_name = summary.split("`")[1]
            else:
                print(f"skipping issue with unexpected summary format: {summary}")
                continue

            matching_repos = [repo for repo in all_repos if repo_name in repo[0]]

            if not matching_repos:
                print(f"no matching GitHub repository found for issue: {summary}")
                continue

            scanning_enabled = matching_repos[0][1]

            # Ensure the issue is assigned to the correct user before transitioning
            if not issue.fields.assignee or issue.fields.assignee.accountId != jira_account_id:
                print(f"assigning issue {issue.key} to {jira_account_id}")
                assign_issue(issue.key)

            if scanning_enabled:
                done_transition_id = get_transition_id(issue, "Done")
                if done_transition_id:
                    transition_issue(issue.key, done_transition_id)
                else:
                    print(f"failed to find transition ID for {issue.key} to DONE")
            else:
                print(f"code scanning not enabled for {repo_name}, leaving issue open.")
        except Exception as e:
            print(f"error processing repository {summary}: {str(e)}")

if __name__ == "__main__":
    process_jira_issues()
