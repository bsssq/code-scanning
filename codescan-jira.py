import os
import requests
from jira import JIRA
import urllib3
import warnings
import sys
import time

## this script creates JIRA issues based on which repos have code scanning enabled or not
## this is part of the SEC-7211 epic

# git configuration
github_token = os.environ.get('GITHUB_TOKEN')
if not github_token:
    print("ERROR: GITHUB_TOKEN environment variable is not set.")
    sys.exit(1)

orgs = ['infoscout', 'MarketTrack']

# jira config
jira_url = os.environ.get('JIRA_URL')
if not jira_url:
    print("ERROR: JIRA_URL environment variable is not set.")
    sys.exit(1)

jira_email = os.environ.get('JIRA_EMAIL')
if not jira_email:
    print("ERROR: JIRA_EMAIL environment variable is not set.")
    sys.exit(1)

jira_api_token = os.environ.get('JIRA_API_TOKEN')
if not jira_api_token:
    print("ERROR: JIRA_API_TOKEN environment variable is not set.")
    sys.exit(1)

jira_project = 'SEC'
jira_epic_key = 'SEC-7211'
jira_assignee = 'Bilal Siddiqui'

# init jira client
try:
    jira = JIRA(server=jira_url, basic_auth=(jira_email, jira_api_token))
except Exception as e:
    print(f"ERROR: Failed to connect to Jira. Please check your Jira configuration. Error: {str(e)}")
    sys.exit(1)

def get_epic_link_field():
    fields = jira.fields()
    for field in fields:
        if field['name'].lower() == 'epic link':
            return field['id']
    raise Exception("Epic Link field not found")

# get epic link field
epic_link_field = get_epic_link_field()
print(f"using field ID '{epic_link_field}' for Epic Link")

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
            print(f"rrror fetching repos for {org}: {response.status_code}")
            break
    return repos

def is_code_scanning_enabled(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    response = requests.get(url, headers={'Authorization': f'token {github_token}'})
    return response.status_code != 404

def get_transition_id(issue, target_status):
    transitions = jira.transitions(issue)
    for t in transitions:
        if target_status.lower() in t['name'].lower():
            return t['id']
    return None

def create_or_update_jira_issue(repo_name, org, scanning_enabled):
    try:
        issue_summary = f"CodeQL for '{repo_name}'"
        existing_issues = jira.search_issues(f'project={jira_project} AND summary~"{issue_summary}"')

        if existing_issues:
            issue = existing_issues[0]
            current_status = issue.fields.status.name
            
            # set assignee before any transitions
            if issue.fields.assignee is None or issue.fields.assignee.displayName != jira_assignee:
                jira.assign_issue(issue, jira_assignee)
                print(f"updated assignee for {org}/{repo_name}")

            if scanning_enabled and current_status.upper() != "DONE":
                if current_status.upper() == "BACKLOG":
                    open_transition_id = get_transition_id(issue, "OPEN")
                    if open_transition_id:
                        jira.transition_issue(issue, open_transition_id)
                        print(f"moved Jira issue for {org}/{repo_name} from BACKLOG to OPEN")
                
                done_transition_id = get_transition_id(issue, "DONE")
                if done_transition_id:
                    jira.transition_issue(issue, done_transition_id)
                    print(f"resolved Jira issue for {org}/{repo_name}")
            
            elif not scanning_enabled and current_status.upper() == "DONE":
                open_transition_id = get_transition_id(issue, "OPEN")
                if open_transition_id:
                    jira.transition_issue(issue, open_transition_id)
                    print(f"reopened Jira issue for {org}/{repo_name}")
        else:
            issue_dict = {
                'project': {'key': jira_project},
                'summary': issue_summary,
                'description': f"Implement CodeQL scanning for the {org}/{repo_name} repository.",
                'issuetype': {'name': 'Task'},
                epic_link_field: jira_epic_key,
                'assignee': {'name': jira_assignee}
            }
            new_issue = jira.create_issue(fields=issue_dict)
            print(f"created Jira issue for {org}/{repo_name}")
            
            # move from BACKLOG to OPEN
            open_transition_id = get_transition_id(new_issue, "OPEN")
            if open_transition_id:
                jira.transition_issue(new_issue, open_transition_id)
                print(f"moved Jira issue for {org}/{repo_name} from BACKLOG to OPEN")
            
            if scanning_enabled:
                done_transition_id = get_transition_id(new_issue, "DONE")
                if done_transition_id:
                    jira.transition_issue(new_issue, done_transition_id)
                    print(f"resolved Jira issue for {org}/{repo_name}")
    except Exception as e:
        print(f"error processing Jira issue for {repo_name}: {str(e)}")

def main():
    enabled_repos = []
    disabled_repos = []

    try:
        # fetch all repository data
        repo_data = {}
        for org in orgs:
            repos = get_org_repos(org)
            print(f"\norganization: {org} - total repositories fetched: {len(repos)}")
            repo_data[org] = repos

        # process the data and interact with Jira
        for org, repos in repo_data.items():
            for repo in repos:
                repo_full_name = f"{org}/{repo['name']}"
                try:
                    scanning_enabled = is_code_scanning_enabled(org, repo['name'])
                    
                    if scanning_enabled:
                        enabled_repos.append(repo_full_name)
                    else:
                        disabled_repos.append(repo_full_name)
                    
                    create_or_update_jira_issue(repo['name'], org, scanning_enabled)
                    print(f"processed {repo_full_name}: scanning enabled = {scanning_enabled}")
                except Exception as e:
                    print(f"error processing repository {repo_full_name}: {str(e)}")

    except Exception as e:
        print(f"an error occurred: {str(e)}")
    finally:
        print("\nRepositories with code scanning enabled:")
        for repo in enabled_repos:
            print(repo)
        
        print("\nRepositories with code scanning disabled:")
        for repo in disabled_repos:
            print(repo)

        print(f"\nTotal repositories checked: {len(enabled_repos) + len(disabled_repos)}")
        print(f"Repositories with code scanning enabled: {len(enabled_repos)}")
        print(f"Repositories with code scanning disabled: {len(disabled_repos)}")

if __name__ == "__main__":
    main()
