import os
import sys
import json
from jira import JIRA
import requests
from requests.auth import HTTPBasicAuth

# Jira configuration
jira_url = os.environ.get('JIRA_URL')
jira_email = os.environ.get('JIRA_EMAIL')
jira_api_token = os.environ.get('JIRA_API_TOKEN')
jira_project = 'SEC'
jira_epic_key = 'SEC-7211'

# Initialize Jira client
try:
    jira = JIRA(server=jira_url, basic_auth=(jira_email, jira_api_token))
except Exception as e:
    print(f"ERROR: Failed to connect to Jira. Please check your Jira configuration. Error: {str(e)}")
    sys.exit(1)

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
                        "body": "Issue has been resolved as the repository is either unsupported or irrelevant."
                    }
                }
            ]
        }
    })
    auth = HTTPBasicAuth(jira_email, jira_api_token)
    
    response = requests.post(url, headers=headers, data=payload, auth=auth)
    
    if response.status_code == 204:
        print(f"  Successfully transitioned issue {issue_key} to Done")
    else:
        print(f"  Failed to transition issue {issue_key}: {response.text}")

def fetch_jira_issues():
    all_issues = []
    start_at = 0
    max_results = 100

    print("Fetching Jira issues...")
    
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
    issues = fetch_jira_issues()

    print(f"\nProcessing {len(issues)} issues...")

    for index, issue in enumerate(issues, start=1):
        summary = issue.fields.summary
        print(f"\nProcessing issue {index}/{len(issues)}: {issue.key} - {summary}")
        try:
            # Transition the issue to Done
            done_transition_id = get_transition_id(issue, "Done")
            if done_transition_id:
                print(f"  Transitioning issue {issue.key} to Done")
                transition_issue(issue.key, done_transition_id)
            else:
                print(f"  Failed to find transition ID for {issue.key} to Done")
        except Exception as e:
            print(f"  Error processing issue {issue.key}: {str(e)}")

    print("\nAll issues processed.")

if __name__ == "__main__":
    process_jira_issues()