import os
import requests
import sys
import time
from datetime import datetime, timedelta
import argparse

# GitHub config
github_token = os.environ.get('GITHUB_TOKEN')
if not github_token:
    print("ERROR: GITHUB_TOKEN environment variable is not set.")
    sys.exit(1)

def get_date_x_years_ago(years):
    return datetime.now() - timedelta(days=365 * years)

def make_request(url, method='get', data=None):
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            if method == 'get':
                response = requests.get(url, headers=headers)
            elif method == 'patch':
                response = requests.patch(url, headers=headers, json=data)
            
            if response.status_code == 200 or response.status_code == 204:
                return response
            elif response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                if int(response.headers['X-RateLimit-Remaining']) == 0:
                    reset_time = int(response.headers['X-RateLimit-Reset']) - time.time()
                    sleep_time = max(reset_time, 0) + 1
                    print(f"Rate limit hit. Sleeping for {sleep_time:.2f} seconds.")
                    time.sleep(sleep_time)
                else:
                    return response
            else:
                return response
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                sleep_time = 2 ** attempt
                print(f"Request failed. Retrying in {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)
            else:
                print(f"Max retries reached. Request failed: {e}")
                return None

def get_repo_info(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    response = make_request(url)
    if response and response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching repo info for {owner}/{repo}: {response.status_code if response else 'No response'}")
        return None

def get_last_commit_date(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    response = make_request(url)
    if response and response.status_code == 200:
        commits = response.json()
        if commits:
            return datetime.strptime(commits[0]['commit']['committer']['date'], "%Y-%m-%dT%H:%M:%SZ")
    return None

def is_code_scanning_enabled(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    response = make_request(url)
    if response is None:
        return False
    if response.status_code == 404:
        error_message = response.json().get('message', '')
        if 'Advanced Security must be enabled' in error_message:
            print(f"  - Advanced Security is not enabled for this repository")
        elif 'no default branch found' in error_message:
            print(f"  - No default branch found for this repository")
        elif 'no analysis found' in error_message:
            print(f"  - Code scanning is enabled, but no analysis has been performed yet")
        else:
            print(f"  - Unknown error: {error_message}")
        return False
    return response.status_code == 200

def get_code_scanning_alerts(owner, repo):
    alerts = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts?state=open&page={page}&per_page=100"
        response = make_request(url)
        if response and response.status_code == 200:
            new_alerts = response.json()
            if not new_alerts:
                break
            alerts.extend(new_alerts)
            page += 1
        else:
            break
    return alerts

def get_user_confirmation():
    while True:
        response = input("Do you want to dismiss the alerts for this repository? (Y/N): ").strip().lower()
        if response in ['y', 'n']:
            return response == 'y'
        print("Invalid input. Please enter 'Y' or 'N'.")

def get_dismissal_reason():
    reasons = {
        '1': 'false positive',
        '2': 'used in tests',
        '3': 'won\'t fix'
    }
    while True:
        print("\nSelect a reason for dismissal:")
        print("1. False positive")
        print("2. Used in tests")
        print("3. Won't fix")
        choice = input("Enter the number of your choice (1-3): ").strip()
        if choice in reasons:
            return reasons[choice]
        print("Invalid choice. Please enter a number between 1 and 3.")

def get_dismissal_comment(reason):
    if reason == "won't fix":
        return input("Enter a comment for the 'Won't fix' dismissal: ").strip()
    return ""

def dismiss_alert(owner, repo, alert_number, reason, comment):
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
    data = {
        "state": "dismissed",
        "dismissed_reason": reason,
        "dismissed_comment": comment
    }
    response = make_request(url, method='patch', data=data)
    return response is not None and response.status_code == 200

def process_repo(owner, repo):
    print(f"Processing {owner}/{repo}...")
    repo_info = get_repo_info(owner, repo)
    if not repo_info:
        print(f"  - Repository not found or inaccessible")
        return 0

    created_at = datetime.strptime(repo_info['created_at'], "%Y-%m-%dT%H:%M:%SZ")
    last_push_date = datetime.strptime(repo_info['pushed_at'], "%Y-%m-%dT%H:%M:%SZ")
    last_commit_date = get_last_commit_date(owner, repo)
    current_date = datetime.now()
    
    print(f"  - Created at: {created_at}")
    print(f"  - Last push (from API): {last_push_date}")
    print(f"  - Last commit: {last_commit_date}")
    print(f"  - Repository age: {(current_date - created_at).days} days")
    print(f"  - Days since last push (from API): {(current_date - last_push_date).days} days")
    if last_commit_date:
        print(f"  - Days since last commit: {(current_date - last_commit_date).days} days")
    
    if is_code_scanning_enabled(owner, repo):
        alerts = get_code_scanning_alerts(owner, repo)
        print(f"  - Found {len(alerts)} open alerts")
        
        if alerts and get_user_confirmation():
            reason = get_dismissal_reason()
            comment = get_dismissal_comment(reason)
            
            dismissed_count = 0
            for alert in alerts:
                if dismiss_alert(owner, repo, alert['number'], reason, comment):
                    dismissed_count += 1
            print(f"  - Dismissed {dismissed_count} alerts")
            return dismissed_count
        else:
            print("  - No alerts dismissed")
    else:
        print("  - Code scanning is not enabled or accessible for this repository")
    return 0

def main():
    parser = argparse.ArgumentParser(description="Dismiss code scanning alerts for specific GitHub repositories.")
    parser.add_argument('repos', nargs='+', help='Repositories to process in the format owner/repo')
    args = parser.parse_args()

    total_dismissed = 0
    for repo_full_name in args.repos:
        owner, repo = repo_full_name.split('/')
        total_dismissed += process_repo(owner, repo)
    
    print(f"\nTotal alerts dismissed: {total_dismissed}")

if __name__ == "__main__":
    main()