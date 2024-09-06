import os
import requests
import sys
import time
import json
from datetime import datetime, timedelta
import random

# GitHub config
github_token = os.environ.get('GITHUB_TOKEN')
if not github_token:
    print("ERROR: GITHUB_TOKEN environment variable is not set.")
    sys.exit(1)

orgs = ['infoscout', 'MarketTrack']
progress_file = 'dismiss_alerts_progress.json'

def get_date_4_years_ago():
    return datetime.now() - timedelta(days=365 * 4)

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
                    sleep_time = max(reset_time, 0) + random.uniform(1, 5)
                    print(f"Rate limit hit. Sleeping for {sleep_time:.2f} seconds.")
                    time.sleep(sleep_time)
                else:
                    return response
            else:
                return response
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                sleep_time = 2 ** attempt + random.uniform(0, 1)
                print(f"Request failed. Retrying in {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)
            else:
                print(f"Max retries reached. Request failed: {e}")
                return None

def get_org_repos(org):
    repos = []
    page = 1
    while True:
        url = f"https://api.github.com/orgs/{org}/repos?page={page}&per_page=100"
        response = make_request(url)
        if response and response.status_code == 200:
            new_repos = response.json()
            if not new_repos:
                break
            repos.extend(new_repos)
            page += 1
        else:
            break
    return repos

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

def dismiss_alert(owner, repo, alert_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
    data = {
        "state": "dismissed",
        "dismissed_reason": "won't fix",
        "dismissed_comment": "set to be archived"
    }
    response = make_request(url, method='patch', data=data)
    return response is not None and response.status_code == 200

def process_repo(org, repo):
    repo_name = repo['name']
    last_push_date = datetime.strptime(repo['pushed_at'], "%Y-%m-%dT%H:%M:%SZ")
    
    if last_push_date < get_date_4_years_ago():
        print(f"Processing {org}/{repo_name}...")
        if is_code_scanning_enabled(org, repo_name):
            alerts = get_code_scanning_alerts(org, repo_name)
            dismissed_count = 0
            for alert in alerts:
                if dismiss_alert(org, repo_name, alert['number']):
                    dismissed_count += 1
            print(f"  - Dismissed {dismissed_count} alerts")
            return dismissed_count
    else:
        print(f"Skipping {org}/{repo_name} (last push: {last_push_date.date()})")
    return 0

def load_progress():
    if os.path.exists(progress_file):
        with open(progress_file, 'r') as f:
            return json.load(f)
    return {'total_dismissed': 0, 'processed_repos': {}}

def save_progress(progress):
    with open(progress_file, 'w') as f:
        json.dump(progress, f)

def main():
    progress = load_progress()
    total_dismissed = progress['total_dismissed']
    processed_repos = progress['processed_repos']

    for org in orgs:
        print(f"\nProcessing organization: {org}")
        repos = get_org_repos(org)
        for repo in repos:
            repo_full_name = f"{org}/{repo['name']}"
            if repo_full_name not in processed_repos:
                dismissed = process_repo(org, repo)
                total_dismissed += dismissed
                processed_repos[repo_full_name] = dismissed
                progress['total_dismissed'] = total_dismissed
                progress['processed_repos'] = processed_repos
                save_progress(progress)
    
    print(f"\nTotal alerts dismissed: {total_dismissed}")

if __name__ == "__main__":
    main()