import os
import requests
import sys
import time
import inquirer
import pickle
import json
from datetime import datetime, timedelta
import threading
import itertools

# GitHub config
github_token = os.environ.get('GITHUB_TOKEN')
if not github_token:
    print("ERROR: GITHUB_TOKEN environment variable is not set.")
    sys.exit(1)

orgs = ['infoscout', 'MarketTrack']
cache_file = 'repo_cache.pkl'
output_file = 'repos_code_scanning.json'
loading = False

# Function to calculate the time delta for X years ago
def get_date_x_years_ago(years):
    return datetime.now() - timedelta(days=365 * years)

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
            print(f"Rate limit hit, sleeping for {reset_time} seconds")
            time.sleep(max(reset_time, 0))
        else:
            print(f"Error fetching repos for {org}: {response.status_code}")
            break
    return repos

def is_code_scanning_enabled(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    response = requests.get(url, headers={'Authorization': f'token {github_token}'})
    return response.status_code != 404

def get_contributors(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/contributors"
    response = requests.get(url, headers={'Authorization': f'token {github_token}'})
    if response.status_code == 200:
        contributors = response.json()
        return [contributor['login'] for contributor in contributors]
    return []

def get_language_breakdown(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/languages"
    response = requests.get(url, headers={'Authorization': f'token {github_token}'})
    if response.status_code == 200:
        return response.json()
    return {}

def load_cache():
    if os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            return pickle.load(f)
    return {}

def save_cache(data):
    with open(cache_file, 'wb') as f:
        pickle.dump(data, f)

def display_menu():
    questions = [
        inquirer.List('filter_by',
                      message="Which repositories do you want to display?",
                      choices=['Without Code Scanning', 'With Code Scanning']),
        inquirer.List('sort_by',
                      message="How would you like to sort the repositories?",
                      choices=['No Sorting', 'Sort by Contributors']),
    ]
    return inquirer.prompt(questions)

def spinner_animation():
    global loading
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if not loading:
            break
        sys.stdout.write('\rLoading ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\rLoading complete!   \n')

def fetch_data(filter_by):
    global loading
    loading = True
    spinner_thread = threading.Thread(target=spinner_animation)
    spinner_thread.start()

    all_repos = {}
    x_years_ago = get_date_x_years_ago(5)  # Example: filter for repos older than 5 years

    for org in orgs:
        repos = get_org_repos(org)
        filtered_repos = []

        for repo in repos:
            repo_full_name = f"{org}/{repo['name']}"
            scanning_enabled = is_code_scanning_enabled(org, repo['name'])

            last_push_date = datetime.strptime(repo['pushed_at'], "%Y-%m-%dT%H:%M:%SZ")
            status = "Old (Eligible for Archive)" if last_push_date < x_years_ago else "Active"

            if filter_by == 'With Code Scanning' and not scanning_enabled:
                continue  # Skip if code scanning is not enabled and we're filtering for enabled

            if filter_by == 'Without Code Scanning' and scanning_enabled:
                continue  # Skip if code scanning is enabled and we're filtering for not enabled

            if last_push_date < x_years_ago:
                filtered_repos.append({
                    'name': repo_full_name,
                    'size': repo['size'],  # in KB
                    'last_push': repo['pushed_at'],
                    'forks_count': repo['forks_count'],
                    'open_issues_count': repo['open_issues_count'],
                    'stargazers_count': repo['stargazers_count'],
                    'contributors': get_contributors(org, repo['name']),
                    'languages': get_language_breakdown(org, repo['name']),
                    'scanning_enabled': scanning_enabled,
                    'status': status
                })

        all_repos[org] = filtered_repos
    
    loading = False
    spinner_thread.join()
    return all_repos

def save_results_to_file(results):
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"Results have been saved to {output_file}")

def main():
    try:
        # Load cached data if it exists
        repo_cache = load_cache()

        # Empty cache -> fetch data + save to cache
        if not repo_cache:
            print("No cache found. Fetching data from GitHub...")
            answer = display_menu()
            repo_cache = fetch_data(answer['filter_by'])
            save_cache(repo_cache)
        else:
            print("Loaded data from cache.")
            answer = display_menu()

        # Final results to save + display
        final_results = {}

        for org, repos in repo_cache.items():
            if answer['sort_by'] == 'Sort by Contributors':
                repos.sort(key=lambda x: ', '.join(x.get('contributors', [])))

            # Detailed info about repos
            if repos:
                print(f"\nOrganization: {org}")
                print(f"Total repositories: {len(repos)}")
                final_results[org] = repos
                for repo_info in repos:
                    print(f"Repo: {repo_info['name']}")
                    print(f"  - Size: {repo_info['size']} KB")
                    print(f"  - Last Push: {repo_info['last_push']}")
                    print(f"  - Forks: {repo_info['forks_count']}")
                    print(f"  - Open Issues: {repo_info['open_issues_count']}")
                    print(f"  - Stars: {repo_info['stargazers_count']}")
                    print(f"  - Contributors: {', '.join(repo_info.get('contributors', [])) if repo_info.get('contributors') else 'None found'}")
                    print(f"  - Language Breakdown: {repo_info.get('languages', {})}")
                    print(f"  - Status: {repo_info.get('status', 'Unknown')}")
                    print(f"  - Code Scanning Enabled: {repo_info.get('scanning_enabled', 'N/A')}")
                    print()
            else:
                print(f"\nNo repositories in the organization {org} match the selected criteria.")

        save_results_to_file(final_results)

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
