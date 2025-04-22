import requests
from datetime import datetime

def get_last_commit_for_path(owner, repo, branch="main", folder_path=""):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {
        "sha": branch,    # The branch to search commits in.
        
        # folder_path = "data/certs" for subfolders
        "path": folder_path  # The specific folder or file path.
    }
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        commits = response.json()
        if commits:
            latest_commit = commits[0]
            commit_date = latest_commit['commit']['committer']['date']
            return datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
        else:
            print("No commits found for that folder path.")
    else:
        print(f"Failed to fetch commits. Status code: {response.status_code}")
    return None

# Example usage:
owner = "Mentalistv"
repo = "certChnDscvry"
branch = "sqliteDB"
folder_path = ""  # Change to the folder of interest

# last_commit_datetime = get_last_commit_for_path(owner, repo, branch, folder_path)
# if last_commit_datetime:
#     print(type(last_commit_datetime))
#     print(f"Last commit in folder '{folder_path}' on branch '{branch}': {last_commit_datetime}")
