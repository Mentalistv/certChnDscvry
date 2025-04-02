import requests
import os
import sys

def fetch_der_files(repo_owner, repo_name, branch="main", folder="certs", output_dir="downloaded_certs"):
    try:
        # GitHub API URL to fetch contents of the 'certs' folder
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{folder}?ref={branch}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to fetch contents. Status code: {response.status_code}")
            print(response.json())
            return
        
        files = response.json()
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        for file in files:
            if file["type"] == "file" and file["name"].endswith(".der"):
                file_url = file["download_url"]
                file_path = os.path.join(output_dir, file["name"])
                
                print(f"Downloading {file['name']}...")
                file_response = requests.get(file_url)
                
                if file_response.status_code == 200:
                    with open(file_path, "wb") as f:
                        f.write(file_response.content)
                    print(f"Saved {file_path}")
                else:
                    print(f"Failed to download {file['name']}")
    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <repo_owner> <repo_name> [branch]")
        sys.exit(1)
    
    repo_owner = sys.argv[1]
    repo_name = sys.argv[2]
    branch = sys.argv[3] if len(sys.argv) > 3 else "main"
    
    fetch_der_files(repo_owner, repo_name, branch)
