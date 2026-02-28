import os
from github import Github, Auth
from typing import List, Dict, Any

def fetch_github_repo(repo_url: str) -> List[Dict[str, Any]]:
    """
    Given a GitHub repository URL (e.g., 'https://github.com/Aress07/mistral-hackathon'),
    fetches all python files from the main branch and returns them in the `files_to_scan` format.
    """
    # Clean the URL to get owner/repo
    repo_path = repo_url.replace("https://github.com/", "").replace("http://github.com/", "").strip("/")
    if repo_path.endswith(".git"):
        repo_path = repo_path[:-4]
        
    # Authenticate via environment variable if available, otherwise anonymous (rate limited)
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        auth = Auth.Token(token)
        g = Github(auth=auth)
    else:
        g = Github()
        
    repo = g.get_repo(repo_path)
    
    # We will traverse the file tree starting from the root
    contents = repo.get_contents("")
    files_to_scan = []
    
    while contents:
        file_content = contents.pop(0)
        if file_content.type == "dir":
            contents.extend(repo.get_contents(file_content.path))
        else:
            filename_lower = file_content.name.lower()
            VALID_EXTENSIONS = (
                ".py", ".js", ".jsx", ".ts", ".tsx", ".java", 
                ".cpp", ".hpp", ".cc", ".cxx", ".h", ".c", 
                ".go", ".yaml", ".yml", ".json", ".txt"
            )
            
            is_valid_ext = filename_lower.endswith(VALID_EXTENSIONS)
            is_special_file = "dockerfile" in filename_lower or filename_lower == "makefile"
            
            if is_valid_ext or is_special_file:
                try:
                    code_string = file_content.decoded_content.decode("utf-8")
                    files_to_scan.append({
                        "file": file_content.path,
                        "code": code_string
                    })
                except Exception as e:
                    print(f"Skipping {file_content.path} due to decode error: {e}")
                    
    return files_to_scan
