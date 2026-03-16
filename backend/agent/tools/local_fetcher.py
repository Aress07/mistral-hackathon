import os
from typing import List, Dict, Any

def fetch_local_repo(repo_path: str) -> List[Dict[str, Any]]:
    """
    Given a local directory path, simulates github fetcher by reading all valid files.
    Skips common ignore directories like .git, venv, node_modules.
    """
    files_to_scan = []
    
    IGNORE_DIRS = {".git", "venv", ".venv", "env", "node_modules", "__pycache__", ".pytest_cache", "reports"}
    VALID_EXTENSIONS = (
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", 
        ".cpp", ".hpp", ".cc", ".cxx", ".h", ".c", 
        ".go", ".yaml", ".yml", ".json", ".txt"
    )
    
    for root, dirs, files in os.walk(repo_path):
        # Modify dirs in-place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            filename_lower = file.lower()
            is_valid_ext = filename_lower.endswith(VALID_EXTENSIONS)
            is_special_file = "dockerfile" in filename_lower or filename_lower == "makefile"
            
            if is_valid_ext or is_special_file:
                file_path = os.path.join(root, file)
                # Make relative to repo root for consistency
                rel_path = os.path.relpath(file_path, repo_path)
                # Convert backslashes to forward slashes for matching github format
                rel_path = rel_path.replace("\\", "/")
                
                # Attempt to get contributor via git
                contributor = "Local User"
                contributor_email = ""
                try:
                    import subprocess
                    # Run git log -1 on the specific file to get the last author
                    # Format %an is Author Name, %ae is Author Email
                    result = subprocess.run(
                        ["git", "log", "-1", "--format=%an|%ae", file_path],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    if result.stdout.strip():
                        parts = result.stdout.strip().split("|")
                        if len(parts) >= 2:
                            contributor = parts[0]
                            contributor_email = parts[1]
                        else:
                            contributor = parts[0]
                except Exception:
                    pass

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        code_string = f.read()
                        
                    files_to_scan.append({
                        "file": rel_path,
                        "code": code_string,
                        "contributor": contributor,
                        "contributor_email": contributor_email
                    })
                except Exception as e:
                    print(f"Skipping {rel_path} due to read error: {e}")
                    
    return files_to_scan
