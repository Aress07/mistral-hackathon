import json
import os
import subprocess
import tempfile
from typing import List, Dict, Any

def run_semgrep_scan(files_to_scan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Takes the fetched files, writes them to a temporary directory, runs Semgrep,
    and returns a list of SAST findings mapped back to the original file paths.
    """
    sast_findings = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # 1. Map temp paths back to the original repo paths
        temp_to_repo_map = {}
        
        for file_info in files_to_scan:
            repo_file_path = file_info.get("file", "")
                
            code = file_info.get("code", "")
            
            # Create a valid temp file name safely
            safe_filename = repo_file_path.replace("/", "_").replace("\\", "_")
            # Preserve original extension so Semgrep knows what language it is
            _, ext = os.path.splitext(repo_file_path)
            if not safe_filename.endswith(ext):
                safe_filename += ext
                
            temp_file_path = os.path.join(temp_dir, safe_filename)
            
            with open(temp_file_path, "w", encoding="utf-8") as f:
                f.write(code)
                
            temp_to_repo_map[temp_file_path] = repo_file_path
            
        if not temp_to_repo_map:
            return sast_findings # No files to scan

        # 2. Run Semgrep
        import sysconfig
        scripts_dir = sysconfig.get_path("scripts", f"{os.name}_user")
        semgrep_bin = os.path.join(scripts_dir, "semgrep.exe" if os.name == "nt" else "semgrep")
        if not os.path.exists(semgrep_bin):
            semgrep_bin = "semgrep" # Fallback if installed globally
            
        env = os.environ.copy()
        if scripts_dir not in env.get("PATH", ""):
            env["PATH"] = scripts_dir + os.pathsep + env.get("PATH", "")
        env["PYTHONIOENCODING"] = "utf8"
        env["PYTHONUTF8"] = "1"
            
        try:
            # We run semgrep recursively on the temp dir, requesting json output
            result = subprocess.run(
                [
                    semgrep_bin, "scan", 
                    "--config=auto", 
                    "--json", 
                    "--quiet",
                    temp_dir
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env
            )
            
            if not result.stdout.strip():
                print(f"Semgrep stderr: {result.stderr}")
                return sast_findings
                
            semgrep_data = json.loads(result.stdout)
            results = semgrep_data.get("results", [])
            
            # 3. Parse and map results back
            for issue in results:
                raw_filename = issue.get("path", "")
                
                # The filename in results is the absolute temp path, which might have backslashes on Windows.
                repo_path = "Unknown"
                
                # Look for matching basename
                issue_basename = os.path.basename(raw_filename.replace("\\", "/"))
                for t_path, r_path in temp_to_repo_map.items():
                    if issue_basename == os.path.basename(t_path.replace("\\", "/")):
                        repo_path = r_path
                        break
                        
                extra = issue.get("extra", {})
                severity_map = {
                    "ERROR": "high",
                    "WARNING": "medium",
                    "INFO": "low"
                }
                
                raw_severity = extra.get("severity", "WARNING")
                mapped_severity = severity_map.get(raw_severity, "medium")
                
                start_line = issue.get("start", {}).get("line", 0)
                end_line = issue.get("end", {}).get("line", start_line)
                            
                sast_findings.append({
                    "file_path": repo_path,
                    "line_number": start_line,
                    "line_range": [start_line, end_line],
                    "severity": mapped_severity,
                    "confidence": "high",
                    "type": issue.get("check_id", "Semgrep Warning"),
                    "description": extra.get("message", ""),
                    "snippet": extra.get("lines", ""),
                    "cwe": extra.get("metadata", {}).get("cwe", {}),
                    "source": "SAST-flagged"
                })
                
        except Exception as e:
            print(f"Error running Semgrep scan: {e}")
            
    return sast_findings
