import os
import markdown
from datetime import datetime
from backend.agent.graph.state import AgentState

def generate_html_report(state: AgentState) -> dict:
    """
    LangGraph node that generates a styled HTML report from the final findings.
    """
    findings = state.get("findings", [])
    files_to_scan = state.get("files_to_scan", [])
    repo_url = state.get("repo_url", "")
    
    # Extract the repository name from the URL safely, or default to "local_scan"
    repo_name = "local_scan"
    if repo_url:
        repo_name = os.path.basename(os.path.normpath(repo_url))
    
    total_files = len(files_to_scan)
    total_findings = len(findings)
    
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for f in findings:
        sev = f.severity.lower() if hasattr(f, 'severity') else f.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["low"] += 1
            
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{repo_name} Security Audit Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --container-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --critical: #ff4b2b;
            --high: #ff8c00;
            --medium: #ffd700;
            --low: #1e90ff;
            --code-bg: #0b1120;
        }}

        body {{
            font-family: system-ui, -apple-system, 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2rem 1rem;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}

        header {{
            border-bottom: 1px solid #334155;
            padding-bottom: 2rem;
            margin-bottom: 2rem;
            text-align: center;
        }}

        h1 {{
            font-size: 2.5rem;
            margin: 0 0 0.5rem 0;
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .timestamp {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        /* Dashboard specific */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }}

        .stat-card {{
            background: var(--container-bg);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #334155;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        .stat-card h3 {{
            margin: 0 0 0.5rem 0;
            color: var(--text-muted);
            font-size: 0.9rem;
            text-transform: uppercase;
        }}

        .stat-card .value {{
            font-size: 2rem;
            font-weight: bold;
        }}

        /* Colors for stats */
        .val-total {{ color: var(--text-main); }}
        .val-files {{ color: var(--accent); }}
        .val-critical {{ color: var(--critical); text-shadow: 0 0 10px rgba(255, 75, 43, 0.5); }}
        .val-high {{ color: var(--high); }}
        .val-medium {{ color: var(--medium); }}
        .val-low {{ color: var(--low); }}

        /* Findings List */
        .findings-section h2 {{
            border-bottom: 1px solid #334155;
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
        }}

        .finding-card {{
            background: var(--container-bg);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid #334155;
            border-left: 5px solid #334155; /* Default fallback */
            position: relative;
        }}
        
        .finding-card.sev-critical {{ border-left-color: var(--critical); box-shadow: -2px 0 15px rgba(255,75,43,0.15); }}
        .finding-card.sev-high {{ border-left-color: var(--high); box-shadow: -2px 0 15px rgba(255,140,0,0.1); }}
        .finding-card.sev-medium {{ border-left-color: var(--medium); }}
        .finding-card.sev-low {{ border-left-color: var(--low); }}

        .finding-card.fp-true {{
            opacity: 0.7;
            border-left-color: #64748b;
            background: #0f172a;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}

        .finding-title {{
            font-size: 1.25rem;
            margin: 0;
            font-weight: 600;
        }}

        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .badge-critical {{ background: rgba(255,75,43,0.15); color: var(--critical); border: 1px solid var(--critical); box-shadow: 0 0 10px rgba(255,75,43,0.3); }}
        .badge-high {{ background: rgba(255,140,0,0.15); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(255,215,0,0.15); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(30,144,255,0.15); color: var(--low); border: 1px solid var(--low); }}
        
        .badge-tp {{ background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid #ef4444; }}
        .badge-fp {{ background: rgba(34,197,94,0.2); color: #86efac; border: 1px solid #22c55e; }}
        .badge-source {{ background: #334155; color: #cbd5e1; border: 1px solid #475569; }}

        .finding-meta {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 1rem;
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }}

        .finding-desc {{
            margin-bottom: 1.5rem;
        }}

        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: var(--code-bg);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}

        pre {{
            background: var(--code-bg);
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid #1e293b;
        }}
        
        pre code {{
            background: none;
            padding: 0;
            font-size: 0.9rem;
        }}

        .fix-hint {{
            background: rgba(56, 189, 248, 0.05);
            border-left: 3px solid var(--accent);
            padding: 1rem;
            margin-top: 1rem;
            border-radius: 0 4px 4px 0;
        }}
        
        .fix-hint h4 {{
            margin: 0 0 0.5rem 0;
            color: var(--accent);
            font-size: 0.9rem;
        }}
        .fix-hint p {{
            margin: 0;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{repo_name} Security Audit</h1>
            <div class="timestamp">Generated on {timestamp}</div>
        </header>

        <div class="dashboard">
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <div class="value val-files">{total_files}</div>
            </div>
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="value val-total">{total_findings}</div>
            </div>
            <div class="stat-card">
                <h3>Critical</h3>
                <div class="value val-critical">{counts['critical']}</div>
            </div>
            <div class="stat-card">
                <h3>High</h3>
                <div class="value val-high">{counts['high']}</div>
            </div>
            <div class="stat-card">
                <h3>Medium</h3>
                <div class="value val-medium">{counts['medium']}</div>
            </div>
            <div class="stat-card">
                <h3>Low</h3>
                <div class="value val-low">{counts['low']}</div>
            </div>
        </div>

        <div class="findings-section">
            <h2>Detailed Findings</h2>
"""

    if not findings:
        html_content += """
            <div class="finding-card sev-low">
                <div class="finding-desc">No vulnerabilities detected.</div>
            </div>
"""
    else:
        for idx, f in enumerate(findings):
            sev = f.severity.lower() if hasattr(f, 'severity') else f.get("severity", "low").lower()
            title = f.type if hasattr(f, 'type') else f.get("type", "Unknown Vulnerability")
            line = f.line_number if hasattr(f, 'line_number') else f.get("line_number", 0)
            snippet = f.snippet if hasattr(f, 'snippet') else f.get("snippet", "")
            file_path = f.file_path if hasattr(f, 'file_path') else f.get("file_path", "Unknown File")
            
            # Additional Context fields
            verdict = f.verdict if hasattr(f, 'verdict') else f.get("verdict", "True Positive")
            
            exploit_scenario = f.exploit_scenario if hasattr(f, 'exploit_scenario') else f.get("exploit_scenario", "")
            if exploit_scenario:
                exploit_scenario = markdown.markdown(exploit_scenario, extensions=['fenced_code', 'tables'])
                
            fix = f.fix if hasattr(f, 'fix') else f.get("fix", "")
            if fix:
                fix = markdown.markdown(fix, extensions=['fenced_code', 'tables'])
                
            source = f.source if hasattr(f, 'source') else f.get("source", "Unknown")
            contributor = f.contributor if hasattr(f, 'contributor') else f.get("contributor", "Unknown")
            
            # format the file path to ensure it has leading slash
            if not file_path.startswith('/'):
                file_path = '/' + file_path
                
            # Map valid severities to css classes
            if sev not in ['critical', 'high', 'medium', 'low']:
                sev = 'low'
                
            is_fp = verdict.lower() == "false positive"
            card_class = f"finding-card sev-{sev}" + (" fp-true" if is_fp else "")
            verdict_badge = "badge-fp" if is_fp else "badge-tp"
                
            html_content += f"""
            <div class="{card_class}">
                <div class="finding-header">
                    <h3 class="finding-title" style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">{file_path} : Line {line}</h3>
                    <div>
                        <span class="badge {verdict_badge}">{verdict.upper()}</span>
                        <span class="badge badge-{sev}">{sev.upper()}</span>
                    </div>
                </div>
                <div class="finding-meta">
                    <span><strong>Vulnerability:</strong> {title}</span>
                    <span><span class="badge badge-source">{source}</span></span>
                    <span><strong>Contributor:</strong> {contributor}</span>
                </div>
                """
                
            if exploit_scenario and not is_fp:
                html_content += f"""
                <div class="finding-desc"><strong>Exploit Scenario:</strong><br/>{exploit_scenario}</div>
                """
            elif exploit_scenario and is_fp:
                 html_content += f"""
                <div class="finding-desc"><strong>False Positive Rationale:</strong><br/>{exploit_scenario}</div>
                """
                
            if snippet:
                snippet_escaped = snippet.replace("<", "&lt;").replace(">", "&gt;")
                html_content += f"""
                <pre><code>{snippet_escaped}</code></pre>
                """
                
            if fix:
                html_content += f"""
                <div class="fix-hint">
                    <h4>Recommended Fix</h4>
                    <div class="markdown-content">{fix}</div>
                </div>
                """
                
            html_content += """
            </div>
            """

    html_content += """
        </div>
    </div>
</body>
</html>
"""

    date_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    filename = f"{repo_name}_{date_str}.html"

    # Directory math: backend/agent/graph -> ../../../ equals the mistral-hackathon root folder
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../reports"))
    
    # Create the reports directory if it doesn't already exist
    os.makedirs(root_dir, exist_ok=True)
    
    report_path = os.path.join(root_dir, filename)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"\n[+] Security HTML Report generated successfully at: {report_path}")
        
    return {}
