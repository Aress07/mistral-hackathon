import os
import sys
from dotenv import load_dotenv

# Add the project root to sys.path so 'backend...' modules can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

# Load variables from .env
load_dotenv(os.path.join(os.path.dirname(__file__), "../../../.env"))

from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import SystemMessage, HumanMessage, RemoveMessage

from backend.agent.graph.state import AgentState, VulnerabilityFinding
from backend.agent.parser.chunker import chunk_node
from backend.agent.tools.security_tools import check_cve_database
from backend.agent.tools.sast_scanner import run_semgrep_scan
from backend.agent.graph.report_gen import generate_html_report

from langchain_mistralai import ChatMistralAI

def run_sast_scan(state: AgentState) -> dict:
    """
    LangGraph node: Runs the deterministic Semgrep SAST scanner on the fetched files
    before the LLM begins its chunk-by-chunk analysis.
    """
    files = state.get("files_to_scan", [])
    
    # Run the scanner
    findings = run_semgrep_scan(files)
    
    return {
        "sast_findings": findings
    }

def analyze_chunk(state: AgentState) -> dict:
    """
    LangGraph node that uses Mistral to triage SAST findings and discover logic flaws.
    """
    chunks = state.get("parsed_chunks", [])
    idx = state.get("current_chunk_index", 0)
    messages = list(state.get("messages", []))
    
    if idx >= len(chunks):
        return {}
        
    chunk = chunks[idx]
    
    try:
        if "MISTRAL_API_KEY" not in os.environ or os.environ["MISTRAL_API_KEY"] == "mock_key_for_test":
             raise ValueError("MISTRAL_API_KEY is not set or is still the mock key.")
            
        llm = ChatMistralAI(model="mistral-small-latest", temperature=0)
        
        # Bind BOTH checking the CVE database and the final reporting structure as tools
        # tool_choice="any" forces the model to call AT LEAST ONE tool, ensuring it doesn't fallback to raw text.
        llm_with_tools = llm.bind_tools([check_cve_database, VulnerabilityFinding], tool_choice="any")
        
        # Only inject the initial prompt if we haven't already started analyzing this specific chunk
        needs_prompt = True
        if messages:
            for msg in reversed(messages):
                if isinstance(msg, HumanMessage) and chunk['code'] in str(msg.content):
                    needs_prompt = False
                    break
                    
        new_messages = []
        if needs_prompt:
            # Gather any SAST findings relevant to this specific file
            file_path = chunk.get('file', 'unknown')
            if not file_path.startswith('/'):
                file_path = f"/{file_path}"
                
            sast_findings = state.get("sast_findings", [])
            # Make comparison agnostic to leading slashes
            clean_chunk_path = chunk.get('file', 'unknown').lstrip('/')
            relevant_sast = [f for f in sast_findings if f.get("file_path", "").lstrip('/') == clean_chunk_path]
            
            sast_context = ""
            if relevant_sast:
                sast_context = "### SAST FINDINGS FOR THIS FILE ###\nThe following vulnerabilities were flagged by a deterministic SAST tool (Semgrep) for this file. Evaluate them:\n"
                for i, sf in enumerate(relevant_sast):
                    sast_context += f"[{i+1}] Line {sf['line_number']} (Severity: {sf['severity'].upper()}): {sf['type']} - {sf['description']}\n"
                    if sf['snippet']:
                        sast_context += f"Code:\n{sf['snippet']}\n"
            else:
                sast_context = "### SAST FINDINGS FOR THIS FILE ###\nNo deterministic SAST findings for this file.\n"

            sys_msg = SystemMessage(content=f"""You are an expert AI Vulnerability Triage Agent. 

{sast_context}

YOUR INSTRUCTIONS:
1. PHASE 2a (SAST Triage): If there are SAST findings above, examine them in the context of the provided code chunk. Is each finding a 'True Positive' or a 'False Positive'? (e.g. is the input sanitized nearby?). If True Positive, provide a plain-English exploit scenario specific to this codebase and a concrete fix. Set `source` to 'SAST-flagged'.
2. PHASE 2b (Business Logic): Analyze the code for business logic flaws (access control, role validation, etc.) that SAST cannot see. If found, set `source` to 'LLM-detected'.
3. PHASE 2c (Dependency Check): If the code imports specific libraries, use the `check_cve_database` tool FIRST. If vulnerable, set `source` to 'CVE-matched'.

CRITICAL RULES:
- If you find a true positive (from any phase), you MUST call the VulnerabilityFinding tool EXACTLY ONCE for each distinct finding. Do not combine them.
- File Path required: Provide the full file path ({file_path}) for every finding.
- Do not reply with regular text. Only call tools.
""")
                
            human_msg = HumanMessage(content=f"Code snippet to analyze:\n{chunk['code']}")
            new_messages.extend([sys_msg, human_msg])

            
        invocation_messages = messages + new_messages
        
        import time
        max_retries = 5
        base_delay = 5
        
        for attempt in range(max_retries):
            try:
                result = llm_with_tools.invoke(invocation_messages)
                new_messages.append(result)
                return {"messages": new_messages}
            except Exception as inner_e:
                if "429" in str(inner_e) or "rate_limit" in str(inner_e).lower() or "1300" in str(inner_e):
                    if attempt < max_retries - 1:
                        wait_time = base_delay * (2 ** attempt)
                        time.sleep(wait_time)
                        continue
                raise inner_e
            
    except Exception as e:
        print(f"--- ERROR DURING API INVOCATION ---")
        print(f"{type(e).__name__}: {str(e)}")
        print(f"-----------------------------------")
        
        return {
            "errors": [f"Error analyzing chunk: {str(e)}"],
            # If things break, append a fallback finding and return a message that forces save_finding to complete the chunk
             "messages": [HumanMessage(content=f"API Error. Mocking completion.")] 
        }

def should_continue(state: AgentState) -> str:
    messages = state.get("messages", [])
    if not messages:
        return END
        
    last_msg = messages[-1]
    
    print(f"\n[DEBUG] LLM Message Output:")
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        print(f"   => Called Tools: {[tc['name'] for tc in last_msg.tool_calls]}")
        for tc in last_msg.tool_calls:
            # If it called our final VulnerabilityFinding structure, route out of the loop
            if tc["name"] == "VulnerabilityFinding":
                return "save_finding"
        # Otherwise, route to the standard tools node (check_cve_database)
        return "tools"
    else:
        print(f"   => Text Response: {last_msg.content}")
        
    return "save_finding" # Fallback if it didn't call any tools and just replied

def save_finding(state: AgentState) -> dict:
    """Parses the finding, saves it to state, and clears the message history for the next chunk."""
    messages = state.get("messages", [])
    last_msg = messages[-1] if messages else None
    findings = list(state.get("findings", []))
    idx = state.get("current_chunk_index", 0)
    
    if last_msg and hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        chunks = state.get("parsed_chunks", [])
        current_chunk = chunks[idx] if idx < len(chunks) else {}
        
        for tc in last_msg.tool_calls:
            if tc["name"] == "VulnerabilityFinding":
                try:
                    vf = VulnerabilityFinding(**tc["args"])
                    vf.contributor = current_chunk.get("contributor", "Unknown")
                    vf.contributor_email = current_chunk.get("contributor_email", "")
                    findings.append(vf)
                except Exception:
                    pass
    
    # Delete the message history so the next chunk starts with a fresh context buffer
    delete_msgs = [RemoveMessage(id=m.id) for m in messages if m.id]
    
    return {
        "findings": findings,
        "current_chunk_index": idx + 1,
        "messages": delete_msgs
    }

def route_after_save(state: AgentState) -> str:
    idx = state.get("current_chunk_index", 0)
    chunks = state.get("parsed_chunks", [])
    if idx < len(chunks):
        return "analyze_chunk"
    return "apply_post_scan_fixes"


from backend.agent.graph.post_processor import apply_post_scan_fixes

# Build the Graph
workflow = StateGraph(AgentState)

tool_node = ToolNode([check_cve_database])

workflow.add_node("run_sast_scan", run_sast_scan)
workflow.add_node("chunk_node", chunk_node)
workflow.add_node("analyze_chunk", analyze_chunk)
workflow.add_node("tools", tool_node)
workflow.add_node("save_finding", save_finding)
workflow.add_node("apply_post_scan_fixes", apply_post_scan_fixes)
workflow.add_node("generate_html_report", generate_html_report)

workflow.set_entry_point("run_sast_scan")

workflow.add_edge("run_sast_scan", "chunk_node")
workflow.add_edge("chunk_node", "analyze_chunk")
workflow.add_conditional_edges("analyze_chunk", should_continue, {
    "save_finding": "save_finding",
    "tools": "tools"
})
workflow.add_edge("tools", "analyze_chunk")
workflow.add_conditional_edges("save_finding", route_after_save, {
    "analyze_chunk": "analyze_chunk",
    "apply_post_scan_fixes": "apply_post_scan_fixes"
})
workflow.add_edge("apply_post_scan_fixes", "generate_html_report")
workflow.add_edge("generate_html_report", END)

app = workflow.compile()

from backend.agent.tools.local_fetcher import fetch_local_repo

if __name__ == "__main__":
    # Test execution against the local directory to avoid rate limits
    repo_url = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    
    print(f"Fetching repository files locally from {repo_url}...")
    try:
        scannable_files = fetch_local_repo(repo_url)
        print(f"Found {len(scannable_files)} files to scan.")
    except Exception as e:
        print(f"Failed to fetch local repo: {e}")
        scannable_files = []
        
    initial_state = {
        "repo_url": repo_url,
        "files_to_scan": scannable_files,
        "parsed_chunks": [],
        "current_chunk_index": 0,
        "messages": [],
        "findings": [],
        "errors": []
    }
    
    if scannable_files:
        print("\nRunning graph analysis on the fetched codebase...")
        result = app.invoke(initial_state)
        print("\n--- Execution Complete ---")
        print(f"Total Chunks Analyzed: {len(result['parsed_chunks'])}")
        print(f"Total Findings Detected: {len(result['findings'])}")
        print(f"Errors Encountered: {len(result['errors'])}")
        
        for i, f in enumerate(result['findings']):
            if hasattr(f, 'severity'):
                print(f"\n[{f.severity.upper()}] Finding #{i+1}: {f.type} at line {f.line_number}:\n{f.exploit_scenario}")
            else:
                print(f"\n[{f.get('severity', 'high').upper()}] Finding #{i+1}: {f.get('type', 'Unknown')} at line {f.get('line_number', 0)}:\n{f.get('exploit_scenario', '')}")
    else:
        print("No files to scan. Exiting.")
