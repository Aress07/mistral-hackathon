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
from backend.agent.graph.report_gen import generate_html_report

from langchain_mistralai import ChatMistralAI

def analyze_chunk(state: AgentState) -> dict:
    """
    LangGraph node that uses Mistral to analyze code and optionally call tools.
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
            sys_msg = SystemMessage(content="You are an AI Vulnerability Analyzer. You have access to the check_cve_database tool. If the code mentions or imports ANY specific libraries (like django), you MUST call check_cve_database FIRST to check for known vulnerabilities. Do NOT guess. After you have received the CVE results from the tool, ONLY THEN should you report findings. CRITICAL: If you find multiple distinct vulnerabilities (e.g., a critical code injection AND a vulnerable dependency from the CVE check), you MUST call the VulnerabilityFinding tool MULTIPLE TIMES, exactly once for each distinct finding. Do not combine them into one finding. You must include the full file path for every finding you detect. I will provide the filename in the context below. Do not reply with regular text.")
            
            # Format the file path with a leading slash to ensure consistency
            file_path = chunk.get('file', 'unknown')
            if not file_path.startswith('/'):
                file_path = f"/{file_path}"
                
            human_msg = HumanMessage(content=f"File: {file_path}\nCode:\n{chunk['code']}")
            new_messages.extend([sys_msg, human_msg])
            
        invocation_messages = messages + new_messages
        result = llm_with_tools.invoke(invocation_messages)
        new_messages.append(result)
        
        return {"messages": new_messages}
            
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
    return "generate_html_report"

from collections import defaultdict

def notify_contributors(state: AgentState) -> dict:
    """Uses Mistral to auto-draft a warm, helpful 'AI Peer Reviewer' email, then mocks sending it."""
    findings = state.get("findings", [])
    repo_url = state.get("repo_url", "local_repository")
    repo_name = repo_url.rstrip("/").split("/")[-1]
    
    # Group findings sequentially by contributor (Ignore generic fallback unknowns)
    contributors_map = defaultdict(list)
    for f in findings:
        name = getattr(f, "contributor", "Unknown")
        email = getattr(f, "contributor_email", "")
        if name != "Unknown":
            contributors_map[(name, email)].append(f)
            
    if not contributors_map:
        return {} # Exit if no known contributors
        
    print("\n--- Generating 'Helpful Peer' Email Notifications ---")
    
    for (name, email), user_findings in contributors_map.items():
        sys_prompt = SystemMessage(content=(
            "You are a friendly, senior AI developer advocate. Your goal is to support "
            "your teammates by catching potential issues early so they can ship high-quality, "
            "secure code with confidence.\n\n"
            "Draft a helpful email to a team member about code improvements based on findings I provide. "
            "CRITICAL EXCLUSIONS: NEVER use words like 'Vulnerability', 'Bug', 'Error', or 'Fault' in the subject line or opening. "
            "Instead, use positive terms like 'Security Insight', 'Improvement', 'Optimization', or 'Best Practice'.\n\n"
            "Follow this Structure Exactly:\n"
            "Subject: 💡 AI Peer Review: Security Insight for [Repo Name]\n"
            "Greeting: \"Hi [Name]! I'm the AI Security Assistant for the team. I was just doing a routine scan of the latest changes...\"\n"
            "The Value Add: \"I found a small opportunity to strengthen the security of the code in [file_paths]. I've attached a detailed report with a suggested fix to save you some time!\"\n"
            "Closing: \"Keep up the great work on this project! If you have any questions about the suggestion, I'm here to help.\"\n\n"
            "Be supportive, professional, and extremely warm!"
        ))
        
        # Summarize findings for the prompt context
        files_mentioned = set(getattr(f, "file_path", "unknown") for f in user_findings)
        files_str = ", ".join(list(files_mentioned)[:3]) # limit to 3 to not spam the prompt
        if len(files_mentioned) > 3:
            files_str += " and others"
            
        user_msg = HumanMessage(content=f"Draft the email for teammate '{name}'.\nRepository: {repo_name}\nFile Paths to mention: {files_str}")
        
        try:
            response = llm.invoke([sys_prompt, user_msg])
            print("\n================ EMAIL DRAFT ====================")
            print(f"TO: {name} <{email if email else 'No Email Found'}>\n")
            print(response.content)
            print("=================================================\n")
        except Exception as e:
            print(f"Failed to generate email for {name}: {e}")
            
    return {}

# Build the Graph
workflow = StateGraph(AgentState)

tool_node = ToolNode([check_cve_database])

workflow.add_node("chunk_node", chunk_node)
workflow.add_node("analyze_chunk", analyze_chunk)
workflow.add_node("tools", tool_node)
workflow.add_node("save_finding", save_finding)
workflow.add_node("generate_html_report", generate_html_report)
workflow.add_node("notify_contributors", notify_contributors)

workflow.set_entry_point("chunk_node")

workflow.add_edge("chunk_node", "analyze_chunk")
workflow.add_conditional_edges("analyze_chunk", should_continue, {
    "save_finding": "save_finding",
    "tools": "tools"
})
workflow.add_edge("tools", "analyze_chunk")
workflow.add_conditional_edges("save_finding", route_after_save, {
    "analyze_chunk": "analyze_chunk",
    "generate_html_report": "generate_html_report"
})
workflow.add_edge("generate_html_report", "notify_contributors")
workflow.add_edge("notify_contributors", END)

app = workflow.compile()

from backend.agent.tools.github_fetcher import fetch_github_repo

if __name__ == "__main__":
    # Test execution against a very small GitHub directory
    repo_url = "https://github.com/Aress07/Text-Mining"
    
    print(f"Fetching repository files from {repo_url}...")
    try:
        scannable_files = fetch_github_repo(repo_url)
        print(f"Found {len(scannable_files)} files to scan.")
    except Exception as e:
        print(f"Failed to fetch repo: {e}")
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
                print(f"\n[{f.severity.upper()}] Finding #{i+1}: {f.type} at line {f.line_number}:\n{f.description}")
            else:
                print(f"\n[{f.get('severity', 'high').upper()}] Finding #{i+1}: {f.get('type', 'Unknown')} at line {f.get('line_number', 0)}:\n{f.get('description', '')}")
    else:
        print("No files to scan. Exiting.")
