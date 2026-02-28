import os
import sys
from dotenv import load_dotenv

# Add the project root to sys.path so 'backend...' modules can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

# Load variables from .env
load_dotenv(os.path.join(os.path.dirname(__file__), "../../../.env"))

from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, ValidationError

# We import the schema and state
from backend.agent.graph.state import AgentState, VulnerabilityFinding

from backend.agent.parser.chunker import chunk_node

# We need a proper Mistral initialization
from langchain_mistralai import ChatMistralAI

def analyze_chunk(state: AgentState) -> dict:
    """
    LangGraph node that uses Mistral to find vulnerabilities in the current chunk.
    """
    chunks = state.get("parsed_chunks", [])
    idx = state.get("current_chunk_index", 0)
    findings = list(state.get("findings", []))
    errors = list(state.get("errors", []))
    
    if idx >= len(chunks):
        return {"current_chunk_index": idx}
        
    chunk = chunks[idx]
    
    # Optional logic: Use LLM to analyze the code
    try:
        # Initialize mistral
        # Validate that the env variable was properly loaded
        if "MISTRAL_API_KEY" not in os.environ or os.environ["MISTRAL_API_KEY"] == "mock_key_for_test":
             raise ValueError("MISTRAL_API_KEY is not set or is still the mock key.")
            
        llm = ChatMistralAI(model="mistral-large-latest", temperature=0)
        structured_llm = llm.with_structured_output(VulnerabilityFinding)
        
        prompt = f"Analyze the following code for vulnerabilities. If none, return low severity generic finding. Code:\n{chunk['code']}"
        
        # If we have a mock key, this might fail with auth error, so we catch it
        result = structured_llm.invoke(prompt)
        if result:
            findings.append(result)
            
    except Exception as e:
        # fallback for testing if API key is invalid
        print(f"--- ERROR DURING API INVOCATION ---")
        print(f"{type(e).__name__}: {str(e)}")
        print(f"-----------------------------------")
        
        errors.append(f"Error analyzing chunk: {str(e)}")
        # Example finding to show it works
        findings.append(VulnerabilityFinding(
            severity="high",
            type="Mock Injection",
            line_number=chunk.get("start_line", 1),
            snippet=chunk["code"][:20],
            description="Mock finding because API key was not set or valid",
            fix_hint="Set MISTRAL_API_KEY to see real findings"
        ))
        
    return {
        "current_chunk_index": idx + 1,
        "findings": findings,
        "errors": errors
    }

def should_continue(state: AgentState) -> str:
    """
    Conditional edge: return 'analyze_chunk' if there are more chunks, else END.
    """
    idx = state.get("current_chunk_index", 0)
    chunks = state.get("parsed_chunks", [])
    if idx < len(chunks):
        return "analyze_chunk"
    return END

# Build the Graph
workflow = StateGraph(AgentState)

workflow.add_node("chunk_node", chunk_node)
workflow.add_node("analyze_chunk", analyze_chunk)

workflow.set_entry_point("chunk_node")
workflow.add_edge("chunk_node", "analyze_chunk")
workflow.add_conditional_edges("analyze_chunk", should_continue, {
    "analyze_chunk": "analyze_chunk",
    END: END
})

app = workflow.compile()

if __name__ == "__main__":
    # Test execution
    test_code = '''
def dangerous_func(user_input):
    eval(user_input)
    '''
    initial_state = {
        "files_to_scan": [{"file": "test.py", "code": test_code}],
        "parsed_chunks": [],
        "current_chunk_index": 0,
        "findings": [],
        "errors": []
    }
    
    print("Running graph...")
    result = app.invoke(initial_state)
    print("\n--- Execution Complete ---")
    print(f"Chunks parsed: {len(result['parsed_chunks'])}")
    print(f"Findings: {len(result['findings'])}")
    print(f"Errors: {len(result['errors'])}")
    for f in result['findings']:
        # If finding is a dict (fallback case) or pydantic model
        if hasattr(f, 'severity'):
            print(f" - [{f.severity.upper()}] {f.type} at line {f.line_number}: {f.description}")
        else:
            print(f" - [{f.get('severity', 'high').upper()}] {f.get('type', 'Unknown')} at line {f.get('line_number', 0)}: {f.get('description', '')}")
