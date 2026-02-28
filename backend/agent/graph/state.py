from typing import TypedDict, List, Dict, Any, Annotated
from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage

# 1. Define the schema for what Mistral should output
class VulnerabilityFinding(BaseModel):
    severity: str = Field(description="'critical', 'high', 'medium', or 'low'")
    type: str = Field(description="Short name (e.g., 'SQL Injection', 'Vulnerable Dependency')")
    file_path: str = Field(description="The full path to the file from the repo root, e.g., '/backend/app/main.py'")
    line_number: int = Field(description="Exact line number")
    snippet: str = Field(description="The code snippet")
    description: str = Field(description="Why it is a vulnerability, including any CVEs found.")
    fix_hint: str = Field(description="How to fix it")

# 2. Define the Graph State
class AgentState(TypedDict):
    # Input from the parser
    repo_url: str
    files_to_scan: List[Dict[str, Any]] # e.g., [{"file": "main.py", "code": "..."}]
    parsed_chunks: List[Dict[str, Any]] # The Tree-sitter chunks
    
    # AI Analysis progress
    current_chunk_index: int
    
    # Tool call history
    messages: Annotated[list[BaseMessage], add_messages]
    
    # Output to the frontend/database
    findings: List[VulnerabilityFinding]
    errors: List[str]
    