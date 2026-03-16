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
    verdict: str = Field(description="'True Positive' or 'False Positive'")
    exploit_scenario: str = Field(description="A plain-English exploit scenario specific to this codebase")
    false_positive_rationale: str = Field(default="", description="Rationale if the finding is a false positive")
    fix: str = Field(description="A concrete, copy-paste-ready code fix")
    source: str = Field(description="'SAST-flagged', 'LLM-detected', or 'CVE-matched'")
    contributor: str = Field(default="Unknown", description="The GitHub contributor who wrote this vulnerable code")
    contributor_email: str = Field(default="", description="The email of the contributor")

# 2. Define the Graph State
class AgentState(TypedDict):
    # Input from the parser
    repo_url: str
    files_to_scan: List[Dict[str, Any]] # e.g., [{"file": "main.py", "code": "..."}]
    parsed_chunks: List[Dict[str, Any]] # The Tree-sitter chunks
    
    # SAST scan results
    sast_findings: List[Dict[str, Any]]
    
    # AI Analysis progress
    current_chunk_index: int
    
    # Tool call history
    messages: Annotated[list[BaseMessage], add_messages]
    
    # Output to the frontend/database
    findings: List[VulnerabilityFinding]
    errors: List[str]
    