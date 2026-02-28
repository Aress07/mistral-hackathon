from typing import TypedDict, List, Dict, Any
from pydantic import BaseModel, Field

# 1. Define the schema for what Mistral should output
class VulnerabilityFinding(BaseModel):
    severity: str = Field(description="'critical', 'high', 'medium', or 'low'")
    type: str = Field(description="Short name (e.g., 'SQL Injection')")
    line_number: int = Field(description="Exact line number")
    snippet: str = Field(description="The code snippet")
    description: str = Field(description="Why it is a vulnerability")
    fix_hint: str = Field(description="How to fix it")

# 2. Define the Graph State
class AgentState(TypedDict):
    # Input from the parser
    files_to_scan: List[Dict[str, Any]] # e.g., [{"file": "main.py", "code": "..."}]
    parsed_chunks: List[Dict[str, Any]] # The Tree-sitter chunks
    
    # AI Analysis progress
    current_chunk_index: int
    
    # Output to the frontend/database
    findings: List[VulnerabilityFinding]
    errors: List[str]
    