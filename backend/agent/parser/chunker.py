import ast
from typing import Dict, Any

def chunk_code(file_info: Dict[str, Any]) -> list[Dict[str, Any]]:
    """
    Takes a file entry like {"file": "main.py", "code": "..."}
    and returns a list of chunks, e.g. [{"chunk_id": "main.py:1", "code": "def foo()...", "start_line": 1}].
    If possible uses tree-sitter, falling back to python ast for python files or simple line splitting.
    """
    code = file_info.get("code", "")
    filename = file_info.get("file", "")
    chunks = []
    # Try tree-sitter if available
    try:
        from tree_sitter import Parser
        import tree_sitter_language_pack as tslp
        # If this works, create tree-sitter parser
        parser = tslp.get_parser("python")
        if hasattr(parser, "parse"):
            tree = parser.parse(bytes(code, "utf8"))
        else:
            # Fallback for newer tree_sitter logic if parser is Language
            p = Parser()
            p.set_language(parser)
            tree = p.parse(bytes(code, "utf8"))
        
        # Simple walk to get functions
        def walk(node):
            if node.type in ["function_definition", "class_definition"]:
                start = node.start_point[0] + 1  # 1-indexed
                text = code.encode("utf8")[node.start_byte:node.end_byte].decode("utf8")
                chunks.append({
                    "chunk_id": f"{filename}:{start}",
                    "code": text,
                    "start_line": start,
                    "file": filename,
                    "contributor": file_info.get("contributor", "Unknown"),
                    "contributor_email": file_info.get("contributor_email", "")
                })
            for child in node.children:
                walk(child)
        walk(tree.root_node)
        if chunks:
            return chunks
    except Exception as e:
        pass
        
    # Fallback to python AST
    try:
        if filename.endswith(".py"):
            tree = ast.parse(code)
            lines = code.split('\n')
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = node.lineno
                    end = getattr(node, "end_lineno", start)
                    node_code = "\n".join(lines[start-1:end])
                    chunks.append({
                        "chunk_id": f"{filename}:{start}",
                        "code": node_code,
                        "start_line": start,
                        "file": filename,
                        "contributor": file_info.get("contributor", "Unknown"),
                        "contributor_email": file_info.get("contributor_email", "")
                    })
            if chunks:
                return chunks
    except Exception:
        pass

    # Generic fallback: just return the whole file as one chunk
    return [{
        "chunk_id": f"{filename}:1",
        "code": code,
        "start_line": 1,
        "file": filename,
        "contributor": file_info.get("contributor", "Unknown"),
        "contributor_email": file_info.get("contributor_email", "")
    }]

def chunk_node(state: dict) -> dict:
    """
    LangGraph node: iterates over state["files_to_scan"],
    calls chunk_code, and populates state["parsed_chunks"].
    """
    files = state.get("files_to_scan", [])
    all_chunks = []
    for f in files:
        all_chunks.extend(chunk_code(f))
    
    return {
        "parsed_chunks": all_chunks,
        "current_chunk_index": 0,
        "findings": state.get("findings", []),
        "errors": state.get("errors", [])
    }