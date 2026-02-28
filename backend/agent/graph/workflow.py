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
            
        llm = ChatMistralAI(model="mistral-large-latest", temperature=0)
        
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
            sys_msg = SystemMessage(content="You are an AI Vulnerability Analyzer. You have access to the check_cve_database tool. If the code mentions or imports ANY specific libraries (like django), you MUST call check_cve_database FIRST to check for known vulnerabilities. Do NOT guess. After you have received the CVE results from the tool, ONLY THEN should you report findings. CRITICAL: If you find multiple distinct vulnerabilities (e.g., a critical code injection AND a vulnerable dependency from the CVE check), you MUST call the VulnerabilityFinding tool MULTIPLE TIMES, exactly once for each distinct finding. Do not combine them into one finding. Do not reply with regular text.")
            human_msg = HumanMessage(content=f"Analyze this chunk of code:\n\n{chunk['code']}")
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
        for tc in last_msg.tool_calls:
            if tc["name"] == "VulnerabilityFinding":
                try:
                    vf = VulnerabilityFinding(**tc["args"])
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
    return END

# Build the Graph
workflow = StateGraph(AgentState)

tool_node = ToolNode([check_cve_database])

workflow.add_node("chunk_node", chunk_node)
workflow.add_node("analyze_chunk", analyze_chunk)
workflow.add_node("tools", tool_node)
workflow.add_node("save_finding", save_finding)

workflow.set_entry_point("chunk_node")

workflow.add_edge("chunk_node", "analyze_chunk")
workflow.add_conditional_edges("analyze_chunk", should_continue, {
    "save_finding": "save_finding",
    "tools": "tools"
})
workflow.add_edge("tools", "analyze_chunk")
workflow.add_conditional_edges("save_finding", route_after_save, {
    "analyze_chunk": "analyze_chunk",
    END: END
})

app = workflow.compile()

if __name__ == "__main__":
    # Test execution
    test_code = '''
import os
import sqlite3
import hashlib
import subprocess
import pickle
import jwt
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_KEY = "hardcoded_super_secret"
DATABASE = "users.db"


class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path

    def connect(self):
        return sqlite3.connect(self.db_path)

    def get_user(self, username):
        conn = self.connect()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        return result

    def create_user(self, username, password):
        conn = self.connect()
        cursor = conn.cursor()
        hashed = hashlib.md5(password.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed),
        )
        conn.commit()
        conn.close()


class AuthService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def login(self, username, password):
        user = self.db.get_user(username)
        if not user:
            return None

        hashed = hashlib.md5(password.encode()).hexdigest()
        if hashed == user[1]:
            token = jwt.encode({"user": username}, SECRET_KEY, algorithm="HS256")
            return token
        return None

    def verify_token(self, token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return payload["user"]
        except Exception:
            return None


class FileProcessor:
    def __init__(self, upload_folder="uploads"):
        self.upload_folder = upload_folder
        os.makedirs(self.upload_folder, exist_ok=True)

    def save_file(self, file_storage):
        filename = file_storage.filename
        path = os.path.join(self.upload_folder, filename)
        file_storage.save(path)
        return path

    def process_file(self, filepath):
        with open(filepath, "rb") as f:
            data = pickle.load(f)
        return data


class AdminUtils:
    @staticmethod
    def run_diagnostic(command):
        result = subprocess.check_output(command, shell=True)
        return result.decode()


def fetch_external_profile(url):
    response = requests.get(url)
    return response.json()


def generate_reset_token(email):
    raw = email + SECRET_KEY
    return hashlib.sha1(raw.encode()).hexdigest()


@app.route("/login", methods=["POST"])
def login_route():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    db = DatabaseManager(DATABASE)
    auth = AuthService(db)

    token = auth.login(username, password)
    if token:
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/upload", methods=["POST"])
def upload_route():
    file = request.files["file"]
    processor = FileProcessor()
    path = processor.save_file(file)
    content = processor.process_file(path)
    return jsonify({"status": "processed", "content": str(content)})


@app.route("/admin/exec", methods=["POST"])
def admin_exec():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Unauthorized"}), 403

    auth = AuthService(DatabaseManager(DATABASE))
    user = auth.verify_token(token)

    if user != "admin":
        return jsonify({"error": "Forbidden"}), 403

    command = request.json.get("command")
    output = AdminUtils.run_diagnostic(command)
    return jsonify({"output": output})


@app.route("/profile")
def profile_route():
    url = request.args.get("url")
    data = fetch_external_profile(url)
    return jsonify(data)


@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.json.get("email")
    token = generate_reset_token(email)
    return jsonify({"reset_token": token})


def initialize_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT,
            password TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def seed_admin():
    db = DatabaseManager(DATABASE)
    db.create_user("admin", "admin123")


if __name__ == "__main__":
    initialize_database()
    seed_admin()
    app.run(debug=True)
    '''
    initial_state = {
        "files_to_scan": [{"file": "test.py", "code": test_code}],
        "parsed_chunks": [],
        "current_chunk_index": 0,
        "messages": [],
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
        if hasattr(f, 'severity'):
            print(f"\n[{f.severity.upper()}] {f.type} at line {f.line_number}:\n{f.description}")
        else:
            print(f"\n[{f.get('severity', 'high').upper()}] {f.get('type', 'Unknown')} at line {f.get('line_number', 0)}:\n{f.get('description', '')}")
