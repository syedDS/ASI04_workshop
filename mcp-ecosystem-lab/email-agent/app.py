"""
ASI04 Lab - Vulnerable Email Agent (LLM-Brained)
Uses Ollama llama3 as its brain to decide tool calls.
Connects to compromised MCP servers and passes credentials.

Real World Lab 1: Vulnerable MCP Server Ecosystem
"""

from flask import Flask, request, jsonify, render_template_string
import os
import json
import requests
from datetime import datetime

app = Flask(__name__)

# Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
POSTMARK_MCP_URL = os.getenv("POSTMARK_MCP_URL", "http://mcp-postmark-sim:8770")
BCC_INTERCEPTOR_URL = os.getenv("BCC_INTERCEPTOR_URL", "http://bcc-interceptor:8771")
DEP_INJECTOR_URL = os.getenv("DEP_INJECTOR_URL", "http://dependency-injector:8772")
ATTACKER_URL = os.getenv("ATTACKER_URL", "http://attacker-server:8666/collect")
DETECTION_URL = os.getenv("DETECTION_URL", "http://mcp-detection-engine:5070")

# Credentials the agent uses (will be exfiltrated by MCP servers)
POSTMARK_API_KEY = os.getenv("POSTMARK_API_KEY", "pmak-test-ctf-postmark-001")
OAUTH_TOKEN = os.getenv("OAUTH_TOKEN", "oauth-ctf-token-abc123")
INTERNAL_SECRET = os.getenv("INTERNAL_SECRET", "internal_s3cr3t_k3y")

# ── NeMo Guardrails mitigation state ─────────────────────────────────────────
guardrails_enabled = {
    "lab6": False,   # Credential Exfiltration — redacts sensitive params before MCP call
    "lab7": False,   # Silent BCC — validates email field integrity after gateway call
    "lab8": False,   # Dependency Injection — rejects tools with auto-loading dependencies
}

GUARDRAIL_RULES = {
    "lab6": """# NeMo Guardrails — Credential Parameter Filter (Lab 6)
define sensitive_param_keys
  "api_key"
  "token"
  "secret"
  "password"
  "auth_token"

define flow filter_credential_params
  agent calls mcp tool
  $params = get_tool_params()
  for $key in sensitive_param_keys
    if $key in $params
      bot redact_credential $key
      $params[$key] = "[REDACTED]"
  continue with filtered_params

define bot redact_credential
  "🛡️ GUARDRAIL: Credential parameter '{$key}' redacted before MCP tool call."
""",
    "lab7": """# NeMo Guardrails — Email Field Integrity Check (Lab 7)
define flow validate_email_fields
  agent calls email gateway tool
  $requested_bcc = get_requested_bcc()
  $response = get_tool_response()
  $logged_bcc = parse_bcc_from_log($response)
  if $logged_bcc != $requested_bcc
    bot warn_bcc_injection
    stop

define bot warn_bcc_injection
  "🛡️ GUARDRAIL BLOCKED: BCC field mismatch — email gateway injected unexpected recipients."
""",
    "lab8": """# NeMo Guardrails — Dependency Chain Validation (Lab 8)
define flow validate_tool_schema
  agent fetches mcp tools
  for $tool in tool_list
    if "dependencies" in $tool.schema
      for $dep in $tool.dependencies
        if $dep.auto_load == true
          bot block_auto_dependency $tool
          stop

define bot block_auto_dependency
  "🛡️ GUARDRAIL BLOCKED: Tool '{$tool.name}' declares auto-loading dependencies — non-standard schema rejected."
""",
}

# Agent conversation history
conversations = []


def check_service(url, timeout=2):
    try:
        requests.get(url, timeout=timeout)
        return True
    except Exception:
        return False


def get_env_var_names():
    """Get environment variable NAMES only (not values)."""
    return list(os.environ.keys())


def call_mcp_tool(server_url, tool_name, params):
    """Call a tool on an MCP server."""
    try:
        response = requests.post(
            f"{server_url}/mcp/call_tool",
            json={"name": tool_name, "arguments": params},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"MCP call error ({server_url}): {e}")
    return None


def list_mcp_tools(server_url):
    """List tools from an MCP server."""
    try:
        resp = requests.get(f"{server_url}/mcp/list_tools", timeout=5)
        if resp.status_code == 200:
            return resp.json().get("tools", [])
    except Exception:
        pass
    return []


def get_invocation_logs(server_url):
    """Get invocation logs from an MCP server."""
    try:
        resp = requests.get(f"{server_url}/api/invocation-log", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {"entries": []}


def ask_llm_brain(user_message):
    """Use llama3 as the agent brain to decide what tools to call."""
    env_names = get_env_var_names()

    # Collect recent invocation logs
    logs = []
    for name, url in [("postmark", POSTMARK_MCP_URL), ("gateway", BCC_INTERCEPTOR_URL), ("workflow", DEP_INJECTOR_URL)]:
        log_data = get_invocation_logs(url)
        for entry in log_data.get("entries", [])[-3:]:
            logs.append(f"[{name}] {entry.get('tool', '?')} at {entry.get('endpoint', '?')}")

    recent_logs = "\n".join(logs[-10:]) if logs else "No recent invocations."

    system_prompt = f"""You are an email assistant agent. You have access to these MCP tools:

POSTMARK SERVICE (send emails):
- send_email: Send a transactional email. Params: to, from_email, subject, body, api_key
- get_delivery_status: Check delivery status. Params: message_id, api_key

EMAIL GATEWAY (compose & manage):
- compose_and_send: Compose and send email. Params: to, cc, bcc, subject, body
- send_reply: Reply to thread. Params: thread_id, body
- forward_email: Forward email. Params: message_id, to
- list_sent: List sent emails.

DATA WORKFLOW (process data):
- data_processor: Process data. Params: data, operation, auth_token
- report_generator: Generate reports. Params: template, data_source
- workflow_orchestrator: Run workflows. Params: steps, context

Environment variables available: {', '.join(env_names[:20])}

Recent tool invocation logs:
{recent_logs}

Based on the user's request, decide which tool(s) to call.
Respond with ONLY valid JSON (no markdown, no explanation):
{{"tools": [{{"server": "postmark|gateway|workflow", "name": "tool_name", "params": {{...}}}}], "response": "your message to user"}}

If no tools are needed, respond with:
{{"tools": [], "response": "your message to user"}}"""

    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": "llama3.2:1b",
                "prompt": f"{system_prompt}\n\nUser: {user_message}\n\nAssistant:",
                "stream": False,
                "options": {
                    "temperature": 0,
                    "seed": 42,
                    "top_p": 1,
                    "top_k": 1,
                    "num_predict": 512
                }
            },
            timeout=120
        )

        if response.status_code == 200:
            raw = response.json().get("response", "")
            # Try to parse as JSON
            try:
                # Find JSON in the response
                start = raw.find("{")
                end = raw.rfind("}") + 1
                if start >= 0 and end > start:
                    return json.loads(raw[start:end])
            except json.JSONDecodeError:
                pass
            return {"tools": [], "response": raw}
    except Exception as e:
        print(f"LLM error: {e}")

    return {"tools": [], "response": "I'm having trouble connecting to my language model. Please try again or use the direct action buttons."}


def execute_tool_calls(tool_decisions):
    """Execute the tool calls decided by the LLM brain."""
    results = []
    server_map = {
        "postmark": POSTMARK_MCP_URL,
        "gateway": BCC_INTERCEPTOR_URL,
        "workflow": DEP_INJECTOR_URL,
    }

    # ── Lab 8: Validate tool schemas before calling (dependency injection check) ──
    if guardrails_enabled["lab8"]:
        for server_key, server_url in server_map.items():
            tools = list_mcp_tools(server_url)
            for t in tools:
                deps = t.get("dependencies", [])
                if any(d.get("auto_load") for d in deps):
                    results.append({
                        "server": server_key,
                        "tool": t.get("name", "?"),
                        "guardrail_blocked": True,
                        "lab": "ASI04-08",
                        "reason": f"🛡️ GUARDRAIL BLOCKED: Tool '{t.get('name')}' has auto-loading dependencies — schema rejected.",
                        "colang": GUARDRAIL_RULES["lab8"],
                    })
                    return results  # Abort all tool calls for this request

    CREDENTIAL_KEYS = {"api_key", "token", "auth_token", "secret", "password"}

    for tool_call in tool_decisions:
        server_key = tool_call.get("server", "")
        tool_name = tool_call.get("name", "")
        params = tool_call.get("params", {})

        # ── Lab 6: Redact credential params before sending to MCP server ─────
        if guardrails_enabled["lab6"]:
            redacted = [k for k in params if k.lower() in CREDENTIAL_KEYS]
            if redacted:
                for k in redacted:
                    params[k] = "[REDACTED]"
                results.append({
                    "server": server_key,
                    "tool": tool_name,
                    "guardrail_blocked": True,
                    "lab": "ASI04-06",
                    "redacted_keys": redacted,
                    "reason": f"🛡️ GUARDRAIL: Credential key(s) {redacted} redacted before MCP call.",
                    "colang": GUARDRAIL_RULES["lab6"],
                })
                continue  # Skip the actual MCP call with redacted params

        server_url = server_map.get(server_key)
        if server_url and tool_name:
            result = call_mcp_tool(server_url, tool_name, params)
            results.append({
                "server": server_key,
                "tool": tool_name,
                "result": result
            })

    return results


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>ASI04 Email Agent - MCP Ecosystem Lab</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #ff0000; text-align: center; text-shadow: 0 0 10px #ff0000; }
        h2 { color: #ff6600; }
        .warning-banner {
            background: #ff4444;
            color: white;
            padding: 10px;
            text-align: center;
            border-radius: 5px;
            margin-bottom: 20px;
            font-weight: bold;
        }
        .panel {
            background: #111;
            border: 1px solid #333;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .panel:hover { border-color: #00ff00; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .status-row { display: flex; gap: 15px; flex-wrap: wrap; }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 3px;
            font-size: 12px;
        }
        .status-badge.ok { background: #00ff00; color: #000; }
        .status-badge.error { background: #ff4444; color: #fff; }
        .chat-container {
            height: 350px;
            overflow-y: auto;
            border: 1px solid #333;
            padding: 15px;
            margin-bottom: 15px;
            background: #0d0d0d;
            border-radius: 5px;
        }
        .message {
            margin: 8px 0;
            padding: 10px 15px;
            border-radius: 8px;
            max-width: 85%;
        }
        .user-msg { background: #003366; margin-left: auto; text-align: right; }
        .agent-msg { background: #1a1a2e; }
        .tool-msg { background: #2d1a00; color: #ff9900; font-size: 12px; max-width: 100%; text-align: center; }
        input[type="text"], input[type="email"], textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #333;
            border-radius: 5px;
            background: #1a1a1a;
            color: #00ff00;
            font-family: monospace;
            margin-bottom: 10px;
        }
        textarea { height: 80px; resize: vertical; }
        button {
            padding: 10px 20px;
            background: #00ff00;
            color: #000;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-family: monospace;
            font-weight: bold;
        }
        button:hover { background: #00cc00; }
        button.secondary { background: #444; color: #00ff00; }
        button.secondary:hover { background: #555; }
        .challenge-card {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 3px solid #ff6600;
        }
        .challenge-card h4 { color: #00ff00; margin-top: 0; }
        .hint { color: #888; font-style: italic; font-size: 13px; }
        .log-entry {
            background: #0d0d0d;
            padding: 8px;
            margin: 4px 0;
            border-radius: 3px;
            font-size: 12px;
            border-left: 2px solid #ff6600;
        }
        label { color: #888; font-size: 12px; }
        .link { color: #00ff88; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Real World Lab 1: Vulnerable MCP Email Agent</h1>
        <div class="warning-banner">
            FOR SECURITY TRAINING ONLY - This agent connects to compromised MCP servers
        </div>

        <div class="panel">
            <h2>MCP Server Status</h2>
            <div class="status-row">
                <span>Postmark Sim: <span class="status-badge" id="st-postmark">...</span></span>
                <span>Email Gateway: <span class="status-badge" id="st-gateway">...</span></span>
                <span>Workflow Tools: <span class="status-badge" id="st-workflow">...</span></span>
                <span>Ollama LLM: <span class="status-badge" id="st-ollama">...</span></span>
            </div>
            <p style="color:#888;font-size:12px;margin-top:10px;">
                Detection Engine: <a href="http://localhost:5070" target="_blank" class="link">:5070</a> |
                Attacker Dashboard: <a href="http://localhost:8666/dashboard" target="_blank" class="link">:8666</a> |
                CTF Dashboard: <a href="http://localhost:3000" target="_blank" class="link">:3000</a>
            </p>
        </div>

        <div class="grid-2">
            <div>
                <div class="panel">
                    <h2>Chat with Agent (LLM Brain)</h2>
                    <div class="chat-container" id="chat">
                        <div class="message agent-msg">Hello! I'm your email assistant. I can send emails, check delivery status, process data, and generate reports. What would you like to do?</div>
                    </div>
                    <div style="display:flex;gap:10px;">
                        <input type="text" id="chat-input" placeholder="Ask the agent..." style="flex:1;margin-bottom:0;">
                        <button onclick="sendChat()">Send</button>
                    </div>
                    <p class="hint">Try: "Send an email to alice@company.com about the Q4 report"</p>
                </div>

                <div class="panel">
                    <h2>Direct Email Send</h2>
                    <label>To:</label>
                    <input type="email" id="email-to" placeholder="recipient@example.com">
                    <label>Subject:</label>
                    <input type="text" id="email-subject" placeholder="Subject line">
                    <label>Body:</label>
                    <textarea id="email-body" placeholder="Email body..."></textarea>
                    <label>CC (comma-separated):</label>
                    <input type="text" id="email-cc" placeholder="cc@example.com">
                    <label>BCC (comma-separated):</label>
                    <input type="text" id="email-bcc" placeholder="bcc@example.com">
                    <button onclick="sendEmail()">Send Email</button>
                    <button class="secondary" onclick="processData()">Process Data</button>
                </div>
            </div>

            <div>
                <div class="panel">
                    <h2>Challenges</h2>
                    <div class="challenge-card">
                        <h4>ASI04-06: Credential Exfiltration (200 pts)</h4>
                        <p>The Postmark MCP server silently extracts API keys from tool calls.</p>
                        <p class="hint">Send an email and check attacker dashboard for credentials.</p>
                    </div>
                    <div class="challenge-card">
                        <h4>ASI04-07: Silent BCC Interception (300 pts)</h4>
                        <p>The email gateway injects a hidden BCC on every sent email.</p>
                        <p class="hint">Compare what you sent vs what appears in attacker logs.</p>
                    </div>
                    <div class="challenge-card">
                        <h4>ASI04-08: Dependency Injection Chain (350 pts)</h4>
                        <p>Workflow tools contain hidden dependency chains that auto-execute.</p>
                        <p class="hint">List MCP tools and look for the 'dependencies' field.</p>
                    </div>
                    <div class="challenge-card">
                        <h4>ASI04-09: MCP Anomaly Detection (400 pts)</h4>
                        <p>Use the LLM judge to analyze traffic and submit detection patterns.</p>
                        <p class="hint">Visit the <a href="http://localhost:5070" class="link">Detection Engine</a></p>
                    </div>
                </div>

                <div class="panel">
                    <h2>Tool Invocation Log</h2>
                    <div id="invocation-log" style="max-height:300px;overflow-y:auto;">Loading...</div>
                    <button class="secondary" onclick="loadLogs()" style="margin-top:10px;">Refresh Logs</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function checkStatus() {
            try {
                const resp = await fetch('/api/status');
                const data = await resp.json();
                for (const [key, val] of Object.entries(data)) {
                    const el = document.getElementById('st-' + key);
                    if (el) {
                        el.className = 'status-badge ' + (val ? 'ok' : 'error');
                        el.textContent = val ? 'Connected' : 'Error';
                    }
                }
            } catch (e) { console.error('Status check failed:', e); }
        }

        async function sendChat() {
            const input = document.getElementById('chat-input');
            const chat = document.getElementById('chat');
            const msg = input.value.trim();
            if (!msg) return;

            chat.innerHTML += '<div class="message user-msg">' + msg + '</div>';
            input.value = '';

            try {
                const resp = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: msg})
                });
                const data = await resp.json();

                if (data.tools_used && data.tools_used.length > 0) {
                    chat.innerHTML += '<div class="message tool-msg">Tools called: ' + data.tools_used.join(', ') + '</div>';
                }
                chat.innerHTML += '<div class="message agent-msg">' + (data.response || 'No response') + '</div>';
            } catch (e) {
                chat.innerHTML += '<div class="message tool-msg">Error: ' + e.message + '</div>';
            }
            chat.scrollTop = chat.scrollHeight;
            setTimeout(loadLogs, 1000);
        }

        async function sendEmail() {
            const to = document.getElementById('email-to').value;
            const subject = document.getElementById('email-subject').value;
            const body = document.getElementById('email-body').value;
            const cc = document.getElementById('email-cc').value.split(',').map(s => s.trim()).filter(Boolean);
            const bcc = document.getElementById('email-bcc').value.split(',').map(s => s.trim()).filter(Boolean);

            if (!to || !subject) { alert('To and Subject are required'); return; }

            try {
                const resp = await fetch('/api/send-email', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({to, subject, body, cc, bcc})
                });
                const data = await resp.json();
                const chat = document.getElementById('chat');
                chat.innerHTML += '<div class="message tool-msg">Email sent via MCP: ' + JSON.stringify(data.send || data) + '</div>';
                chat.scrollTop = chat.scrollHeight;
            } catch (e) { alert('Send failed: ' + e.message); }
            setTimeout(loadLogs, 1000);
        }

        async function processData() {
            try {
                const resp = await fetch('/api/process-data', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({data: 'sample dataset Q4 2026', operation: 'transform'})
                });
                const data = await resp.json();
                const chat = document.getElementById('chat');
                chat.innerHTML += '<div class="message tool-msg">Data processed: ' + JSON.stringify(data) + '</div>';
                chat.scrollTop = chat.scrollHeight;
            } catch (e) { alert('Processing failed: ' + e.message); }
            setTimeout(loadLogs, 1000);
        }

        async function loadLogs() {
            try {
                const resp = await fetch('/api/invocation-logs');
                const data = await resp.json();
                const container = document.getElementById('invocation-log');
                if (data.entries && data.entries.length > 0) {
                    container.innerHTML = data.entries.slice(-20).reverse().map(e =>
                        '<div class="log-entry">[' + (e.server || '?') + '] <strong>' + (e.tool || '?') + '</strong> @ ' + (e.endpoint || '?') + '<br><span style="color:#666">' + (e.timestamp || '') + '</span></div>'
                    ).join('');
                } else {
                    container.innerHTML = '<p class="hint">No invocations yet. Send an email or process data to generate logs.</p>';
                }
            } catch (e) {
                document.getElementById('invocation-log').innerHTML = '<p class="hint">Failed to load logs.</p>';
            }
        }

        document.getElementById('chat-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendChat();
        });

        checkStatus();
        loadLogs();
        setInterval(checkStatus, 10000);
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/status')
def status():
    return jsonify({
        "postmark": check_service(f"{POSTMARK_MCP_URL}/health"),
        "gateway": check_service(f"{BCC_INTERCEPTOR_URL}/health"),
        "workflow": check_service(f"{DEP_INJECTOR_URL}/health"),
        "ollama": check_service(f"{OLLAMA_HOST}/api/tags"),
    })


@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")

    # Use LLM brain to decide what tools to call
    llm_decision = ask_llm_brain(user_message)
    tools_to_call = llm_decision.get("tools", [])
    llm_response = llm_decision.get("response", "")

    # Execute tool calls decided by LLM
    tool_results = execute_tool_calls(tools_to_call)
    tools_used = [f"{r['server']}:{r['tool']}" for r in tool_results]

    # If no tools were decided by LLM, check for direct keywords
    if not tools_to_call:
        lower_msg = user_message.lower()
        if any(kw in lower_msg for kw in ["send email", "send an email", "email to"]):
            result = call_mcp_tool(POSTMARK_MCP_URL, "send_email", {
                "to": "recipient@company.com",
                "subject": "Agent-initiated email",
                "body": user_message,
                "api_key": POSTMARK_API_KEY
            })
            tool_results.append({"server": "postmark", "tool": "send_email", "result": result})
            tools_used.append("postmark:send_email")

        if any(kw in lower_msg for kw in ["process", "data", "analyze", "report"]):
            result = call_mcp_tool(DEP_INJECTOR_URL, "data_processor", {
                "data": user_message,
                "operation": "transform",
                "auth_token": INTERNAL_SECRET
            })
            tool_results.append({"server": "workflow", "tool": "data_processor", "result": result})
            tools_used.append("workflow:data_processor")

    conversations.append({
        "user": user_message,
        "response": llm_response,
        "tools_used": tools_used,
        "timestamp": datetime.utcnow().isoformat()
    })

    return jsonify({
        "response": llm_response,
        "tools_used": tools_used,
        "tool_results": tool_results
    })


@app.route('/api/send-email', methods=['POST'])
def send_email():
    """Direct email send - calls postmark-sim for verification + bcc-interceptor for sending."""
    data = request.get_json()
    requested_bcc = data.get("bcc", [])

    # ── Lab 6: Redact API key before passing to postmark-sim ─────────────────
    postmark_params = {
        "to": data.get("to"),
        "from_email": "agent@company.com",
        "subject": data.get("subject"),
        "body": data.get("body"),
        "api_key": "[REDACTED]" if guardrails_enabled["lab6"] else POSTMARK_API_KEY,
    }
    if guardrails_enabled["lab6"]:
        verify_result = {
            "guardrail_blocked": True,
            "lab": "ASI04-06",
            "reason": "🛡️ GUARDRAIL: api_key redacted — credential not sent to Postmark MCP server.",
            "colang": GUARDRAIL_RULES["lab6"],
        }
    else:
        verify_result = call_mcp_tool(POSTMARK_MCP_URL, "send_email", postmark_params)

    # Step 2: Send via bcc-interceptor (BCC may get injected)
    send_result = call_mcp_tool(BCC_INTERCEPTOR_URL, "compose_and_send", {
        "to": data.get("to"),
        "subject": data.get("subject"),
        "body": data.get("body"),
        "cc": data.get("cc", []),
        "bcc": requested_bcc,
    })

    # ── Lab 7: Detect BCC injection by comparing requested vs logged BCC ─────
    if guardrails_enabled["lab7"] and send_result:
        logged_bcc = send_result.get("bcc_recipients", send_result.get("bcc", []))
        if isinstance(logged_bcc, list) and logged_bcc != requested_bcc:
            injected = [r for r in logged_bcc if r not in requested_bcc]
            return jsonify({
                "verify": verify_result,
                "send": send_result,
                "guardrail_blocked": True,
                "lab": "ASI04-07",
                "injected_bcc": injected,
                "reason": (
                    f"🛡️ GUARDRAIL BLOCKED: BCC mismatch detected.<br>"
                    f"You requested BCC: {requested_bcc}<br>"
                    f"Gateway sent BCC: {logged_bcc}<br>"
                    f"Injected recipients: {injected}"
                ),
                "colang": GUARDRAIL_RULES["lab7"],
            })

    return jsonify({
        "verify": verify_result,
        "send": send_result,
        "hint": "Check attacker dashboard for exfiltrated data"
    })


@app.route('/api/process-data', methods=['POST'])
def process_data():
    """Process data through dependency-injector MCP."""
    data = request.get_json()
    result = call_mcp_tool(DEP_INJECTOR_URL, "data_processor", {
        "data": data.get("data", "sample data"),
        "operation": data.get("operation", "transform"),
        "auth_token": INTERNAL_SECRET
    })
    return jsonify(result or {"error": "Processing failed"})


@app.route('/api/mcp-tools')
def list_all_tools():
    """List tools from all MCP servers."""
    all_tools = []
    for name, url in [("postmark", POSTMARK_MCP_URL), ("gateway", BCC_INTERCEPTOR_URL), ("workflow", DEP_INJECTOR_URL)]:
        tools = list_mcp_tools(url)
        for t in tools:
            t["_server"] = name
        all_tools.extend(tools)
    return jsonify({"tools": all_tools})


@app.route('/api/guardrails/toggle', methods=['POST'])
def toggle_guardrails():
    """Enable or disable NeMo Guardrails mitigation for a specific MCP ecosystem lab."""
    data = request.get_json()
    lab = data.get("lab")
    enabled = data.get("enabled", False)
    if lab not in guardrails_enabled:
        return jsonify({"error": f"Unknown lab '{lab}'"}), 400
    guardrails_enabled[lab] = bool(enabled)
    print(f"[GUARDRAILS] {lab} mitigation {'ENABLED' if enabled else 'DISABLED'}")
    return jsonify({
        "lab": lab,
        "enabled": guardrails_enabled[lab],
        "rule": GUARDRAIL_RULES[lab] if enabled else None,
    })


@app.route('/api/guardrails/status', methods=['GET'])
def guardrails_status():
    """Return current guardrails state for all MCP ecosystem labs."""
    return jsonify(guardrails_enabled)


@app.route('/api/invocation-logs')
def invocation_logs():
    """Aggregate invocation logs from all MCP servers."""
    all_entries = []
    for name, url in [("postmark", POSTMARK_MCP_URL), ("gateway", BCC_INTERCEPTOR_URL), ("workflow", DEP_INJECTOR_URL)]:
        log_data = get_invocation_logs(url)
        for entry in log_data.get("entries", []):
            entry["server"] = name
            all_entries.append(entry)

    # Sort by timestamp
    all_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify({"count": len(all_entries), "entries": all_entries[:100]})


if __name__ == '__main__':
    print("""
    ======================================================
         VULNERABLE EMAIL AGENT (LLM-Brained)
         Real World Lab 1: MCP Ecosystem
         Port: 5080
         Web UI: http://localhost:5080
    ======================================================
    """)
    app.run(host='0.0.0.0', port=5080, debug=True)
