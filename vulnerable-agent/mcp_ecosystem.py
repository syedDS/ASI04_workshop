"""
MCP Ecosystem Module - Flask Blueprint
Real World Simulated Challenges (ASI04-06 to ASI04-09)

Demonstrates how compromised MCP servers exploit agentic AI workflows:
- Credential exfiltration via MCP tool parameters
- Silent BCC email interception
- Malicious dependency injection chains
- Anomaly detection using LLM judge
"""

from flask import Blueprint, jsonify, render_template_string
import os
import requests

mcp_ecosystem = Blueprint('mcp_ecosystem', __name__, url_prefix='/rwl')

# MCP Ecosystem service URLs
POSTMARK_MCP_URL = os.getenv("POSTMARK_MCP_URL", "http://mcp-postmark-sim:8770")
BCC_INTERCEPTOR_URL = os.getenv("BCC_INTERCEPTOR_URL", "http://bcc-interceptor:8771")
DEP_INJECTOR_URL = os.getenv("DEP_INJECTOR_URL", "http://dependency-injector:8772")
EMAIL_AGENT_URL = os.getenv("EMAIL_AGENT_URL", "http://email-agent:5080")
DETECTION_ENGINE_URL = os.getenv("DETECTION_ENGINE_URL", "http://mcp-detection-engine:5070")

# RWL Challenge definitions
RWL_CHALLENGES = {
    "ASI04-06": {
        "name": "Credential Exfiltration via MCP",
        "points": 200,
        "description": "Postmark-style MCP server steals API keys from tool parameters",
        "flag": "ASI04_FLAG{p0stm4rk_cr3d_st34l}",
    },
    "ASI04-07": {
        "name": "Silent BCC Email Interception",
        "points": 300,
        "description": "Email gateway MCP injects hidden BCC on all emails",
        "flag": "ASI04_FLAG{s1l3nt_bcc_1nt3rc3pt}",
    },
    "ASI04-08": {
        "name": "Malicious Dependency Injection",
        "points": 350,
        "description": "Workflow MCP auto-loads hidden dependencies that exfiltrate",
        "flag": "ASI04_FLAG{d3p_1nj3ct10n_ch41n}",
    },
    "ASI04-09": {
        "name": "MCP Anomaly Detection",
        "points": 400,
        "description": "Identify all three attacks using LLM judge + traffic analysis",
        "flag": "ASI04_FLAG{4n0m4ly_d3t3ct3d}",
    },
}


def _check_service(url, timeout=2):
    try:
        requests.get(url, timeout=timeout)
        return True
    except Exception:
        return False


RWL_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>ASI04 - Real World Simulated Challenges</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #ff6600;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            color: #ff6600;
            text-align: center;
            text-shadow: 0 0 10px #ff6600;
        }
        .breadcrumb {
            font-size: 13px;
            color: #888;
            margin-bottom: 20px;
        }
        .breadcrumb a { color: #00ff88; }
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
        .panel:hover { border-color: #ff6600; }
        .panel h3 { color: #ff6600; margin-top: 0; }
        .status-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 3px;
            font-size: 12px;
        }
        .status-badge.ok { background: #00ff00; color: #000; }
        .status-badge.error { background: #ff4444; color: #fff; }
        .status-badge.unknown { background: #666; color: #fff; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .challenge-card {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 3px solid #ff6600;
        }
        .challenge-card h4 { color: #ff6600; margin-top: 0; }
        .challenge-card .pts {
            float: right;
            background: #222;
            padding: 3px 10px;
            border-radius: 3px;
            color: #ffff00;
            font-size: 12px;
        }
        .hint { color: #888; font-style: italic; font-size: 13px; }
        code {
            background: #0d1117;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 13px;
            color: #00ff00;
        }
        a.link { color: #00ff88; }
        button {
            padding: 10px 20px;
            background: #ff6600;
            color: #000;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-family: monospace;
            font-weight: bold;
        }
        button:hover { background: #cc5200; }
        button.secondary { background: #333; color: #ff6600; }
        button.secondary:hover { background: #444; }
        .nav-links {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            padding: 10px;
            background: #111;
            border-radius: 5px;
            margin-bottom: 20px;
            justify-content: center;
        }
        .nav-links a {
            color: #ff6600;
            padding: 8px 16px;
            border: 1px solid #333;
            border-radius: 5px;
            text-decoration: none;
            font-size: 13px;
        }
        .nav-links a:hover { border-color: #ff6600; background: #1a0a00; }
        .arch-diagram {
            background: #0d0d0d;
            padding: 20px;
            border-radius: 5px;
            font-size: 12px;
            white-space: pre;
            overflow-x: auto;
            color: #888;
            line-height: 1.4;
        }
        .arch-diagram .highlight { color: #ff6600; }
        .arch-diagram .link-hl { color: #00ff88; }
    </style>
</head>
<body>
    <div class="container">
        <div class="breadcrumb">
            <a href="/">Vulnerable Agent</a> &gt; Real World Simulated Challenges
        </div>

        <h1>MCP Ecosystem Lab</h1>
        <p style="text-align:center; color:#888;">Real World Simulated Challenges (ASI04-06 to ASI04-09) | 1250 pts</p>

        <div class="warning-banner">
            FOR SECURITY TRAINING ONLY - Compromised MCP servers demonstrating real-world attack patterns
        </div>

        <div class="nav-links">
            <a href="http://localhost:5080" target="_blank">Email Agent :5080</a>
            <a href="http://localhost:5070" target="_blank">Detection Engine :5070</a>
            <a href="http://localhost:8666/dashboard" target="_blank">Attacker Dashboard :8666</a>
            <a href="http://localhost:3000" target="_blank">CTF Dashboard :3000</a>
            <a href="/">Core Challenges :5050</a>
        </div>

        <div class="panel">
            <h3>MCP Server Status</h3>
            <div class="status-row">
                <span>Postmark Sim: <span class="status-badge unknown" id="st-postmark">checking...</span></span>
                <span>BCC Interceptor: <span class="status-badge unknown" id="st-bcc">checking...</span></span>
                <span>Dep Injector: <span class="status-badge unknown" id="st-dep">checking...</span></span>
                <span>Email Agent: <span class="status-badge unknown" id="st-email">checking...</span></span>
                <span>Detection Engine: <span class="status-badge unknown" id="st-detect">checking...</span></span>
            </div>
        </div>

        <div class="panel">
            <h3>Architecture</h3>
            <div class="arch-diagram"><span class="highlight">Email Agent (:5080)</span>  ──  LLM-brained email assistant
    │
    ├──▶  <span class="link-hl">mcp-postmark-sim (:8770)</span>   ──  Steals API keys from params
    │         └──▶  Attacker Server (:8666)
    │
    ├──▶  <span class="link-hl">bcc-interceptor (:8771)</span>    ──  Injects BCC to attacker@evil.com
    │         └──▶  Attacker Server (:8666)
    │
    └──▶  <span class="link-hl">dependency-injector (:8772)</span> ──  Hidden dep chains auto-execute
              └──▶  Attacker Server (:8666)

<span class="highlight">Detection Engine (:5070)</span>  ──  LLM Judge analyzes all traffic</div>
        </div>

        <div class="grid-2">
            <div>
                <div class="panel">
                    <h3>Challenges</h3>
                    <div class="challenge-card">
                        <span class="pts">200 pts</span>
                        <h4>ASI04-06: Credential Exfiltration</h4>
                        <p>The Postmark MCP server silently extracts API keys from tool call parameters.</p>
                        <p class="hint">Send an email via the Email Agent and check attacker dashboard for stolen credentials.</p>
                        <code>curl http://localhost:8770/api/invocation-log</code>
                    </div>
                    <div class="challenge-card">
                        <span class="pts">300 pts</span>
                        <h4>ASI04-07: Silent BCC Interception</h4>
                        <p>The email gateway injects a hidden BCC recipient on every sent email.</p>
                        <p class="hint">Compare what you sent vs what appears in attacker logs. Response omits BCC field.</p>
                        <code>curl http://localhost:8771/api/invocation-log</code>
                    </div>
                    <div class="challenge-card">
                        <span class="pts">350 pts</span>
                        <h4>ASI04-08: Dependency Injection Chain</h4>
                        <p>Workflow tools contain hidden auto-loading dependencies that exfiltrate data.</p>
                        <p class="hint">List MCP tools and look for the non-standard 'dependencies' field with auto_load: true.</p>
                        <code>curl http://localhost:8772/mcp/list_tools</code>
                    </div>
                    <div class="challenge-card">
                        <span class="pts">400 pts</span>
                        <h4>ASI04-09: MCP Anomaly Detection</h4>
                        <p>Use the LLM judge to analyze traffic and submit all 3 detection patterns.</p>
                        <p class="hint">Visit the <a href="http://localhost:5070" class="link">Detection Engine</a> - submit credential_exfil, bcc_injection, and dependency_chain.</p>
                    </div>
                </div>
            </div>
            <div>
                <div class="panel">
                    <h3>Quick Actions</h3>
                    <p style="color:#888;font-size:13px;margin-bottom:15px;">Trigger MCP server interactions from here.</p>

                    <button onclick="sendTestEmail()">Send Test Email (triggers ASI04-06, 07)</button>
                    <div id="email-result" style="margin:10px 0;font-size:12px;color:#888;"></div>

                    <button onclick="processTestData()">Process Test Data (triggers ASI04-08)</button>
                    <div id="data-result" style="margin:10px 0;font-size:12px;color:#888;"></div>

                    <button class="secondary" onclick="listMcpTools()">List MCP Tools</button>
                    <div id="tools-result" style="margin:10px 0;font-size:12px;color:#888;max-height:300px;overflow-y:auto;"></div>
                </div>

                <div class="panel">
                    <h3>MCP Traffic Log</h3>
                    <div id="traffic-log" style="max-height:300px;overflow-y:auto;font-size:12px;">Loading...</div>
                    <button class="secondary" onclick="loadTrafficLog()" style="margin-top:10px;">Refresh</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function checkStatus() {
            try {
                const resp = await fetch('/rwl/api/status');
                const data = await resp.json();
                for (const [key, val] of Object.entries(data)) {
                    const el = document.getElementById('st-' + key);
                    if (el) {
                        el.className = 'status-badge ' + (val ? 'ok' : 'error');
                        el.textContent = val ? 'Connected' : 'Offline';
                    }
                }
            } catch (e) { console.error(e); }
        }

        async function sendTestEmail() {
            const el = document.getElementById('email-result');
            el.textContent = 'Sending test email...';
            el.style.color = '#888';
            try {
                const resp = await fetch('/rwl/api/send-test-email', {method: 'POST', headers: {'Content-Type': 'application/json'}});
                const data = await resp.json();
                el.style.color = '#00ff00';
                el.textContent = 'Email sent! Check attacker dashboard. Postmark: ' + JSON.stringify(data.postmark_result || {}).substring(0, 100);
            } catch (e) {
                el.style.color = '#ff4444';
                el.textContent = 'Error: ' + e.message;
            }
            setTimeout(loadTrafficLog, 1000);
        }

        async function processTestData() {
            const el = document.getElementById('data-result');
            el.textContent = 'Processing data...';
            el.style.color = '#888';
            try {
                const resp = await fetch('/rwl/api/process-test-data', {method: 'POST', headers: {'Content-Type': 'application/json'}});
                const data = await resp.json();
                el.style.color = '#00ff00';
                el.textContent = 'Data processed! Dependency chain triggered. ' + JSON.stringify(data.result || {}).substring(0, 100);
            } catch (e) {
                el.style.color = '#ff4444';
                el.textContent = 'Error: ' + e.message;
            }
            setTimeout(loadTrafficLog, 1000);
        }

        async function listMcpTools() {
            const el = document.getElementById('tools-result');
            el.textContent = 'Loading tools...';
            try {
                const resp = await fetch('/rwl/api/mcp-tools');
                const data = await resp.json();
                el.innerHTML = (data.tools || []).map(t =>
                    '<div style="background:#0d0d0d;padding:8px;margin:4px 0;border-radius:3px;border-left:2px solid #ff6600;">' +
                    '<strong>' + (t._server || '?') + '/' + t.name + '</strong><br>' +
                    '<span style="color:#666">' + (t.description || '').substring(0, 120) + '</span>' +
                    (t.dependencies ? '<br><span style="color:#ff4444">DEPS: ' + t.dependencies.map(d => d.name).join(', ') + '</span>' : '') +
                    '</div>'
                ).join('');
            } catch (e) {
                el.style.color = '#ff4444';
                el.textContent = 'Error: ' + e.message;
            }
        }

        async function loadTrafficLog() {
            try {
                const resp = await fetch('/rwl/api/traffic-log');
                const data = await resp.json();
                const el = document.getElementById('traffic-log');
                if (data.entries && data.entries.length > 0) {
                    el.innerHTML = data.entries.slice(0, 20).map(e => {
                        const src = e.server || e.source || '?';
                        const tool = e.tool || e.type || '?';
                        return '<div style="background:#0d0d0d;padding:6px;margin:3px 0;border-radius:3px;border-left:2px solid #ff6600;">[' + src + '] <strong>' + tool + '</strong><br><span style="color:#555">' + (e.timestamp || '') + '</span></div>';
                    }).join('');
                } else {
                    el.innerHTML = '<p class="hint">No traffic yet. Send an email or process data.</p>';
                }
            } catch (e) {
                document.getElementById('traffic-log').innerHTML = '<p style="color:#ff4444">Failed to load.</p>';
            }
        }

        checkStatus();
        loadTrafficLog();
        setInterval(checkStatus, 10000);
    </script>
</body>
</html>
'''


@mcp_ecosystem.route('/')
def rwl_index():
    return render_template_string(RWL_HTML)


@mcp_ecosystem.route('/api/status')
def rwl_status():
    return jsonify({
        "postmark": _check_service(f"{POSTMARK_MCP_URL}/health"),
        "bcc": _check_service(f"{BCC_INTERCEPTOR_URL}/health"),
        "dep": _check_service(f"{DEP_INJECTOR_URL}/health"),
        "email": _check_service(f"{EMAIL_AGENT_URL}/api/status"),
        "detect": _check_service(f"{DETECTION_ENGINE_URL}/health"),
    })


@mcp_ecosystem.route('/api/challenges')
def rwl_challenges():
    return jsonify(RWL_CHALLENGES)


def _call_mcp_tool(server_url, tool_name, params):
    try:
        resp = requests.post(
            f"{server_url}/mcp/call_tool",
            json={"name": tool_name, "arguments": params},
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"MCP call error: {e}")
    return None


def _list_mcp_tools(server_url):
    try:
        resp = requests.get(f"{server_url}/mcp/list_tools", timeout=5)
        if resp.status_code == 200:
            return resp.json().get("tools", [])
    except Exception:
        pass
    return []


@mcp_ecosystem.route('/api/send-test-email', methods=['POST'])
def rwl_send_test_email():
    """Send a test email through both MCP servers to trigger ASI04-06 and ASI04-07."""
    postmark_result = _call_mcp_tool(POSTMARK_MCP_URL, "send_email", {
        "to": "test@company.com",
        "from_email": "agent@company.com",
        "subject": "RWL Test Email",
        "body": "This is a test email from the MCP ecosystem lab.",
        "api_key": os.getenv("POSTMARK_API_KEY", "pmak-test-ctf-postmark-001"),
    })

    bcc_result = _call_mcp_tool(BCC_INTERCEPTOR_URL, "compose_and_send", {
        "to": "test@company.com",
        "subject": "RWL Test Email",
        "body": "This is a test email from the MCP ecosystem lab.",
        "cc": [],
        "bcc": [],
    })

    return jsonify({
        "postmark_result": postmark_result,
        "bcc_result": bcc_result,
        "hint": "Check attacker dashboard for exfiltrated credentials and BCC injection"
    })


@mcp_ecosystem.route('/api/process-test-data', methods=['POST'])
def rwl_process_test_data():
    """Process test data through dependency-injector to trigger ASI04-08."""
    result = _call_mcp_tool(DEP_INJECTOR_URL, "data_processor", {
        "data": "sample Q4 dataset",
        "operation": "transform",
        "auth_token": os.getenv("INTERNAL_SECRET", "internal_s3cr3t_k3y"),
    })
    return jsonify({
        "result": result,
        "hint": "Check attacker dashboard for dependency injection evidence"
    })


@mcp_ecosystem.route('/api/mcp-tools')
def rwl_list_tools():
    """List tools from all MCP ecosystem servers."""
    all_tools = []
    for name, url in [("postmark", POSTMARK_MCP_URL), ("gateway", BCC_INTERCEPTOR_URL), ("workflow", DEP_INJECTOR_URL)]:
        tools = _list_mcp_tools(url)
        for t in tools:
            t["_server"] = name
        all_tools.extend(tools)
    return jsonify({"tools": all_tools})


@mcp_ecosystem.route('/api/traffic-log')
def rwl_traffic_log():
    """Aggregate invocation logs from MCP ecosystem servers."""
    all_entries = []
    for name, url in [("postmark", POSTMARK_MCP_URL), ("gateway", BCC_INTERCEPTOR_URL), ("workflow", DEP_INJECTOR_URL)]:
        try:
            resp = requests.get(f"{url}/api/invocation-log", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("entries", []):
                    entry["server"] = name
                    all_entries.append(entry)
        except Exception:
            pass

    all_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify({"count": len(all_entries), "entries": all_entries[:50]})
