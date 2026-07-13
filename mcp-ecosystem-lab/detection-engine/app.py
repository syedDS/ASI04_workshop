"""
ASI04 Lab - Detection Engine (LLM Judge)
Analyzes MCP traffic for anomalous behavior using llama3.
Students must identify attack patterns to capture the flag.

Challenge: ASI04-09 - MCP Anomaly Detection
"""

from flask import Flask, request, jsonify, render_template_string
import os
import json
import requests
from datetime import datetime

app = Flask(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
ATTACKER_SERVER = os.getenv("ATTACKER_SERVER", "http://attacker-server:8666")
POSTMARK_MCP_URL = os.getenv("POSTMARK_MCP_URL", "http://mcp-postmark-sim:8770")
BCC_INTERCEPTOR_URL = os.getenv("BCC_INTERCEPTOR_URL", "http://bcc-interceptor:8771")
DEP_INJECTOR_URL = os.getenv("DEP_INJECTOR_URL", "http://dependency-injector:8772")

DETECTIONS_FILE = "/tmp/asi04_detections.json"


def _load_detections():
    try:
        with open(DETECTIONS_FILE) as f:
            return json.load(f)
    except Exception:
        return {"credential_harvest": False, "bcc_injection": False, "dep_chain": False}


def _save_detections():
    try:
        with open(DETECTIONS_FILE, "w") as f:
            json.dump(detections, f)
    except Exception:
        pass


# Track detections — persisted to /tmp so state survives Flask restarts within the same container
detections = _load_detections()

DETECTION_SIGNATURES = {
    "credential_harvest": {
        "name": "Credential Harvesting via MCP",
        "description": "MCP server extracting API keys, tokens, and secrets from tool call parameters",
        "indicators": [
            "Outbound POST to collection endpoint containing credential data",
            "Tool responses succeed but credentials appear in attacker logs",
            "Environment variable names with KEY/SECRET/TOKEN patterns in exfil data"
        ],
    },
    "bcc_injection": {
        "name": "Silent BCC Email Interception",
        "description": "Email MCP server injecting hidden BCC recipients into outgoing emails",
        "indicators": [
            "BCC field in exfiltrated data differs from BCC in tool response",
            "All sent emails contain an unauthorized recipient address",
            "Response deliberately omits BCC field to hide the injection"
        ],
    },
    "dep_chain": {
        "name": "Malicious Dependency Injection Chain",
        "description": "MCP tool definitions containing hidden dependency references that auto-execute",
        "indicators": [
            "Tool definitions contain non-standard 'dependencies' field with auto_load",
            "Secondary exfiltration payloads tagged as dependency_injection",
            "Internal /internal/dep/ endpoints called during tool execution"
        ],
    }
}

judge_verdicts = []


def get_invocation_logs(server_url):
    try:
        resp = requests.get(f"{server_url}/api/invocation-log", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {"entries": []}


def get_attacker_log():
    try:
        resp = requests.get(f"{ATTACKER_SERVER}/api/log", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {"entries": []}


def ask_llm_judge(logs_text, endpoints_text, env_names_text):
    """Use llama3 as a judge to analyze MCP traffic."""
    judge_prompt = f"""You are a security analyst. Analyze these MCP tool invocation logs for anomalous behavior.

TOOL INVOCATION LOGS:
{logs_text}

MCP ENDPOINTS USED:
{endpoints_text}

ENVIRONMENT VARIABLE NAMES IN LOGS:
{env_names_text}

Identify:
1. Any credential exfiltration patterns (API keys, tokens being sent to external endpoints)
2. Any unauthorized BCC injection (hidden recipients added to emails)
3. Any hidden dependency chain execution (auto-loaded dependencies that exfiltrate data)

For each anomaly found, provide:
- Type: credential_exfil, bcc_injection, or dependency_chain
- Evidence: specific log entries or patterns
- Severity: HIGH, MEDIUM, or LOW

Respond in plain text with clear sections for each anomaly found."""

    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": "llama3.2:1b",
                "prompt": judge_prompt,
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
            return response.json().get("response", "Analysis failed.")
    except Exception as e:
        return f"LLM Judge error: {e}"

    return "Unable to connect to LLM for analysis."


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>ASI04 Detection Engine - MCP Anomaly Detector</title>
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
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #ff0000; text-align: center; text-shadow: 0 0 10px #ff0000; }
        h2 { color: #ff6600; }
        .panel {
            background: #111;
            border: 1px solid #333;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .panel:hover { border-color: #00ff00; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; }
        .detection-card {
            background: #1a1a1a;
            border: 2px solid #333;
            border-radius: 10px;
            padding: 20px;
            transition: all 0.3s;
        }
        .detection-card.detected {
            border-color: #00ff00;
            background: rgba(0, 255, 0, 0.05);
        }
        .detection-card h3 { color: #ff6600; margin-top: 0; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge.detected { background: #00ff00; color: #000; }
        .badge.pending { background: #666; color: #fff; }
        .indicator { color: #888; font-size: 12px; margin: 3px 0; padding-left: 15px; border-left: 2px solid #444; }
        input[type="text"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #333;
            border-radius: 3px;
            background: #0d0d0d;
            color: #00ff00;
            font-family: monospace;
            font-size: 12px;
            margin: 5px 0;
        }
        button {
            padding: 8px 16px;
            background: #00ff00;
            color: #000;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-family: monospace;
            font-weight: bold;
            margin: 3px;
        }
        button:hover { background: #00cc00; }
        button.secondary { background: #444; color: #00ff00; }
        button.secondary:hover { background: #555; }
        button.judge { background: #ff6600; color: #000; }
        button.judge:hover { background: #cc5200; }
        .log-entry {
            background: #0d0d0d;
            padding: 6px 10px;
            margin: 3px 0;
            border-radius: 3px;
            font-size: 11px;
            border-left: 2px solid #ff6600;
            word-break: break-all;
        }
        .flag-panel {
            background: #000;
            border: 3px solid #333;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            font-size: 18px;
        }
        .flag-panel.unlocked {
            border-color: #00ff00;
            background: rgba(0, 255, 0, 0.05);
        }
        .flag-text { color: #00ff00; font-size: 24px; text-shadow: 0 0 10px #00ff00; }
        .judge-output {
            background: #0d0d0d;
            border: 1px solid #333;
            padding: 15px;
            border-radius: 5px;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            font-size: 12px;
            color: #ccc;
        }
        .link { color: #00ff88; }
    </style>
</head>
<body>
    <div class="container">
        <h1>MCP Anomaly Detection Engine</h1>
        <p style="text-align:center;color:#888;">
            Analyze MCP traffic patterns | Identify attack signatures | Capture the detection flag
            <br>Email Agent: <a href="http://localhost:5080" class="link">:5080</a> |
            Attacker Dashboard: <a href="http://localhost:8666/dashboard" class="link">:8666</a>
        </p>

        <div class="grid-2">
            <div class="panel">
                <h2>Traffic Log (from MCP Servers)</h2>
                <div id="traffic-log" style="max-height:350px;overflow-y:auto;">Loading...</div>
                <button class="secondary" onclick="loadTrafficLog()" style="margin-top:10px;">Refresh</button>
            </div>

            <div class="panel">
                <h2>LLM Judge Analysis</h2>
                <p style="color:#888;font-size:12px;">Feed tool invocation logs, MCP endpoints, and env var names to llama3 for anomaly detection.</p>
                <button class="judge" onclick="runJudge()">Run LLM Judge Analysis</button>
                <div id="judge-output" class="judge-output" style="margin-top:10px;">
                    Click "Run LLM Judge Analysis" to analyze the traffic logs for anomalies.
                </div>
            </div>
        </div>

        <h2 style="text-align:center;">Detection Rules</h2>
        <div class="grid-3" id="detection-cards">
            <!-- Credential Harvest -->
            <div class="detection-card" id="card-credential">
                <span class="badge pending" id="badge-credential">PENDING</span>
                <h3>1. Credential Harvesting</h3>
                <p style="font-size:12px;">MCP server extracting API keys and secrets from tool parameters.</p>
                <div>
                    <p style="color:#888;font-size:11px;">Indicators:</p>
                    <div class="indicator">Outbound POST with credential data</div>
                    <div class="indicator">Env var names (KEY/SECRET/TOKEN) in exfil</div>
                    <div class="indicator">Tool succeeds but creds appear in attacker log</div>
                </div>
                <hr style="border-color:#333;">
                <label style="color:#888;font-size:11px;">Anomaly type:</label>
                <input type="text" id="cred-anomaly" placeholder="credential_exfil" value="credential_exfil">
                <label style="color:#888;font-size:11px;">Source MCP:</label>
                <input type="text" id="cred-source" placeholder="postmark_mcp">
                <button onclick="submitDetection('credential-harvest')">Submit Detection</button>
            </div>

            <!-- BCC Injection -->
            <div class="detection-card" id="card-bcc">
                <span class="badge pending" id="badge-bcc">PENDING</span>
                <h3>2. BCC Injection</h3>
                <p style="font-size:12px;">Email MCP injecting hidden BCC recipients.</p>
                <div>
                    <p style="color:#888;font-size:11px;">Indicators:</p>
                    <div class="indicator">BCC field differs between request and exfil</div>
                    <div class="indicator">Unauthorized recipient on all emails</div>
                    <div class="indicator">Response omits BCC field entirely</div>
                </div>
                <hr style="border-color:#333;">
                <label style="color:#888;font-size:11px;">Anomaly type:</label>
                <input type="text" id="bcc-anomaly" placeholder="bcc_injection" value="bcc_injection">
                <label style="color:#888;font-size:11px;">Injected address:</label>
                <input type="text" id="bcc-address" placeholder="attacker-collect@evil.com">
                <button onclick="submitDetection('bcc-inject')">Submit Detection</button>
            </div>

            <!-- Dependency Chain -->
            <div class="detection-card" id="card-dep">
                <span class="badge pending" id="badge-dep">PENDING</span>
                <h3>3. Dependency Chain</h3>
                <p style="font-size:12px;">Hidden dependency references that auto-execute.</p>
                <div>
                    <p style="color:#888;font-size:11px;">Indicators:</p>
                    <div class="indicator">Non-standard 'dependencies' field in tools</div>
                    <div class="indicator">Internal /internal/dep/ calls during execution</div>
                    <div class="indicator">Secondary exfil tagged dependency_injection</div>
                </div>
                <hr style="border-color:#333;">
                <label style="color:#888;font-size:11px;">Anomaly type:</label>
                <input type="text" id="dep-anomaly" placeholder="dependency_chain" value="dependency_chain">
                <label style="color:#888;font-size:11px;">Malicious deps (comma-separated):</label>
                <input type="text" id="dep-names" placeholder="data-validation-lib, report-template-engine, workflow-state-manager">
                <button onclick="submitDetection('dep-chain')">Submit Detection</button>
            </div>
        </div>

        <div class="flag-panel" id="flag-panel">
            <p>FLAG LOCKED - Detect all 3 anomalies to unlock</p>
            <p style="color:#666;font-size:14px;" id="detection-progress">Progress: 0 / 3</p>
        </div>
    </div>

    <script>
        let detectionState = {credential_harvest: false, bcc_injection: false, dep_chain: false};

        async function loadTrafficLog() {
            try {
                const resp = await fetch('/api/traffic-log');
                const data = await resp.json();
                const container = document.getElementById('traffic-log');
                if (data.entries && data.entries.length > 0) {
                    container.innerHTML = data.entries.slice(0, 30).map(e => {
                        const src = e.server || e.source || '?';
                        const tool = e.tool || e.attack_type || '?';
                        const ep = e.endpoint || '';
                        const ts = (e.timestamp || '').substring(0, 19);
                        let color = '#ff6600';
                        if (src === 'postmark' || (e.attack_type || '').includes('credential')) color = '#ff4444';
                        else if (src === 'gateway' || (e.attack_type || '').includes('bcc')) color = '#ff8800';
                        else if (src === 'workflow' || (e.attack_type || '').includes('dep')) color = '#ffcc00';
                        return '<div class="log-entry" style="border-left-color:' + color + '">[' + src + '] <strong>' + tool + '</strong> ' + ep + '<br><span style="color:#555">' + ts + '</span></div>';
                    }).join('');
                } else {
                    container.innerHTML = '<p style="color:#666;">No traffic yet. Use the Email Agent to generate MCP traffic.</p>';
                }
            } catch (e) {
                document.getElementById('traffic-log').innerHTML = '<p style="color:#ff4444;">Failed to load traffic log.</p>';
            }
        }

        async function runJudge() {
            const output = document.getElementById('judge-output');
            output.textContent = 'Running LLM Judge analysis... (this may take a minute)';
            try {
                const resp = await fetch('/api/judge', {method: 'POST'});
                const data = await resp.json();
                output.textContent = data.verdict || 'No verdict returned.';
            } catch (e) {
                output.textContent = 'Judge analysis failed: ' + e.message;
            }
        }

        async function submitDetection(ruleName) {
            let payload = {};
            if (ruleName === 'credential-harvest') {
                payload = {
                    anomaly: document.getElementById('cred-anomaly').value,
                    source: document.getElementById('cred-source').value
                };
            } else if (ruleName === 'bcc-inject') {
                payload = {
                    anomaly: document.getElementById('bcc-anomaly').value,
                    injected_address: document.getElementById('bcc-address').value
                };
            } else if (ruleName === 'dep-chain') {
                payload = {
                    anomaly: document.getElementById('dep-anomaly').value,
                    malicious_deps: document.getElementById('dep-names').value.split(',').map(s => s.trim()).filter(Boolean)
                };
            }

            try {
                const resp = await fetch('/api/detect/' + ruleName, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const data = await resp.json();

                if (data.detected) {
                    updateDetectionUI(ruleName, true);
                }
                if (data.flag) {
                    showFlag(data.flag);
                }
                alert(data.message || JSON.stringify(data));
            } catch (e) {
                alert('Submission failed: ' + e.message);
            }
        }

        function updateDetectionUI(ruleName, detected) {
            const mapping = {
                'credential-harvest': {card: 'card-credential', badge: 'badge-credential', key: 'credential_harvest'},
                'bcc-inject': {card: 'card-bcc', badge: 'badge-bcc', key: 'bcc_injection'},
                'dep-chain': {card: 'card-dep', badge: 'badge-dep', key: 'dep_chain'}
            };
            const m = mapping[ruleName];
            if (m && detected) {
                document.getElementById(m.card).classList.add('detected');
                document.getElementById(m.badge).className = 'badge detected';
                document.getElementById(m.badge).textContent = 'DETECTED';
                detectionState[m.key] = true;
            }
            const count = Object.values(detectionState).filter(Boolean).length;
            document.getElementById('detection-progress').textContent = 'Progress: ' + count + ' / 3';
        }

        function showFlag(flag) {
            const panel = document.getElementById('flag-panel');
            panel.classList.add('unlocked');
            panel.innerHTML = '<p class="flag-text">FLAG CAPTURED!</p><p class="flag-text">' + flag + '</p>';
        }

        async function checkDetectionState() {
            try {
                const resp = await fetch('/api/detection-state');
                const data = await resp.json();
                for (const [rule, detected] of Object.entries(data.detections || {})) {
                    if (detected) {
                        const ruleMap = {credential_harvest: 'credential-harvest', bcc_injection: 'bcc-inject', dep_chain: 'dep-chain'};
                        updateDetectionUI(ruleMap[rule], true);
                    }
                }
                if (data.flag) showFlag(data.flag);
            } catch (e) {}
        }

        loadTrafficLog();
        checkDetectionState();
        setInterval(loadTrafficLog, 10000);
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/health')
def health():
    return jsonify({"status": "healthy", "detections": detections})


@app.route('/api/traffic-log')
def traffic_log():
    """Aggregate traffic from MCP invocation logs + attacker server."""
    all_entries = []

    # Get MCP invocation logs
    for name, url in [("postmark", POSTMARK_MCP_URL), ("gateway", BCC_INTERCEPTOR_URL), ("workflow", DEP_INJECTOR_URL)]:
        try:
            resp = requests.get(f"{url}/api/invocation-log", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("entries", []):
                    entry["server"] = name
                    entry["source"] = "mcp_invocation"
                    all_entries.append(entry)
        except Exception:
            pass

    # Get attacker server log
    attacker_data = get_attacker_log()
    for entry in attacker_data.get("entries", []):
        entry["source"] = "attacker_exfil"
        all_entries.append(entry)

    all_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify({"count": len(all_entries), "entries": all_entries[:100]})


@app.route('/api/judge', methods=['POST'])
def run_judge():
    """Run LLM judge analysis on collected traffic."""
    # Collect invocation logs
    logs_text_parts = []
    endpoints_set = set()
    env_names_set = set()

    for name, url in [("postmark", POSTMARK_MCP_URL), ("gateway", BCC_INTERCEPTOR_URL), ("workflow", DEP_INJECTOR_URL)]:
        try:
            resp = requests.get(f"{url}/api/invocation-log", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("entries", [])[-10:]:
                    logs_text_parts.append(
                        f"[{name}] Tool: {entry.get('tool', '?')}, "
                        f"Endpoint: {entry.get('endpoint', '?')}, "
                        f"Params: {json.dumps(entry.get('params', {}))[:200]}"
                    )
                    if entry.get("endpoint"):
                        endpoints_set.add(entry["endpoint"])
                    for env_name in entry.get("env_var_names", []):
                        env_names_set.add(env_name)
                    # Check for BCC injection evidence
                    if entry.get("bcc_injected"):
                        logs_text_parts.append(f"  >> BCC injected: {entry['bcc_injected']}")
                    if entry.get("dependency_chain"):
                        logs_text_parts.append(f"  >> Dependency chain triggered by: {entry.get('parent_tool', '?')}")
        except Exception:
            pass

    # Also check attacker log for exfil evidence
    attacker_data = get_attacker_log()
    for entry in attacker_data.get("entries", [])[-10:]:
        attack_type = entry.get("attack_type", "unknown")
        logs_text_parts.append(f"[attacker] Type: {attack_type}, Data keys: {list(entry.get('data', {}).keys())[:5]}")

    logs_text = "\n".join(logs_text_parts) if logs_text_parts else "No logs available yet."
    endpoints_text = "\n".join(endpoints_set) if endpoints_set else "No endpoints recorded."
    env_names_text = ", ".join(list(env_names_set)[:30]) if env_names_set else "No env var names recorded."

    verdict = ask_llm_judge(logs_text, endpoints_text, env_names_text)
    judge_verdicts.append({
        "timestamp": datetime.utcnow().isoformat(),
        "verdict": verdict
    })

    return jsonify({"verdict": verdict, "logs_analyzed": len(logs_text_parts)})


@app.route('/api/detect/credential-harvest', methods=['POST'])
def detect_credential_harvest():
    data = request.get_json()
    if data.get("anomaly") == "credential_exfil" and data.get("source") == "postmark_mcp":
        detections["credential_harvest"] = True
        _save_detections()
        return _check_all_detected("Credential harvesting pattern correctly identified!")
    return jsonify({"detected": False, "message": "Incorrect detection. Check the anomaly type and source MCP server name."})


@app.route('/api/detect/bcc-inject', methods=['POST'])
def detect_bcc_inject():
    data = request.get_json()
    if data.get("anomaly") == "bcc_injection" and data.get("injected_address") == "attacker-collect@evil.com":
        detections["bcc_injection"] = True
        _save_detections()
        return _check_all_detected("BCC injection pattern correctly identified!")
    return jsonify({"detected": False, "message": "Incorrect detection. Check the anomaly type and the injected email address."})


@app.route('/api/detect/dep-chain', methods=['POST'])
def detect_dep_chain():
    data = request.get_json()
    required_deps = {"data-validation-lib", "report-template-engine", "workflow-state-manager"}
    submitted_deps = set(data.get("malicious_deps", []))
    if data.get("anomaly") == "dependency_chain" and required_deps.issubset(submitted_deps):
        detections["dep_chain"] = True
        _save_detections()
        return _check_all_detected("Dependency injection chain correctly identified!")
    return jsonify({"detected": False, "message": "Incorrect detection. Check the anomaly type and list all three malicious dependencies."})


def _check_all_detected(success_msg):
    if all(detections.values()):
        # Post flag to attacker server
        try:
            requests.post(f"{ATTACKER_SERVER}/collect", json={
                "type": "detection_complete",
                "source": "detection_engine",
                "data": {
                    "flag": "ASI04_FLAG{4n0m4ly_d3t3ct3d}",
                    "all_detections": detections,
                    "challenge": "ASI04-09"
                }
            }, timeout=5)
        except Exception:
            pass
        return jsonify({
            "detected": True,
            "message": f"{success_msg} ALL ANOMALIES DETECTED!",
            "flag": "ASI04_FLAG{4n0m4ly_d3t3ct3d}"
        })
    count = sum(1 for v in detections.values() if v)
    return jsonify({"detected": True, "message": f"{success_msg} ({count}/3 detected)"})


@app.route('/api/detection-state')
def detection_state():
    all_detected = all(detections.values())
    return jsonify({
        "detections": detections,
        "flag": "ASI04_FLAG{4n0m4ly_d3t3ct3d}" if all_detected else None
    })


if __name__ == '__main__':
    print("""
    ======================================================
         MCP ANOMALY DETECTION ENGINE (LLM Judge)
         Real World Lab 1: MCP Ecosystem
         Port: 5070
         Web UI: http://localhost:5070
    ======================================================
    """)
    app.run(host='0.0.0.0', port=5070, debug=True)
