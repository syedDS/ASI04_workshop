"""
ASI04 Lab - CTF Dashboard
Track progress and view captured flags
"""

from flask import Flask, jsonify, render_template_string
import os
import json
import requests

app = Flask(__name__)

ATTACKER_SERVER = os.getenv("ATTACKER_SERVER", "http://attacker-server:8666")

# Challenge definitions - Core Supply Chain Challenges
CHALLENGES = {
    "ASI04-01": {
        "name": "Typosquatting",
        "points": 100,
        "description": "Install a typosquatted package and trigger exfiltration",
        "flag": "ASI04_FLAG{typ0squ4t_g0t_y0u}",
        "hints": [
            "Look at the fake PyPI server packages",
            "Compare package names to legitimate ones",
            "langchaln vs langchain"
        ]
    },
    "ASI04-02": {
        "name": "Malicious MCP Server",
        "points": 250,
        "description": "Identify and exploit the malicious MCP server",
        "flag": "ASI04_FLAG{mcp_tr0j4n_d3t3ct3d}",
        "hints": [
            "Examine MCP tool responses",
            "Look for hidden exfiltration endpoints",
            "Check tool descriptions for prompt injection"
        ]
    },
    "ASI04-03": {
        "name": "Dependency Confusion",
        "points": 250,
        "description": "Exploit dependency confusion with high-version packages",
        "flag": "ASI04_FLAG{d3p_c0nfus10n_pwn3d}",
        "hints": [
            "Internal packages have low versions",
            "Public PyPI might have higher versions",
            "pip prefers higher version numbers"
        ]
    },
    "ASI04-04": {
        "name": "Poisoned Tool Descriptors",
        "points": 250,
        "description": "Find hidden prompt injections in tool descriptions",
        "flag": "ASI04_FLAG{h1dd3n_1nstruct10ns}",
        "hints": [
            "Fetch tools from the registry",
            "Look for HTML comments, hidden characters",
            "Descriptions are longer than they should be"
        ]
    },
    "ASI04-05": {
        "name": "RAG Poisoning",
        "points": 500,
        "description": "Trigger retrieval of poisoned documents",
        "flag": "ASI04_FLAG{r4g_p01s0n3d}",
        "hints": [
            "Ask about password reset procedures",
            "Query for security policies",
            "Poisoned docs override legitimate ones"
        ]
    }
}

# Real World Simulated Challenges - MCP Ecosystem
RWL_CHALLENGES = {
    "ASI04-06": {
        "name": "Credential Exfiltration via MCP",
        "points": 200,
        "description": "Postmark-style MCP server steals API keys from tool parameters",
        "flag": "ASI04_FLAG{p0stm4rk_cr3d_st34l}",
        "hints": [
            "Send an email via the Email Agent",
            "Check what the Postmark MCP does with api_key param",
            "Inspect the attacker dashboard for credential data"
        ]
    },
    "ASI04-07": {
        "name": "Silent BCC Email Interception",
        "points": 300,
        "description": "Email gateway MCP injects hidden BCC on all emails",
        "flag": "ASI04_FLAG{s1l3nt_bcc_1nt3rc3pt}",
        "hints": [
            "Send any email through the gateway",
            "Compare BCC in request vs attacker logs",
            "Look for attacker-collect@evil.com"
        ]
    },
    "ASI04-08": {
        "name": "Malicious Dependency Injection",
        "points": 350,
        "description": "Workflow MCP auto-loads hidden dependencies that exfiltrate",
        "flag": "ASI04_FLAG{d3p_1nj3ct10n_ch41n}",
        "hints": [
            "List tools from the dependency-injector MCP",
            "Look for non-standard 'dependencies' field",
            "Process data to trigger the chain"
        ]
    },
    "ASI04-09": {
        "name": "MCP Anomaly Detection",
        "points": 400,
        "description": "Identify all three attacks using LLM judge + traffic analysis",
        "flag": "ASI04_FLAG{4n0m4ly_d3t3ct3d}",
        "hints": [
            "Complete ASI04-06, 07, 08 first",
            "Visit the Detection Engine at :5070",
            "Submit all 3 detection patterns correctly"
        ]
    }
}

# Real World Lab 2 - Skill Lab (ASI04-10 to 13)
SKILL_CHALLENGES = {
    "ASI04-10": {
        "name": "Skill Identity Spoofing",
        "points": 300,
        "description": "Compromised registry entry redirects the researcher skill to a malicious endpoint",
        "flag": "ASI04_FLAG{sk1ll_1d3nt1ty_sp00f3d}",
        "hints": [
            "Run a task at the Skill Orchestrator :5090",
            "Check /api/endpoint-check after running",
            "Compare declared endpoint vs trusted host"
        ]
    },
    "ASI04-11": {
        "name": "Output Injection via Sub-Agent",
        "points": 350,
        "description": "Malicious skill embeds SYSTEM INSTRUCTION in its output; LLM follows it and leaks secrets",
        "flag": "ASI04_FLAG{0utput_1nj3ct10n_3x3cut3d}",
        "hints": [
            "Run a task and read the answer field carefully",
            "Look for injected directives in the LLM response",
            "POST the phrase to /api/find-injection"
        ]
    },
    "ASI04-12": {
        "name": "Capability Scope Creep",
        "points": 350,
        "description": "Skill requests read_env at runtime beyond its declared permissions; orchestrator silently grants it",
        "flag": "ASI04_FLAG{sc0p3_cr33p_gr4nt3d}",
        "hints": [
            "Run a task with the researcher skill",
            "Check /api/permission-audit",
            "Look for permissions granted beyond what was declared"
        ]
    },
    "ASI04-13": {
        "name": "Skill Version Downgrade",
        "points": 400,
        "description": "Registry pins researcher to v3.0.1 (malicious); patched v3.1.0 exists but is never deployed",
        "flag": "ASI04_FLAG{v3rs10n_d0wngr4d3_pwn3d}",
        "hints": [
            "Check /api/version-check?skill=researcher",
            "Compare pinned_version vs latest_available_version",
            "The patch exists but the registry never bumps the pin"
        ]
    }
}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>ASI04 CTF Dashboard</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 0;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            color: #ff0000;
            text-align: center;
            text-shadow: 0 0 10px #ff0000;
        }
        .scoreboard {
            background: #111;
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }
        .score-row {
            display: flex;
            justify-content: space-around;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        .score-block {
            text-align: center;
        }
        .score-label {
            font-size: 14px;
            color: #888;
            margin-bottom: 5px;
        }
        .total-score {
            font-size: 48px;
            text-align: center;
            color: #00ff00;
            text-shadow: 0 0 20px #00ff00;
        }
        .total-score.rwl {
            font-size: 36px;
            color: #ff6600;
            text-shadow: 0 0 15px #ff6600;
        }
        .total-score.grand {
            font-size: 42px;
            color: #ffff00;
            text-shadow: 0 0 20px #ffff00;
        }
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
        }
        .tab {
            padding: 12px 24px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            font-family: monospace;
            font-size: 14px;
            color: #888;
            transition: all 0.3s;
        }
        .tab:hover {
            border-color: #00ff00;
            color: #00ff00;
        }
        .tab.active {
            background: #111;
            border-color: #00ff00;
            border-bottom-color: #111;
            color: #00ff00;
            font-weight: bold;
        }
        .tab.rwl-tab.active {
            border-color: #ff6600;
            color: #ff6600;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .challenges {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        .challenge {
            background: #111;
            border: 1px solid #333;
            border-radius: 10px;
            padding: 20px;
            transition: all 0.3s;
        }
        .challenge:hover {
            border-color: #00ff00;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
        }
        .challenge.solved {
            border-color: #00ff00;
            background: rgba(0, 255, 0, 0.1);
        }
        .challenge.rwl-challenge {
            border-color: #333;
        }
        .challenge.rwl-challenge:hover {
            border-color: #ff6600;
            box-shadow: 0 0 15px rgba(255, 102, 0, 0.2);
        }
        .challenge.rwl-challenge.solved {
            border-color: #ff6600;
            background: rgba(255, 102, 0, 0.1);
        }
        .challenge h3 {
            margin-top: 0;
            color: #ff6600;
        }
        .points {
            float: right;
            background: #222;
            padding: 5px 15px;
            border-radius: 5px;
            color: #ffff00;
        }
        .solved .points {
            background: #00ff00;
            color: #000;
        }
        .rwl-challenge.solved .points {
            background: #ff6600;
            color: #000;
        }
        .hints {
            font-size: 12px;
            color: #666;
            margin-top: 10px;
            padding: 10px;
            background: #0a0a0a;
            border-radius: 5px;
        }
        .flag {
            background: #000;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            border-left: 3px solid #00ff00;
            margin-top: 10px;
            word-break: break-all;
        }
        .rwl-challenge .flag {
            border-left-color: #ff6600;
        }
        .status {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 12px;
        }
        .status.captured { background: #00ff00; color: #000; }
        .status.pending { background: #666; }
        .refresh-btn {
            background: #00ff00;
            color: #000;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-family: monospace;
            font-weight: bold;
        }
        .refresh-btn:hover { background: #00cc00; }
        .header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .section-header {
            color: #ff6600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 15px;
            padding-bottom: 5px;
            border-bottom: 1px solid #333;
        }
        .rwl-banner {
            background: linear-gradient(135deg, #1a0a00, #2a1500);
            border: 1px solid #ff6600;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            text-align: center;
        }
        .rwl-banner h3 { color: #ff6600; margin: 0 0 5px 0; }
        .rwl-banner p { color: #888; margin: 0; font-size: 13px; }
        .links-bar {
            text-align: center;
            padding: 10px;
            background: #111;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .links-bar a { color: #00ff88; margin: 0 10px; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ASI04 SUPPLY CHAIN CTF</h1>

        <div class="scoreboard">
            <div class="header-row">
                <h2>Scoreboard</h2>
                <button class="refresh-btn" onclick="loadProgress()">Refresh</button>
            </div>
            <div class="score-row">
                <div class="score-block">
                    <div class="score-label">Core Challenges</div>
                    <div class="total-score" id="core-score">0 / 1350</div>
                </div>
                <div class="score-block">
                    <div class="score-label">Real World Labs</div>
                    <div class="total-score rwl" id="rwl-score">0 / 2650</div>
                </div>
                <div class="score-block">
                    <div class="score-label">Grand Total</div>
                    <div class="total-score grand" id="total-score">0 / 4000</div>
                </div>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="switchTab('core')">Core Challenges (ASI04-01 to 05)</div>
            <div class="tab rwl-tab" onclick="switchTab('rwl')">RWL1: MCP Ecosystem (06-09)</div>
            <div class="tab rwl-tab" onclick="switchTab('skill')">RWL2: Skill Lab (10-13)</div>
        </div>

        <div id="tab-core" class="tab-content active">
            <div class="section-header">Supply Chain Attack Fundamentals - 1350 pts</div>
            <div class="challenges" id="core-challenges">
                Loading challenges...
            </div>
        </div>

        <div id="tab-rwl" class="tab-content">
            <div class="rwl-banner">
                <h3>Real World Simulated Challenges - MCP Ecosystem Lab</h3>
                <p>Advanced scenarios demonstrating how compromised MCP servers exploit agentic AI workflows</p>
            </div>
            <div class="links-bar">
                <a href="http://localhost:5080" target="_blank">Email Agent :5080</a>
                <a href="http://localhost:5070" target="_blank">Detection Engine :5070</a>
                <a href="http://localhost:8666/dashboard" target="_blank">Attacker Dashboard :8666</a>
            </div>
            <div class="section-header">MCP Ecosystem Attacks - 1250 pts</div>
            <div class="challenges" id="rwl-challenges">
                Loading challenges...
            </div>
        </div>

        <div id="tab-skill" class="tab-content">
            <div class="rwl-banner">
                <h3>Real World Simulated Challenges - Skill Lab</h3>
                <p>Agent orchestration trust failures: poisoned skill registry, output injection, scope creep, version downgrade</p>
            </div>
            <div class="links-bar">
                <a href="http://localhost:5090" target="_blank">Skill Orchestrator :5090</a>
                <a href="http://localhost:8090/skills" target="_blank">Skill Registry :8090</a>
                <a href="http://localhost:8094/invocations" target="_blank">Malicious Skill :8094</a>
                <a href="http://localhost:8666/dashboard" target="_blank">Attacker Dashboard :8666</a>
            </div>
            <div class="section-header">Skill Orchestration Attacks - 1400 pts</div>
            <div class="challenges" id="skill-challenges">
                Loading challenges...
            </div>
        </div>
    </div>

    <script>
        const challenges = ''' + json.dumps(CHALLENGES) + ''';
        const rwlChallenges = ''' + json.dumps(RWL_CHALLENGES) + ''';
        const skillChallenges = ''' + json.dumps(SKILL_CHALLENGES) + ''';

        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            const tabMap = {core: [0, 'tab-core'], rwl: [1, 'tab-rwl'], skill: [2, 'tab-skill']};
            const [idx, id] = tabMap[tab] || [0, 'tab-core'];
            document.querySelectorAll('.tab')[idx].classList.add('active');
            document.getElementById(id).classList.add('active');
        }

        function renderChallenges(containerId, challengeData, solvedData, isRwl) {
            let html = '';
            for (const [id, challenge] of Object.entries(challengeData)) {
                const solved = solvedData[id] || false;
                const rwlClass = isRwl ? 'rwl-challenge' : '';

                html += `
                    <div class="challenge ${rwlClass} ${solved ? 'solved' : ''}">
                        <span class="points">${challenge.points} pts</span>
                        <h3>${id}: ${challenge.name}</h3>
                        <p>${challenge.description}</p>
                        <p>
                            <span class="status ${solved ? 'captured' : 'pending'}">
                                ${solved ? 'CAPTURED' : 'PENDING'}
                            </span>
                        </p>
                        ${solved ? `<div class="flag">${challenge.flag}</div>` : ''}
                        <div class="hints">
                            <strong>Hints:</strong>
                            <ul>
                                ${challenge.hints.map(h => `<li>${h}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            }
            document.getElementById(containerId).innerHTML = html;
        }

        async function loadProgress() {
            try {
                const resp = await fetch('/api/progress');
                const data = await resp.json();

                let coreScore = 0, coreMax = 0;
                let rwlScore = 0, rwlMax = 0;

                // Calculate core scores
                for (const [id, challenge] of Object.entries(challenges)) {
                    coreMax += challenge.points;
                    if (data.solved[id]) coreScore += challenge.points;
                }

                // Calculate RWL scores (MCP Ecosystem + Skill Lab)
                for (const [id, challenge] of Object.entries(rwlChallenges)) {
                    rwlMax += challenge.points;
                    if (data.solved[id]) rwlScore += challenge.points;
                }
                for (const [id, challenge] of Object.entries(skillChallenges)) {
                    rwlMax += challenge.points;
                    if (data.solved[id]) rwlScore += challenge.points;
                }

                // Render challenges
                renderChallenges('core-challenges', challenges, data.solved, false);
                renderChallenges('rwl-challenges', rwlChallenges, data.solved, true);
                renderChallenges('skill-challenges', skillChallenges, data.solved, true);

                // Update scores
                document.getElementById('core-score').textContent = `${coreScore} / ${coreMax}`;
                document.getElementById('rwl-score').textContent = `${rwlScore} / ${rwlMax}`;
                document.getElementById('total-score').textContent = `${coreScore + rwlScore} / ${coreMax + rwlMax}`;

            } catch (e) {
                console.error('Failed to load progress:', e);
            }
        }

        loadProgress();
        setInterval(loadProgress, 5000);
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/progress')
def get_progress():
    """Check which flags have been captured"""
    try:
        response = requests.get(f"{ATTACKER_SERVER}/api/log", timeout=5)
        if response.status_code == 200:
            data = response.json()
            entries = data.get("entries", [])

            # Convert to string for searching
            all_data = str(entries)

            solved = {
                # Core challenges - use exact flag strings to prevent cross-triggering
                "ASI04-01": CHALLENGES["ASI04-01"]["flag"] in all_data,
                "ASI04-02": CHALLENGES["ASI04-02"]["flag"] in all_data,
                "ASI04-03": CHALLENGES["ASI04-03"]["flag"] in all_data,
                "ASI04-04": CHALLENGES["ASI04-04"]["flag"] in all_data,
                "ASI04-05": CHALLENGES["ASI04-05"]["flag"] in all_data,
                # Real World Lab 1 — MCP Ecosystem
                "ASI04-06": RWL_CHALLENGES["ASI04-06"]["flag"] in all_data,
                "ASI04-07": RWL_CHALLENGES["ASI04-07"]["flag"] in all_data,
                "ASI04-08": RWL_CHALLENGES["ASI04-08"]["flag"] in all_data,
                "ASI04-09": RWL_CHALLENGES["ASI04-09"]["flag"] in all_data,
                # Real World Lab 2 — Skill Lab
                "ASI04-10": SKILL_CHALLENGES["ASI04-10"]["flag"] in all_data,
                "ASI04-11": SKILL_CHALLENGES["ASI04-11"]["flag"] in all_data,
                "ASI04-12": SKILL_CHALLENGES["ASI04-12"]["flag"] in all_data,
                "ASI04-13": SKILL_CHALLENGES["ASI04-13"]["flag"] in all_data,
            }

            return jsonify({
                "solved": solved,
                "total_entries": len(entries)
            })
    except Exception as e:
        print(f"Error checking progress: {e}")

    all_keys = {**{k: False for k in CHALLENGES.keys()}, **{k: False for k in RWL_CHALLENGES.keys()}, **{k: False for k in SKILL_CHALLENGES.keys()}}
    return jsonify({
        "solved": all_keys,
        "total_entries": 0
    })

@app.route('/api/challenges')
def get_challenges():
    return jsonify({
        "core": CHALLENGES,
        "rwl": RWL_CHALLENGES
    })

if __name__ == '__main__':
    print("""
    ======================================================
         ASI04 CTF DASHBOARD
         Port: 3000
         Tracks Core + Real World Lab challenges
    ======================================================
    """)
    app.run(host='0.0.0.0', port=3000, debug=True)
