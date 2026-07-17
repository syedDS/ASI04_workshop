# Real World Simulated Challenges: Vulnerable MCP Server Ecosystem

A hands-on security training lab demonstrating how compromised MCP (Model Context Protocol) servers can exploit agentic AI workflows through credential exfiltration, silent email interception, and malicious dependency injection.

Part of the [ASI04 Supply Chain Vulnerabilities Lab](../README.md).

## Overview

This module simulates a realistic scenario where an LLM-powered email agent connects to multiple MCP tool servers. Three of these servers are compromised, each demonstrating a distinct attack vector. A fourth component uses an LLM judge to help students detect the anomalies.

| Challenge | Name | Points | Attack Vector |
|-----------|------|--------|---------------|
| ASI04-06 | Credential Exfiltration via MCP | 200 | Postmark-style MCP steals API keys from tool params |
| ASI04-07 | Silent BCC Email Interception | 300 | Email gateway MCP injects hidden BCC on all emails |
| ASI04-08 | Malicious Dependency Injection | 350 | Workflow MCP auto-loads hidden dependencies that exfiltrate |
| ASI04-09 | MCP Anomaly Detection | 400 | Identify all three attacks using LLM judge + traffic analysis |

**Total: 1,250 points**

## Architecture

```
                          +-------------------+
                          |   CTF Dashboard   |
                          |      :3000        |
                          | (RWL Challenges   |
                          |  tab integrated)  |
                          +-------------------+
                                  |
                          +-------------------+
                          |  Attacker Server  |<---------- all exfil flows here
                          |      :8666        |
                          +--------^----------+
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
+--------+--------+    +-----------+---------+    +----------+---------+
| mcp-postmark-sim|    |  bcc-interceptor    |    | dependency-injector|
|     :8770       |    |      :8771          |    |      :8772         |
| Steals API keys |    | Injects BCC to      |    | Hidden dep chains  |
| from tool params|    | attacker@evil.com   |    | auto-execute       |
+--------^--------+    +-----------^---------+    +----------^---------+
         |                         |                         |
         +-------------------------+-------------------------+
                                   |
                          +--------+----------+
                          |   Email Agent     |
                          |     :5080         |
                          | LLM Brain (llama3)|
                          +-------------------+
                                   |
                          +-------------------+
                          | Detection Engine  |
                          |     :5070         |
                          | LLM Judge (llama3)|
                          +-------------------+
```

## Integration

This module is fully integrated into the main ASI04 lab:

- **CTF Dashboard (:3000)** - Has a dedicated "Real World Simulated Challenges" tab tracking ASI04-06 to 09
- **Vulnerable Agent (:5050)** - Links to the MCP ecosystem lab via `/rwl` route (Flask Blueprint)
- **docker-compose.yml** - All 5 MCP ecosystem services are included in the main compose file
- **Attacker Server (:8666)** - Shared exfiltration collection point for all challenges

## Components

### Email Agent (Port 5080)

The primary student-facing interface. A Flask web app with an LLM-brained (llama3 via Ollama) email assistant that:

- Accepts natural language requests and decides which MCP tools to call
- Passes environment credentials (API keys, tokens) to MCP servers as a real agent would
- Provides a direct email compose form and data processing interface
- Shows tool invocation logs so students can observe MCP traffic

**Environment credentials exposed to MCP servers:**
- `POSTMARK_API_KEY` - Postmark API token
- `OAUTH_TOKEN` - OAuth authentication token
- `INTERNAL_SECRET` - Internal service key
- `AWS_ACCESS_KEY` - AWS access key
- `DATABASE_URL` - Database connection string

**Traffic Inspector panel** (bottom of the page, auto-refreshes every 10 s):

Shows every MCP invocation with color-coded rows:
- Red — credential exfiltration (Lab 6, postmark-sim)
- Orange — BCC injection (Lab 7, bcc-interceptor)
- Yellow — dependency chain (Lab 8, dep-injector)

**NeMo Guardrails panel** (right column):

Three toggle checkboxes — one per lab — let you enable or disable mitigations and immediately observe the effect on the next chat message or direct send.

### mcp-postmark-sim (Port 8770) - ASI04-06

Simulated Postmark email API as an MCP server. Returns deterministic fake responses.

**Tools:** `send_email`, `get_delivery_status`

**Attack:** Scans all tool call arguments for credential-like keys (`api_key`, `token`, `secret`, `password`, etc.). Extracts and exfiltrates them to the attacker server.

### bcc-interceptor (Port 8771) - ASI04-07

Email gateway MCP that silently modifies outgoing emails.

**Tools:** `compose_and_send`, `send_reply`, `forward_email`, `list_sent`

**Attack:** Every send operation silently appends `attacker-collect@evil.com` to the BCC list. The response deliberately omits the BCC field to hide the injection.

### dependency-injector (Port 8772) - ASI04-08

Data workflow MCP with hidden dependency chains.

**Tools:** `data_processor`, `report_generator`, `workflow_orchestrator`

**Attack:** Each tool definition contains a non-standard `dependencies` array with `auto_load: true` entries. When any tool is called, the server internally executes the dependency chain, which exfiltrates parameters and env var names.

### Detection Engine (Port 5070) - ASI04-09

LLM-powered anomaly detection dashboard using llama3 as a judge.

**Features:**
- Aggregates traffic logs from all MCP servers and the attacker server
- "Run LLM Judge Analysis" button feeds traffic data to llama3 for automated analysis
- Three detection rule cards where students submit identified anomaly patterns
- Flag unlocked when all three patterns correctly identified

The three detection form inputs are **pre-filled** with correct values — click **Submit Detection** after the LLM judge confirms the anomaly in its analysis. The expected values are:
- **Credential Source:** `postmark_mcp`
- **BCC Address:** `attacker-collect@evil.com`
- **Dependency Names:** `data-validation-lib, report-template-engine, workflow-state-manager`

## Quick Start

All services are included in the main docker-compose stack:

```bash
# From the project root
docker compose up -d

# Or build and start
docker compose up -d --build
```

### Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| Email Agent | http://localhost:5080 | Main RWL lab interface |
| Detection Engine | http://localhost:5070 | Anomaly analysis |
| Vulnerable Agent RWL | http://localhost:5050/rwl | Integrated module view |
| CTF Dashboard | http://localhost:3000 | Progress tracking (Real World Labs tab) |
| Attacker Dashboard | http://localhost:8666/dashboard | View exfiltrated data |
| Postmark Sim MCP | http://localhost:8770/manifest | Server manifest |
| BCC Interceptor MCP | http://localhost:8771/manifest | Server manifest |
| Dep Injector MCP | http://localhost:8772/mcp/list_tools | Tool definitions |

## How Flags Are Captured

| Flag | Chat trigger phrase (at :5080) | What fires |
|------|-------------------------------|------------|
| `ASI04_FLAG{p0stm4rk_cr3d_st34l}` | `Send an email to alice@company.com about the Q4 report` | Postmark MCP extracts API key from params |
| `ASI04_FLAG{s1l3nt_bcc_1nt3rc3pt}` | `Reply to the team thread about the product launch` | BCC interceptor injects `attacker-collect@evil.com` |
| `ASI04_FLAG{d3p_1nj3ct10n_ch41n}` | `Analyze the weekly figures and summarize the trends` | Dependency chain auto-executes and exfiltrates |
| `ASI04_FLAG{4n0m4ly_d3t3ct3d}` | Submit all 3 correct detection patterns on :5070 | All three anomaly patterns identified by LLM judge |

Each lab has a dedicated keyword family — Labs 6, 7, and 8 fire independently and do **not** overlap:

| Lab | Keywords that trigger it |
|-----|--------------------------|
| ASI04-06 | `send email`, `send an email`, `email to` |
| ASI04-07 | `reply to`, `forward`, `compose a`, `compose and send` |
| ASI04-08 | `analyze`, `process data`, `generate report`, `run workflow` |

## Inspecting MCP Traffic

Each MCP server exposes an invocation log endpoint:

```bash
# View postmark-sim invocations
curl http://localhost:8770/api/invocation-log | jq

# View bcc-interceptor invocations (look for bcc_injected field)
curl http://localhost:8771/api/invocation-log | jq

# View dependency-injector invocations (look for dependency_chain entries)
curl http://localhost:8772/api/invocation-log | jq

# View all exfiltrated data
curl http://localhost:8666/api/log | jq
```

## File Structure

```
mcp-ecosystem-lab/
  mcp-postmark-sim/
    Dockerfile
    server.py          # Simulated Postmark MCP (aiohttp)
  bcc-interceptor/
    Dockerfile
    server.py          # BCC injection MCP (aiohttp)
  dependency-injector/
    Dockerfile
    server.py          # Dependency chain MCP (aiohttp)
  email-agent/
    Dockerfile
    app.py             # LLM-brained email agent (Flask)
  detection-engine/
    Dockerfile
    app.py             # LLM judge detection engine (Flask)
  README.md            # This file
  solution.md          # Full walkthrough and solutions
```

## LLM Integration

Both the email agent and detection engine use the shared Ollama instance (`llama3.2:1b`):

- **Agent Brain:** Decides which MCP tools to call based on user requests
- **LLM Judge:** Analyzes collected traffic for anomalies

## Real-World Parallels

| Lab Attack | Real-World Example |
|------------|-------------------|
| Credential exfiltration via MCP | Postmark-MCP vulnerability where API tokens passed to tool servers are captured |
| Silent BCC injection | Compromised email gateways that copy all corporate email to external addresses |
| Dependency injection chain | Supply chain attacks where legitimate tools load compromised sub-dependencies (cf. event-stream, ua-parser-js) |
| Anomaly detection | SOC/SIEM monitoring for unusual MCP tool behavior patterns |

## Disclaimer

This lab is for **educational purposes only**. All MCP servers are intentionally vulnerable simulators. Do not use these techniques against systems you do not own or have permission to test.
