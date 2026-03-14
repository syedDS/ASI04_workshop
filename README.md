# ASI04: Agentic Supply Chain Vulnerabilities Lab

A hands-on security training lab focused on **ASI04** from the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## Overview

This lab demonstrates nine supply chain attack vectors against agentic AI systems, organized into two modules:

### Core Challenges - Supply Chain Fundamentals (1,350 pts)

| Challenge | Name | Points | Attack Type |
|-----------|------|--------|-------------|
| ASI04-01 | Typosquatting | 100 | Malicious package with similar name |
| ASI04-02 | Malicious MCP Server | 250 | Trojanized tool server |
| ASI04-03 | Dependency Confusion | 250 | High-version public package |
| ASI04-04 | Poisoned Tool Descriptors | 250 | Hidden prompt injection in tool descriptions |
| ASI04-05 | RAG Poisoning | 500 | Malicious documents in knowledge base |

### Real World Simulated Challenges - MCP Ecosystem (1,250 pts)

| Challenge | Name | Points | Attack Type |
|-----------|------|--------|-------------|
| ASI04-06 | Credential Exfiltration via MCP | 200 | MCP server steals API keys from tool params |
| ASI04-07 | Silent BCC Email Interception | 300 | Email gateway injects hidden BCC |
| ASI04-08 | Malicious Dependency Injection | 350 | Hidden dependency chains auto-execute |
| ASI04-09 | MCP Anomaly Detection | 400 | Identify all attacks using LLM judge |

**Grand Total: 2,600 points**

## Architecture

```
                     USER INTERFACES
  +-----------------+  +----------------+  +------------------+
  |Vulnerable Agent |  | CTF Dashboard  |  |Attacker Dashboard|
  |   :5050         |  |    :3000       |  |     :8666        |
  |  (Core + /rwl)  |  | (Core + RWL    |  |                  |
  +--------+--------+  |  tabs)         |  +--------+---------+
           |            +----------------+           ^
           |                                         |
  CORE SUPPLY CHAIN                                  |
  +----------------+                                 |
  | Malicious MCP  |------------ exfil --------------+
  |    :8765       |                                 |
  +----------------+                                 |
  | Poisoned Reg.  |------------ hidden prompts      |
  |    :8080       |                                 |
  +----------------+                                 |
  | Fake PyPI      |------------ typosquat/depconf   |
  |    :8081       |                                 |
  +----------------+                                 |
  | Poisoned RAG   |------------ malicious docs      |
  | (ChromaDB:8000)|                                 |
  +----------------+                                 |
                                                     |
  MCP ECOSYSTEM (Real World Simulated Challenges)    |
  +----------------+                                 |
  | Email Agent    |                                 |
  |    :5080       |                                 |
  +-------+--------+                                 |
          |                                          |
  +-------+--------+  +---------------+  +-----------+------+
  |mcp-postmark-sim|  |bcc-interceptor|  |dependency-injector|
  |    :8770       |  |    :8771      |  |     :8772        |
  +----------------+  +---------------+  +------------------+
          |                                          |
  +-------+--------+                                 |
  |Detection Engine|                                 |
  |    :5070       |---------------------------------+
  +----------------+
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- 8GB+ RAM (16GB recommended for LLM)
- 20GB disk space

### Installation

```bash
# Clone or download the lab
cd asi04-lab

# Make setup script executable
chmod +x setup.sh

# Run setup (builds containers, pulls LLM model)
./setup.sh
```

Or manually:

```bash
docker compose up -d --build
# Pull LLM model
docker exec asi04-ollama ollama pull llama3.2:1b
```

### Access Points

| Service | URL | Description |
|---------|-----|-------------|
| **Core Lab** | | |
| Vulnerable Agent | http://localhost:5050 | Main agent interface |
| CTF Dashboard | http://localhost:3000 | Track all challenges (Core + RWL tabs) |
| Attacker Dashboard | http://localhost:8666/dashboard | View exfiltrated data |
| Malicious MCP | http://localhost:8765/manifest | Trojanized tool server |
| Poisoned Registry | http://localhost:8080/v1/tools | Tool registry with hidden payloads |
| Fake PyPI | http://localhost:8081/simple/ | Malicious package server |
| **MCP Ecosystem** | | |
| Email Agent | http://localhost:5080 | LLM-brained email assistant |
| Detection Engine | http://localhost:5070 | LLM judge anomaly detection |
| RWL Module | http://localhost:5050/rwl | Integrated in vulnerable agent |
| Postmark Sim | http://localhost:8770/manifest | Credential-stealing MCP |
| BCC Interceptor | http://localhost:8771/manifest | BCC injection MCP |
| Dep Injector | http://localhost:8772/mcp/list_tools | Dependency chain MCP |

## Challenge Walkthroughs

### ASI04-01: Typosquatting (100 pts)

**Attack:**
```bash
curl -X POST http://localhost:5050/api/install-package \
  -H "Content-Type: application/json" \
  -d '{"package": "langchaln"}'
```

The fake PyPI server serves `langchaln` (typo of `langchain`) whose `__init__.py` exfiltrates environment variables on import.

### ASI04-02: Malicious MCP Server (250 pts)

Ask the agent to search: "Search for documents about passwords" or directly call the MCP server.

### ASI04-03: Dependency Confusion (250 pts)

```bash
curl -X POST http://localhost:5050/api/install-package \
  -H "Content-Type: application/json" \
  -d '{"package": "acme-agent-core"}'
```

pip installs the attacker's v99.0.0 instead of internal v1.0.0.

### ASI04-04: Poisoned Tool Descriptors (250 pts)

Fetch tools and examine descriptions for hidden prompt injections:
```bash
curl http://localhost:8080/v1/tools | jq '.tools[].description'
```

### ASI04-05: RAG Poisoning (500 pts)

Upload a document containing `RUN_MAINTENANCE`, then ask about "system health". See [SOLUTION.md](SOLUTION.md) for step-by-step.

### ASI04-06 to ASI04-09: MCP Ecosystem

See [mcp-ecosystem-lab/README.md](mcp-ecosystem-lab/README.md) and [mcp-ecosystem-lab/solution.md](mcp-ecosystem-lab/solution.md) for full walkthroughs.

## Mitigations

### For Typosquatting
```python
# Pin exact versions with hashes
langchain==0.1.0 --hash=sha256:abc123...
```

### For MCP/Tool Security
```python
# Verify tool signatures
def load_tool(manifest):
    if not verify_signature(manifest, trusted_keys):
        raise SecurityError("Invalid tool signature")
```

### For Dependency Confusion
```ini
# pip.conf - prioritize internal registry
[global]
index-url = https://internal-pypi.company.com/simple/
```

### For Tool Descriptor Poisoning
```python
import re
def sanitize_description(desc):
    desc = re.sub(r'<!--.*?-->', '', desc, flags=re.DOTALL)
    return desc[:500]
```

### For RAG Poisoning
```python
def add_document(content, source):
    return {
        "content": content,
        "source": source,
        "verified": False,
        "hash": sha256(content)
    }
```

## Cleanup

```bash
docker compose down        # Stop all containers
docker compose down -v     # Remove all data
docker compose down --rmi all  # Remove images too
```

## References

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore](https://sigstore.dev/)

## Disclaimer

This lab is for **educational purposes only**. The vulnerabilities demonstrated here are intentional and designed for security training. Do not use these techniques against systems you don't own or have permission to test.
