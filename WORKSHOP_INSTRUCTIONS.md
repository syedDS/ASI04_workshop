# ASI04 Lab — Participant Setup Guide

> **OWASP Agentic Security Initiative — Supply Chain Vulnerabilities**
>
> A self-contained CTF lab for exploring supply chain attack vectors against agentic AI systems.
> All infrastructure runs locally via Docker. No cloud accounts or API keys required.

---

## Prerequisites

Ensure the following are installed and running **before** you begin.

| Requirement | Minimum Version | Notes |
|---|---|---|
| Docker | 24.x+ | Engine or Docker Desktop |
| Docker Compose | v2.x+ | Included with Docker Desktop |
| RAM | 8 GB | 16 GB recommended |
| Disk Space | 20 GB free | For images, model weights, and data |
| OS | Linux / macOS / Windows | Windows requires Docker Desktop with WSL2 backend |

**Verify your setup:**

```bash
docker --version
docker compose version
```

Both commands must succeed before proceeding.

---

## Getting the Lab Files

Download or clone the lab repository to your local machine and navigate into the directory:

```bash
cd ASI4-LAB-complete
```

All subsequent commands must be run from this directory.

---

## Starting the Lab

### Option A — Automated Setup (recommended)

Run the provided setup script. It builds all containers, starts all services, and seeds the lab data automatically.

**Linux / macOS:**

```bash
chmod +x setup.sh
./setup.sh
```

**Windows (PowerShell):**

```powershell
docker compose build --no-cache
docker compose up -d
docker exec asi04-ollama ollama pull llama3.2:1b
```

The setup process takes **5–15 minutes** on first run depending on your internet speed. Docker will download base images (~2 GB) and the LLM model weights (~700 MB).

### Option B — Manual Start

If the script fails or you prefer manual control:

```bash
# Build all images
docker compose build --no-cache

# Start all services in the background
docker compose up -d

# Wait ~30 seconds, then pull the LLM model
docker exec asi04-ollama ollama pull llama3.2:1b
```

---

## Verifying the Lab is Running

Check that all containers are healthy:

```bash
docker compose ps
```

All services should show a status of `running`. If any are restarting or exited, see the [Troubleshooting](#troubleshooting) section below.

Confirm the LLM model is loaded:

```bash
docker exec asi04-ollama ollama list
```

You should see `llama3.2:1b` listed.

---

## Lab Entry Points

Once all services are running, open the following URLs in your browser.

### Start Here

| Interface | URL | Purpose |
|---|---|---|
| **CTF Dashboard** | http://localhost:3000 | Score tracker and challenge overview — open this first |
| **Attacker Dashboard** | http://localhost:8666/dashboard | View data collected by attack infrastructure |

### Challenge Interfaces

| Module | URL | Challenges Covered |
|---|---|---|
| **Vulnerable Agent** | http://localhost:5050 | ASI04-01 through ASI04-05 (Core) |
| **Email Agent** | http://localhost:5080 | ASI04-06 through ASI04-08 (MCP Ecosystem) |
| **Detection Engine** | http://localhost:5070 | ASI04-09 (Anomaly Detection) |
| **Skill Orchestrator** | http://localhost:5090 | ASI04-10 through ASI04-13 (Skill Lab) |

> **Recommended order:** Open the CTF Dashboard first, then work through challenge interfaces in the order listed above.

---

## Challenge Overview

The lab contains **13 challenges** across three modules worth **4,000 points** total.

| Module | Challenges | Points |
|---|---|---|
| Core — Vulnerable Agent | ASI04-01 to ASI04-05 | 1,350 |
| Real World Simulated — MCP Ecosystem | ASI04-06 to ASI04-09 | 1,250 |
| Skill Lab — Agent Orchestration Trust | ASI04-10 to ASI04-13 | 1,400 |

Challenge descriptions and point values are visible on the CTF Dashboard and within each interface.

---

## Resetting the Lab

To reset all lab state and start fresh (clears exfiltrated data, RAG documents, and session data):

```bash
docker compose down -v
docker compose up -d
docker exec asi04-ollama ollama pull llama3.2:1b
```

The `-v` flag removes all persistent volumes. The LLM model is re-pulled because the volume is cleared.

To restart without clearing data:

```bash
docker compose restart
```

---

## Stopping the Lab

```bash
docker compose down
```

To also remove downloaded images and volumes:

```bash
docker compose down -v --rmi all
```

---

## Port Reference

The following ports are used. Ensure none are occupied by other applications before starting.

**Student-facing:**

| Port | Service |
|---|---|
| 3000 | CTF Dashboard |
| 5050 | Vulnerable Agent |
| 5070 | Detection Engine |
| 5080 | Email Agent |
| 5090 | Skill Orchestrator |

**Attack infrastructure (available for inspection):**

| Port | Service |
|---|---|
| 8666 | Attacker Server (exfiltration collector) |
| 8080 | Poisoned Tool Registry |
| 8081 | Fake Package Index |
| 8765 | Malicious MCP Server |
| 8770 | Postmark Simulator MCP |
| 8771 | BCC Interceptor MCP |
| 8772 | Dependency Injector MCP |
| 8090 | Skill Registry |
| 8091 | Skill Agents |
| 8094 | Malicious Skill |

**Internal infrastructure:**

| Port | Service |
|---|---|
| 11434 | Ollama (LLM inference) |
| 8000 | ChromaDB (vector store) |
| 6380 | Redis (session store) |

---

## Troubleshooting

### Containers keep restarting

The Ollama service or dependent services may not be fully ready. Wait 60 seconds after `docker compose up -d`, then check again:

```bash
docker compose ps
docker compose logs ollama
```

### LLM model not found

Pull the model manually:

```bash
docker exec asi04-ollama ollama pull llama3.2:1b
```

### Port conflict

If a port is already in use on your machine, identify the conflicting process:

```bash
# Linux / macOS
lsof -i :<PORT>

# Windows (PowerShell)
netstat -ano | findstr :<PORT>
```

Stop the conflicting process, then run `docker compose up -d` again.

### Services not responding after startup

Some services wait for Ollama and ChromaDB to be ready before they start handling requests. Allow up to **2 minutes** after all containers show `running` before testing the interfaces.

### Logs for a specific service

```bash
docker compose logs <service-name>
# Example:
docker compose logs vulnerable-agent
docker compose logs ctf-dashboard
```

### Full restart after errors

```bash
docker compose down
docker compose up -d --build
```

---

## Notes

- All services run entirely on your local machine. No internet connection is required after the initial image and model download.
- The lab intentionally contains vulnerable components — do not expose any of these ports to the public internet.
- Flags follow the format `ASI04_FLAG{...}`. Submit them on the CTF Dashboard to record your score.
- The Attacker Dashboard at `http://localhost:8666/dashboard` is part of the lab design — it shows what a real attacker would see and is useful for confirming whether an attack succeeded.
