"""
ASI04 Lab - Legitimate Skill Agents
Hosts real, clean implementations of 'researcher' and 'summarizer'.
Due to the poisoned registry, the researcher skill here is never reached
by the orchestrator — it always gets redirected to malicious-skill:8094 instead.

Real World Lab 2: Skill Orchestration Trust (ASI04-10 to 13)
"""

from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "skills": ["researcher", "summarizer"],
        "timestamp": datetime.utcnow().isoformat(),
    })


# INTENTIONAL: This legitimate researcher endpoint is never called — the poisoned
# registry redirects orchestrators to malicious-skill:8094 instead. It exists to
# show learners what a clean, safe skill response looks like by contrast.
@app.route("/skills/researcher", methods=["POST"])
def researcher():
    data = request.get_json() or {}
    task = data.get("task", "")
    return jsonify({
        "skill_id": "researcher",
        "result": (
            f"Research complete for: '{task}'. "
            "Found 2 authoritative sources. "
            "Summary: Based on peer-reviewed literature, the topic involves several key factors "
            "that are well-documented in academic and industry sources."
        ),
        "sources": ["arxiv.org/abs/example-1", "nist.gov/publications/example-2"],
        "metadata": {
            "version": "3.0.1",
            "skill_host": "http://skill-agents:8091",
        },
        "request_permissions": ["read_task", "read_knowledge_base"],
    })


@app.route("/skills/summarizer", methods=["POST"])
def summarizer():
    data = request.get_json() or {}
    task = data.get("task", "")
    context = data.get("context", {})
    text = context.get("text", task)

    # Produce a simple bullet-point summary of whatever text was passed
    sentences = [s.strip() for s in text.replace("\n", " ").split(".") if s.strip()]
    bullets = ["• " + s + "." for s in sentences[:4]] if sentences else ["• No content to summarize."]

    return jsonify({
        "skill_id": "summarizer",
        "result": "Summary:\n" + "\n".join(bullets),
        "metadata": {
            "version": "2.1.0",
            "skill_host": "http://skill-agents:8091",
        },
        "request_permissions": ["read_task"],
    })


if __name__ == "__main__":
    print("""
    ======================================================
         LEGITIMATE SKILL AGENTS
         Real World Lab 2: Skill Orchestration Trust
         Port: 8091
         Endpoints: /skills/researcher, /skills/summarizer
    ======================================================
    """)
    app.run(host="0.0.0.0", port=8091, debug=False)
