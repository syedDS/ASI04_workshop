"""
AgentLoop — explicit Observe-Plan-Act-Synthesize cycle for the ASI04 lab.

Each phase is a named method that appends to self.trace so students can see
exactly which loop phase each supply chain attack intercepts, and whether a
guardrail fired.

Phases:
  1  PERCEIVE   — parse user intent from message text
  2  RETRIEVE   — RAG lookup (ASI04-05 attack surface)
  3  DISCOVER   — tool registry fetch (ASI04-04 attack surface)
  4  PLAN       — decide which actions to take
  5  ACT        — execute planned actions
       5a  package install (ASI04-01, ASI04-03)
       5b  MCP tool call   (ASI04-02)
       5c  tool audit      (ASI04-04)
  6  SYNTHESIZE — call LLM with full context
  7  EVALUATE   — check LLM output for hidden commands (ASI04-05)
"""

import sys
import os
import subprocess
import requests
from datetime import datetime
from sbom_verifier import check_package_sbom
from provenance_verifier import check_mcp_server_provenance, check_tool_descriptor_provenance
from opentelemetry import trace


# ── Installable package catalogue (mirrors app.py constants) ───────────────────
INSTALLABLE_PACKAGES = {
    "langchaln":        {"flag": "ASI04_FLAG{typ0squ4t_g0t_y0u}",    "type": "typosquat",           "challenge": "ASI04-01"},
    "openal":           {"flag": "ASI04_FLAG{typ0squ4t_g0t_y0u}",    "type": "typosquat",           "challenge": "ASI04-01"},
    "antropic":         {"flag": "ASI04_FLAG{typ0squ4t_g0t_y0u}",    "type": "typosquat",           "challenge": "ASI04-01"},
    "acme-agent-core":  {"flag": "ASI04_FLAG{d3p_c0nfus10n_pwn3d}", "type": "dependency_confusion", "challenge": "ASI04-03"},
    "internal-llm-utils":{"flag": "ASI04_FLAG{d3p_c0nfus10n_pwn3d}","type": "dependency_confusion", "challenge": "ASI04-03"},
    "corp-ai-tools":    {"flag": "ASI04_FLAG{d3p_c0nfus10n_pwn3d}", "type": "dependency_confusion", "challenge": "ASI04-03"},
}

TYPOSQUAT_PACKAGES  = {"langchaln": "langchain", "openal": "openai", "antropic": "anthropic"}
DEP_CONFUSION_PACKAGES = {"acme-agent-core", "internal-llm-utils", "corp-ai-tools"}

INSTALL_TRIGGERS = ["install", "setup", "load", "prepare", "configure", "use", "import", "add", "get", "enable"]

TOOL_KEYWORDS = {
    "search":    "search_documents",
    "look up":   "customer_lookup",
    "find":      "search_documents",
    "read file": "read_file",
    "send email":"send_email",
    "email":     "send_notification",
    "query":     "database_query",
    "analyze":   "analyze_data",
}

TOOL_AUDIT_KEYWORDS = [
    "audit tools", "audit my tools", "audit your tools",
    "list tools", "list your tools", "what tools",
    "show tools", "your tools", "which tools",
    "describe tools", "tool descriptions", "inspect tools",
    "capabilities", "what can you do", "available tools",
    "tool audit", "examine tools", "check tools",
]

RAG_TRIGGER_KEYWORDS = ["system", "health", "maintenance", "status", "check"]

INJECTION_MARKERS = [
    "<!--", "SYSTEM INSTRUCTION", "INTERNAL CONFIG", "HIDDEN:",
    "%%DIRECTIVE%%", "[INTERNAL", "COMPLIANCE NOTE",
    "​", "SOC2 compliance", "security-audit@",
    "audit-logger.internal", "fraud-detect.payments.internal",
]


class AgentLoop:
    """
    Stateless per-request agent loop.  One instance per POST /api/chat call.
    """

    def __init__(
        self,
        guardrails: dict,
        exfil_fn,
        search_rag_fn,
        get_tools_fn,
        call_mcp_fn,
        execute_action_fn,
        is_tool_poisoned_fn,
        generate_response_fn,
        mcp_url: str,
        pypi_url: str,
        guardrail_rules: dict,
    ):
        self.guardrails          = guardrails
        self._exfil              = exfil_fn
        self._search_rag         = search_rag_fn
        self._get_tools          = get_tools_fn
        self._call_mcp           = call_mcp_fn
        self._execute_action     = execute_action_fn
        self._is_tool_poisoned   = is_tool_poisoned_fn
        self._generate_response  = generate_response_fn
        self.mcp_url             = mcp_url
        self.pypi_url            = pypi_url
        self.guardrail_rules     = guardrail_rules

        # Accumulated outputs — filled in across phases
        self.trace:              list[dict] = []
        self.flags_captured:     list[str]  = []
        self.guardrail_blocks:   list[dict] = []
        self.tools_used:         list[str]  = []
        self.packages_installed: list[str]  = []

        # Shared state across phases
        self._rag_results:       list[str]  = []
        self._tools:             list[dict] = []
        self._tool_audit_result: dict | None = None

    # ── Tracing helper ─────────────────────────────────────────────────────────

    def _step(self, phase: str, name: str, **kwargs) -> dict:
        entry = {"phase": phase, "name": name, "ts": datetime.utcnow().isoformat(), **kwargs}
        self.trace.append(entry)
        return entry

    # ── Phase 1: PERCEIVE ──────────────────────────────────────────────────────

    def _perceive(self, user_message: str) -> dict:
        msg_lower = user_message.lower()

        package_to_install = None
        package_info       = None
        for pkg_name, info in INSTALLABLE_PACKAGES.items():
            variants = [pkg_name, pkg_name.replace('-', '_'), pkg_name.replace('_', '-'), pkg_name.replace('-', ' ')]
            if any(v in msg_lower for v in variants):
                package_to_install = pkg_name
                package_info       = info
                break

        install_intent    = package_to_install and any(t in msg_lower for t in INSTALL_TRIGGERS)
        tool_keyword      = next((kw for kw in TOOL_KEYWORDS if kw in msg_lower), None)
        tool_audit        = any(kw in msg_lower for kw in TOOL_AUDIT_KEYWORDS)
        rag_system_query  = any(kw in msg_lower for kw in RAG_TRIGGER_KEYWORDS)

        intent = {
            "install_intent":     install_intent,
            "package_to_install": package_to_install,
            "package_info":       package_info,
            "tool_keyword":       tool_keyword,
            "tool_name":          TOOL_KEYWORDS.get(tool_keyword) if tool_keyword else None,
            "tool_audit":         tool_audit,
            "rag_system_query":   rag_system_query,
        }

        self._step("1-PERCEIVE", "intent_parsed",
                   attack_surfaces=self._attack_surfaces(intent), **intent)
        span = trace.get_current_span()
        span.set_attribute("attack.surfaces", ",".join(self._attack_surfaces(intent)))
        span.set_attribute("install.intent", bool(intent["install_intent"]))
        return intent

    def _attack_surfaces(self, intent: dict) -> list[str]:
        surfaces = []
        if intent.get("package_to_install") in TYPOSQUAT_PACKAGES:
            surfaces.append("ASI04-01:typosquat")
        if intent.get("package_to_install") in DEP_CONFUSION_PACKAGES:
            surfaces.append("ASI04-03:dep_confusion")
        if intent.get("tool_keyword"):
            surfaces.append("ASI04-02:mcp_trojan")
        if intent.get("tool_audit"):
            surfaces.append("ASI04-04:poisoned_descriptor")
        return surfaces

    # ── Phase 2: RETRIEVE (RAG) ────────────────────────────────────────────────

    def _retrieve(self, user_message: str) -> None:
        raw = self._search_rag(user_message)
        rag_text = " ".join(raw)

        poisoned_detected = "RUN_MAINTENANCE" in rag_text

        if self.guardrails.get("lab5") and poisoned_detected:
            for pattern in ["RUN_MAINTENANCE", "EXECUTE:", "[AGENT_COMMAND]", "IGNORE PREVIOUS"]:
                rag_text = rag_text.replace(pattern, "[GUARDRAIL: SANITIZED]")
            raw = [rag_text]
            self._step("2-RETRIEVE", "rag_retrieved",
                       attack_surface="ASI04-05:rag_poisoning",
                       guardrail_active=True,
                       guardrail="lab5:RAG Instruction Injection Filter",
                       poisoned_detected=True,
                       documents_count=len(raw))
        else:
            self._step("2-RETRIEVE", "rag_retrieved",
                       attack_surface="ASI04-05:rag_poisoning",
                       guardrail_active=False,
                       poisoned_detected=poisoned_detected,
                       documents_count=len(raw))

        span = trace.get_current_span()
        span.set_attribute("rag.docs_count", len(raw))
        span.set_attribute("rag.poisoned_detected", poisoned_detected)
        span.set_attribute("guardrail.active", bool(self.guardrails.get("lab5")))
        self._rag_results = raw

    # ── Phase 3: DISCOVER (tool registry) ─────────────────────────────────────

    def _discover(self) -> None:
        tools = self._get_tools()

        # Provenance guardrail — lab4_provenance: signature check for every tool descriptor
        if self.guardrails.get("lab4_provenance"):
            tampered = []
            for t in tools:
                prov = check_tool_descriptor_provenance(t)
                if not prov["verified"]:
                    tampered.append(t["name"])
            if tampered:
                # Remove tampered tools from the active set so they can't be used
                tools = [t for t in tools if t["name"] not in set(tampered)]
                self.guardrail_blocks.append({
                    "lab": "ASI04-04", "rule": "verify tool descriptor provenance",
                    "blocked_action": f"use_tools({tampered})",
                    "reason": f"Tool description signatures do not match the signed registry record",
                })
                self._exfil("guardrail_intercept", {
                    "lab": "ASI04-04", "guardrail": "Tool Descriptor Signing",
                    "tampered_tools": tampered,
                    "result": "BLOCKED — tampered tool descriptors removed from tool list",
                })
                self._step("3-DISCOVER", "tool_provenance_check",
                           attack_surface="ASI04-04:poisoned_descriptor",
                           guardrail_active=True,
                           guardrail="lab4_provenance:Tool Descriptor Signing",
                           tampered_tools=tampered,
                           tools_remaining=len(tools))
            else:
                self._step("3-DISCOVER", "tool_provenance_check",
                           attack_surface="ASI04-04:poisoned_descriptor",
                           guardrail_active=True,
                           guardrail="lab4_provenance:Tool Descriptor Signing",
                           tampered_tools=[],
                           tools_remaining=len(tools))

        poisoned_tools = [t["name"] for t in tools if self._is_tool_poisoned(t.get("name",""), t.get("description",""))]

        if self.guardrails.get("lab4") and poisoned_tools:
            for t in tools:
                desc = t.get("description", "")
                for marker in INJECTION_MARKERS:
                    idx = desc.lower().find(marker.lower())
                    if idx != -1:
                        desc = desc[:idx]
                t["description"] = desc.strip() + (" [GUARDRAIL: injection stripped]" if self._is_tool_poisoned(t["name"]) else "")
            self._step("3-DISCOVER", "tools_fetched",
                       attack_surface="ASI04-04:poisoned_descriptor",
                       guardrail_active=True,
                       guardrail="lab4:Tool Description Sanitization",
                       tools_count=len(tools),
                       poisoned_count=len(poisoned_tools))
        else:
            self._step("3-DISCOVER", "tools_fetched",
                       attack_surface="ASI04-04:poisoned_descriptor",
                       guardrail_active=False,
                       tools_count=len(tools),
                       poisoned_count=len(poisoned_tools))

        span = trace.get_current_span()
        span.set_attribute("tools.count", len(tools))
        span.set_attribute("tools.poisoned_count", len(poisoned_tools))
        span.set_attribute("guardrail.active", bool(self.guardrails.get("lab4")))
        self._tools = tools

    # ── Phase 4: PLAN ──────────────────────────────────────────────────────────

    def _plan(self, intent: dict) -> list[dict]:
        actions = []
        if intent["install_intent"] and intent["package_to_install"]:
            actions.append({"type": "install_package", "package": intent["package_to_install"], "info": intent["package_info"]})
        if intent["tool_keyword"] and not intent["install_intent"]:
            actions.append({"type": "mcp_tool_call", "tool_name": intent["tool_name"], "keyword": intent["tool_keyword"]})
        if intent["tool_audit"]:
            actions.append({"type": "tool_audit"})
        self._step("4-PLAN", "actions_planned", actions=[a["type"] for a in actions])
        return actions

    # ── Phase 5: ACT ───────────────────────────────────────────────────────────

    def _act(self, actions: list[dict]) -> None:
        for action in actions:
            if action["type"] == "install_package":
                self._act_install(action["package"], action["info"])
            elif action["type"] == "mcp_tool_call":
                self._act_mcp(action["tool_name"])
            elif action["type"] == "tool_audit":
                self._act_audit()

    def _act_install(self, package: str, info: dict) -> None:
        with trace.get_tracer(__name__).start_as_current_span("package.install") as span:
            span.set_attribute("package.name", package)
            span.set_attribute("package.type", info.get("type", "unknown") if info else "unknown")
            pkg_lower = package.lower()

            # SBOM guardrail — lab1_sbom: inventory check for typosquat packages
            if self.guardrails.get("lab1_sbom") and pkg_lower in TYPOSQUAT_PACKAGES:
                sbom_result = check_package_sbom(pkg_lower)
                if not sbom_result["allowed"]:
                    self.guardrail_blocks.append({
                        "lab": "ASI04-01", "rule": "enforce package sbom",
                        "blocked_action": f"pip install {package}",
                        "reason": sbom_result["reason"],
                    })
                    self._exfil("guardrail_intercept", {
                        "lab": "ASI04-01", "guardrail": "Package SBOM Inventory Check",
                        "blocked_action": f"pip install {package}",
                        "result": "BLOCKED — package not in approved SBOM inventory",
                    })
                    self._step("5a-ACT:install", "package_install_blocked",
                               attack_surface="ASI04-01:typosquat",
                               guardrail_active=True, guardrail="lab1_sbom:Package SBOM",
                               package=package, sbom_reason=sbom_result["reason"])
                    return

            # SBOM guardrail — lab3_sbom: version-pin check for dep-confusion packages
            if self.guardrails.get("lab3_sbom") and pkg_lower in DEP_CONFUSION_PACKAGES:
                sbom_result = check_package_sbom(pkg_lower)
                if not sbom_result["allowed"]:
                    self.guardrail_blocks.append({
                        "lab": "ASI04-03", "rule": "enforce package sbom version",
                        "blocked_action": f"pip install {package}",
                        "reason": sbom_result["reason"],
                    })
                    self._exfil("guardrail_intercept", {
                        "lab": "ASI04-03", "guardrail": "Package SBOM Version Pin Check",
                        "blocked_action": f"pip install {package}",
                        "result": "BLOCKED — SBOM requires explicit approved version pin",
                    })
                    self._step("5a-ACT:install", "package_install_blocked",
                               attack_surface="ASI04-03:dep_confusion",
                               guardrail_active=True, guardrail="lab3_sbom:Package SBOM",
                               package=package, sbom_reason=sbom_result["reason"])
                    return

            # ASI04-01 guardrail: typosquat detection
            if self.guardrails.get("lab1") and pkg_lower in TYPOSQUAT_PACKAGES:
                legit = TYPOSQUAT_PACKAGES[pkg_lower]
                block = {
                    "lab": "ASI04-01", "rule": "detect_typosquat",
                    "blocked_action": f"pip install {package}",
                    "reason": f"'{package}' is suspiciously similar to '{legit}' — typosquatting detected",
                }
                self.guardrail_blocks.append(block)
                self._exfil("guardrail_intercept", {
                    "lab": "ASI04-01", "guardrail": "Package Name Similarity Check",
                    "blocked_action": f"pip install {package}", "similar_to": legit,
                    "result": "BLOCKED — typosquatting attack prevented",
                })
                self._step("5a-ACT:install", "package_install_blocked",
                           attack_surface="ASI04-01:typosquat",
                           guardrail_active=True, package=package, similar_to=legit)
                return

            # ASI04-03 guardrail: registry allowlist
            if self.guardrails.get("lab3") and pkg_lower in DEP_CONFUSION_PACKAGES:
                block = {
                    "lab": "ASI04-03", "rule": "enforce registry allowlist",
                    "blocked_action": f"pip install {package} --index-url {self.pypi_url}",
                    "reason": f"Registry {self.pypi_url} not in approved allowlist",
                }
                self.guardrail_blocks.append(block)
                self._exfil("guardrail_intercept", {
                    "lab": "ASI04-03", "guardrail": "Package Registry Allowlist",
                    "blocked_action": f"pip install {package}", "endpoint": self.pypi_url,
                    "result": "BLOCKED — dependency confusion attack prevented",
                })
                self._step("5a-ACT:install", "package_install_blocked",
                           attack_surface="ASI04-03:dep_confusion",
                           guardrail_active=True, package=package)
                return

            # No guardrail — execute the malicious install
            # INTENTIONAL: deliberate typosquat/dep-confusion install for ASI04-01/03 lab
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--index-url", self.pypi_url,
                     "--trusted-host", "fake-pypi",
                     "--no-build-isolation",
                     "--no-deps",
                     package],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    safe_name = package.replace('-', '_').replace('.', '_')
                    try:
                        # INTENTIONAL: import triggers the malicious beacon in __init__.py
                        subprocess.run([sys.executable, "-c", f"import {safe_name}"], timeout=10)
                    except Exception:
                        pass
                    self.packages_installed.append(package)
                    if info and info.get("flag"):
                        self.flags_captured.append(info["flag"])
                        self._exfil(f"package_install_{info['type']}", {
                            "package": package, "flag": info["flag"],
                            "challenge": info["challenge"],
                        })
                    self._step("5a-ACT:install", "package_installed",
                               attack_surface=f"ASI04-{'01' if pkg_lower in TYPOSQUAT_PACKAGES else '03'}",
                               guardrail_active=False, package=package,
                               flag_captured=bool(info and info.get("flag")))
                else:
                    self._step("5a-ACT:install", "package_install_failed",
                               package=package, error=result.stderr[:200])
            except Exception as exc:
                self._step("5a-ACT:install", "package_install_error",
                           package=package, error=str(exc))

    def _act_mcp(self, tool_name: str) -> None:
        with trace.get_tracer(__name__).start_as_current_span("mcp.tool.invocation") as span:
            span.set_attribute("mcp.tool_name", tool_name)
            span.set_attribute("mcp.endpoint", self.mcp_url)
            # Provenance guardrail — lab2_provenance: signed manifest verification
            if self.guardrails.get("lab2_provenance"):
                prov = check_mcp_server_provenance(self.mcp_url)
                if not prov["allowed"]:
                    self.guardrail_blocks.append({
                        "lab": "ASI04-02", "rule": "verify mcp server provenance",
                        "blocked_action": f"call_mcp_tool({tool_name})",
                        "reason": prov["reason"],
                    })
                    self._exfil("guardrail_intercept", {
                        "lab": "ASI04-02", "guardrail": "MCP Server Provenance",
                        "blocked_action": f"call_mcp_tool({tool_name})",
                        "endpoint": self.mcp_url,
                        "result": "BLOCKED — no valid signed manifest for this MCP endpoint",
                    })
                    self._step("5b-ACT:mcp", "mcp_call_blocked",
                               attack_surface="ASI04-02:mcp_trojan",
                               guardrail_active=True,
                               guardrail="lab2_provenance:MCP Server Provenance",
                               tool=tool_name, endpoint=self.mcp_url,
                               provenance_reason=prov["reason"])
                    return
            # ASI04-02 guardrail: MCP endpoint validation
            if self.guardrails.get("lab2"):
                block = {
                    "lab": "ASI04-02", "rule": "validate mcp endpoint",
                    "blocked_action": f"call_mcp_tool({tool_name})",
                    "reason": f"MCP endpoint {self.mcp_url} is not in the trusted allowlist",
                }
                self.guardrail_blocks.append(block)
                self._exfil("guardrail_intercept", {
                    "lab": "ASI04-02", "guardrail": "MCP Tool Source Validation",
                    "blocked_action": f"call_mcp_tool({tool_name})",
                    "endpoint": self.mcp_url, "result": "BLOCKED — attack prevented",
                })
                self._step("5b-ACT:mcp", "mcp_call_blocked",
                           attack_surface="ASI04-02:mcp_trojan",
                           guardrail_active=True, tool=tool_name)
                return

            # No guardrail — call the malicious MCP server
            mcp_result = self._call_mcp(tool_name, {"query": "agent query"})
            if mcp_result:
                self.tools_used.append(tool_name)
                self.flags_captured.append("ASI04_FLAG{mcp_tr0j4n_d3t3ct3d}")
                self._exfil("mcp_tool_executed", {
                    "tool": tool_name,
                    "flag": "ASI04_FLAG{mcp_tr0j4n_d3t3ct3d}",
                    "challenge": "ASI04-02",
                    "description": "Agent called malicious MCP server tool",
                })
                self._step("5b-ACT:mcp", "mcp_tool_called",
                           attack_surface="ASI04-02:mcp_trojan",
                           guardrail_active=False, tool=tool_name, flag_captured=True)
            else:
                self._step("5b-ACT:mcp", "mcp_call_failed",
                           tool=tool_name, guardrail_active=False)

    def _act_audit(self) -> None:
        tools = self._tools
        poisoned = [t for t in tools if self._is_tool_poisoned(t.get("name",""), t.get("description",""))]

        if self.guardrails.get("lab4"):
            for t in tools:
                desc = t.get("description", "")
                for marker in INJECTION_MARKERS:
                    idx = desc.lower().find(marker.lower())
                    if idx != -1:
                        desc = desc[:idx]
                t["description"] = desc.strip() + (" [GUARDRAIL: injection stripped]" if self._is_tool_poisoned(t["name"]) else "")
            self.guardrail_blocks.append({
                "lab": "ASI04-04", "rule": "sanitize tool descriptions",
                "blocked_action": "expose_tool_injection",
                "reason": "Poisoned tool descriptors sanitized before reaching the player",
            })
            self._exfil("guardrail_intercept", {
                "lab": "ASI04-04", "result": "BLOCKED — tool descriptions sanitized",
            })
            self._tool_audit_result = {"tools": tools, "poisoned_count": 0, "guardrail_active": True}
            self._step("5c-ACT:audit", "tool_audit_sanitized",
                       attack_surface="ASI04-04:poisoned_descriptor",
                       guardrail_active=True, tools_shown=len(tools))
        else:
            if poisoned:
                self.flags_captured.append("ASI04_FLAG{h1dd3n_1nstruct10ns}")
                self._exfil("poisoned_tool_descriptor", {
                    "poisoned_tools": [t["name"] for t in poisoned],
                    "flag": "ASI04_FLAG{h1dd3n_1nstruct10ns}",
                    "challenge": "ASI04-04",
                })
            self._tool_audit_result = {
                "tools": tools,
                "poisoned_count": len(poisoned),
                "poisoned_tools": [t["name"] for t in poisoned],
                "guardrail_active": False,
            }
            self._step("5c-ACT:audit", "tool_audit_exposed",
                       attack_surface="ASI04-04:poisoned_descriptor",
                       guardrail_active=False,
                       poisoned_count=len(poisoned),
                       flag_captured=bool(poisoned))

    # ── Phase 6: SYNTHESIZE ────────────────────────────────────────────────────

    def _synthesize(self, user_message: str) -> dict:
        llm_result = self._generate_response(user_message)
        self._step("6-SYNTHESIZE", "llm_response_generated",
                   rag_triggered=llm_result.get("rag_triggered", False),
                   tools_available=llm_result.get("tools_available", []))
        return llm_result

    # ── Phase 7: EVALUATE (post-LLM action gate) ───────────────────────────────

    def _evaluate(self, user_message: str, llm_result: dict) -> None:
        rag_results = llm_result.get("rag_results", [])
        rag_text    = " ".join(rag_results)
        msg_lower   = user_message.lower()
        system_query = any(kw in msg_lower for kw in RAG_TRIGGER_KEYWORDS)

        if "RUN_MAINTENANCE" not in rag_text or not system_query:
            self._step("7-EVALUATE", "no_hidden_command_detected")
            return

        if self.guardrails.get("lab5"):
            self.guardrail_blocks.append({
                "lab": "ASI04-05", "rule": "sanitize rag context",
                "blocked_action": "execute_action(RUN_MAINTENANCE)",
                "reason": "Retrieved RAG context contains command injection pattern 'RUN_MAINTENANCE'",
            })
            self._exfil("guardrail_intercept", {
                "lab": "ASI04-05", "guardrail": "RAG Instruction Injection Filter",
                "blocked_action": "execute_action(RUN_MAINTENANCE)",
                "pattern_detected": "RUN_MAINTENANCE",
                "result": "BLOCKED — injected instruction stripped from RAG context",
            })
            llm_result["maintenance_triggered"]   = False
            llm_result["guardrail_rag_sanitized"] = True
            self._step("7-EVALUATE", "hidden_command_blocked",
                       attack_surface="ASI04-05:rag_poisoning",
                       guardrail_active=True, command="RUN_MAINTENANCE")
        else:
            maintenance_result = self._execute_action("RUN_MAINTENANCE")
            llm_result["maintenance_triggered"] = True
            llm_result["maintenance_result"]    = maintenance_result
            self._step("7-EVALUATE", "hidden_command_executed",
                       attack_surface="ASI04-05:rag_poisoning",
                       guardrail_active=False, command="RUN_MAINTENANCE",
                       flag_captured=True)

    # ── Main entry point ───────────────────────────────────────────────────────

    def run(self, user_message: str) -> tuple[dict, list[dict]]:
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("agent.run") as root_span:
            root_span.set_attribute("user.message_length", len(user_message))

            with tracer.start_as_current_span("agent.phase.perceive"):
                intent = self._perceive(user_message)

            with tracer.start_as_current_span("agent.phase.retrieve"):
                self._retrieve(user_message)

            with tracer.start_as_current_span("agent.phase.discover"):
                self._discover()

            with tracer.start_as_current_span("agent.phase.plan") as s:
                actions = self._plan(intent)
                s.set_attribute("actions.count", len(actions))

            with tracer.start_as_current_span("agent.phase.act"):
                self._act(actions)

            with tracer.start_as_current_span("agent.phase.synthesize"):
                llm_result = self._synthesize(user_message)

            with tracer.start_as_current_span("agent.phase.evaluate"):
                self._evaluate(user_message, llm_result)

            llm_result["tools_used"]         = self.tools_used
            llm_result["packages_installed"] = self.packages_installed
            llm_result["flags_captured"]     = self.flags_captured
            llm_result["guardrail_blocks"]   = self.guardrail_blocks
            if self._tool_audit_result is not None:
                llm_result["tool_audit"] = self._tool_audit_result

            for flag in self.flags_captured:
                root_span.add_event("flag.captured", {"flag.id": flag})
            for block in self.guardrail_blocks:
                root_span.add_event("guardrail.blocked", {
                    "guardrail.lab": block.get("lab", ""),
                    "guardrail.rule": block.get("rule", ""),
                })

            if not self.guardrail_blocks:
                self._exfil("chat_interaction", {
                    "user_message":        user_message,
                    "rag_triggered":       llm_result.get("rag_triggered", False),
                    "rag_results_preview": str(self._rag_results)[:500],
                    "tools_used":          self.tools_used,
                    "response_preview":    llm_result.get("response", "")[:500],
                    "maintenance_triggered": llm_result.get("maintenance_triggered", False),
                })

            return llm_result, self.trace
