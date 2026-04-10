"""
kira/planner.py — Planner
==========================
The brain of Kira. Runs the observe → think → act loop, dispatching
each LLM-chosen action to the correct executor, updating state, and
auto-advancing phases when completion criteria are met.
"""

from __future__ import annotations

import json
import time
from typing import Optional


# ── Phase completion criteria ─────────────────────────────────────────────────

PHASE_COMPLETION = {
    "RECON":        ["open_ports"],
    "ENUM":         ["open_ports", "findings"],
    "VULN_SCAN":    ["findings"],
    "EXPLOIT":      ["sessions"],
    "POST_EXPLOIT": ["current_user"],
    "REPORT":       [],   # terminal — always complete
    "DONE":         [],
}

# Minimum findings required before REPORT is valid
MIN_FINDINGS_FOR_REPORT = 1


class PhaseController:
    """
    Tracks per-phase context focus and completion logic.
    Injected into the LLM prompt alongside the state summary.
    """

    PHASE_FOCUS = {
        "RECON": (
            "Run an nmap scan on heavily used ports "
            "(22,25,53,80,443,8080,3128,4443,4444,8090,8443) if you haven't yet. "
            "Goal: discover service versions on the approved default port set."
        ),
        "ENUM": (
            "Enumerate each discovered service. Run gobuster on HTTP ports, "
            "enum4linux on SMB, curl/whatweb for server banners. "
            "Goal: find web paths, usernames, shares, and version strings."
        ),
        "VULN_SCAN": (
            "Cross-reference every service version with searchsploit. "
            "Add findings for each CVE found. "
            "Goal: build a prioritised list of exploitable vulnerabilities."
        ),
        "EXPLOIT": (
            "Attempt exploitation of the highest-CVSS finding with an "
            "available Metasploit module. "
            "Goal: obtain a shell session."
        ),
        "POST_EXPLOIT": (
            "You have a session. Run linpeas, check sudo, SUID binaries, "
            "cron jobs, and kernel version. "
            "Goal: escalate to root."
        ),
        "REPORT": (
            "Emit the REPORT action. "
            "All findings have been collected."
        ),
        "DONE": "Session complete.",
    }

    def __init__(self, state):
        self._state = state

    def focus(self) -> str:
        return self.PHASE_FOCUS.get(self._state.phase, "")

    def is_phase_complete(self) -> bool:
        required = PHASE_COMPLETION.get(self._state.phase, [])
        for key in required:
            if not self._state.get(key):
                return False
        return True

    def context_with_focus(self) -> str:
        summary = self._state.get_context_summary()
        focus = self.focus()
        return f"{summary}\n\nCURRENT FOCUS: {focus}" if focus else summary


class Planner:
    """
    Observe → Think → Act agent loop for Kira.
    """

    MAX_SAME_ACTION = 3

    def __init__(
        self,
        state,
        runner,
        llm,
        msf=None,
        kb=None,
        verbose: bool = True,
        logger=None,
        guard=None,
    ):
        self._state = state
        self._runner = runner
        self._llm = llm
        self._msf = msf
        self._kb = kb
        self._verbose = verbose
        self._logger = logger
        self._guard = guard
        self._phase_ctrl = PhaseController(state)
        self._action_history: list[str] = []

    def run(self, max_iterations: int = 10) -> str:
        if self._verbose:
            self._print_banner()

        for iteration in range(1, max_iterations + 1):
            if self._verbose:
                self._print_iter_header(iteration, max_iterations)

            context = self._phase_ctrl.context_with_focus()
            action = self._llm.next_action(context_summary=context, phase=self._state.phase)

            tool = action.get("tool", "HALT")
            args = action.get("args", {}) or {}
            reasoning = action.get("reasoning", "")

            if self._verbose:
                self._print_action(tool, args, reasoning)

            if self._anti_loop_check(tool, args):
                msg = (
                    f"Anti-loop guard triggered: '{tool}' with identical args "
                    f"seen {self.MAX_SAME_ACTION} times consecutively."
                )
                self._state.log_action("HALT", {}, msg)
                if self._verbose:
                    self._print_warn(msg)
                return "HALTED"

            if tool == "HALT":
                self._state.log_action("HALT", args, reasoning)
                if self._verbose:
                    self._print_info(f"Agent halted: {reasoning}")
                return "HALTED"

            if tool == "REPORT":
                findings = self._state.get("findings", [])
                if len(findings) < MIN_FINDINGS_FOR_REPORT:
                    self._state.log_action(
                        "REPORT_REJECTED",
                        {},
                        "REPORT requested but no findings in state yet. Continue enumeration.",
                    )
                    if self._verbose:
                        self._print_warn("REPORT rejected — no findings yet. Continuing...")
                    continue
                self._state.log_action("REPORT", {}, "Generating final report.")
                self._state.update(phase="REPORT")
                if self._verbose:
                    self._print_info("REPORT action received — exiting loop.")
                return "DONE"

            result_summary = self._dispatch(action)

            if self._logger:
                self._logger.action(
                    tool=tool,
                    args=args,
                    result={"ok": not result_summary.startswith(("BLOCKED", "FAILED")), "summary": result_summary},
                    elapsed_s=0.0,
                )

            self._state.log_action(tool, args, result_summary)
            self._sync_kb_to_state()

            if self._verbose:
                self._print_result(result_summary)

            exit_reason = self._check_phase_gate()
            if exit_reason:
                return exit_reason

            time.sleep(0.5)

        self._state.log_action("MAX_ITER", {}, f"Loop terminated after {max_iterations} iterations.")
        if self._verbose:
            self._print_warn(f"Max iterations ({max_iterations}) reached.")
        return "MAX_ITER"

    def _dispatch(self, action: dict) -> str:
        if self._guard is not None:
            allowed, reason = self._guard.check_action(action)
            if not allowed:
                self._state.log_error(action.get("tool", "unknown"), reason)
                return f"BLOCKED by guardrail: {reason[:120]}"

        tool = action.get("tool", "")
        args = action.get("args", {}) or {}
        target = self._state.target or ""

        try:
            if tool == "nmap_scan":
                return self._do_nmap(args, target)
            if tool == "gobuster_dir":
                return self._do_gobuster(args)
            if tool == "searchsploit":
                return self._do_searchsploit(args)
            if tool == "enum4linux":
                return self._do_enum4linux(args, target)
            if tool == "curl_probe":
                return self._do_curl(args)
            if tool == "whatweb":
                return self._do_whatweb(args)
            if tool == "msf_exploit":
                return self._do_msf_exploit(args)
            if tool == "shell_cmd":
                return self._do_shell_cmd(args)
            if tool == "linpeas":
                return self._do_linpeas(args)
            if tool == "add_finding":
                return self._do_add_finding(args)
            if tool == "add_note":
                return self._do_add_note(args)
            if tool == "advance_phase":
                old = self._state.phase
                new = self._state.advance_phase()
                return f"Phase advanced: {old} → {new}"
            return f"Unknown tool dispatched: '{tool}'"
        except Exception as exc:
            msg = f"Dispatch error for '{tool}': {exc}"
            self._state.log_error(tool, msg)
            return msg

    # ── Tool implementations ─────────────────────────────────────────────────

    def _do_nmap(self, args: dict, target: str) -> str:
        tgt = args.get("target", target)
        flags = args.get("flags", "-sV -sC")
        ports = _normalize_ports_arg(args.get("ports")) or NMAP_HEAVY_PORTS

        result = self._runner.nmap(target=tgt, flags=flags, ports=ports)
        if result.ok and result.artifact_path:
            try:
                from kira.parsers.nmap_parser import (
                    parse_nmap_xml,
                    extract_state_fields,
                    get_notable_script_findings,
                )
                parsed = parse_nmap_xml(result.artifact_path)
                fields = extract_state_fields(parsed)
                self._state.update(**fields)
                if self._kb:
                    for f in get_notable_script_findings(parsed):
                        self._kb.add_from_dict(f)
                return (
                    f"Found {len(fields.get('open_ports', []))} open ports: "
                    f"{fields.get('open_ports', [])}. "
                    f"Services: {list(fields.get('services', {}).values())[:5]}"
                )
            except Exception as e:
                return f"nmap OK but parse failed: {e}. raw: {result.summary}"
        return result.summary

    def _do_gobuster(self, args: dict) -> str:
        url = _normalize_http_tool_url(args.get("url") or _default_http_url(self._state), self._state)
        wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        result = self._runner.gobuster(url=url, wordlist=wordlist)
        if result.ok:
            try:
                from kira.parsers.gobuster_parser import GobusterParser
                parsed = GobusterParser(raw=result.stdout, base_url=url, port=_url_to_port(url) or 80).parse()
                paths = list(parsed.all_paths or [])
                self._state.update(web_paths=paths)
                if self._kb:
                    # gobuster_parser may return Finding objects; store as dicts when possible
                    for f in (parsed.findings or []):
                        self._kb.add_from_dict(getattr(f, "to_dict", lambda: f)())
                juicy = list(parsed.juicy_paths or [])
                return f"Found {len(paths)} paths. Juicy: {juicy[:5] or 'none'}"
            except Exception as e:
                return f"gobuster OK but parse failed: {e}"
        return result.summary

    def _do_searchsploit(self, args: dict) -> str:
        query = args.get("query", "")
        if not query:
            return "searchsploit skipped — no query provided"
        result = self._runner.searchsploit(query=query)
        if result.ok and result.stdout:
            try:
                from kira.parsers.vuln_scanner import parse_searchsploit_json
                findings = parse_searchsploit_json(result.stdout)
                if self._kb:
                    for f in findings:
                        self._kb.add_from_dict(f)
                return f"searchsploit '{query}': {len(findings)} results"
            except Exception as e:
                return f"searchsploit OK but parse failed: {e}. raw: {result.summary}"
        return result.summary

    def _do_enum4linux(self, args: dict, target: str) -> str:
        tgt = args.get("target", target)
        flags = args.get("flags", "-a")
        result = self._runner.enum4linux(target=tgt, flags=flags)
        return result.summary

    def _do_curl(self, args: dict) -> str:
        url = _normalize_http_tool_url(args.get("url") or _default_http_url(self._state), self._state)
        flags = args.get("flags", "-sI")
        result = self._runner.curl(url=url, flags=flags)
        if result.ok:
            for line in result.stdout.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    port = _url_to_port(url)
                    svcs = dict(self._state.get("services") or {})
                    if port and str(port) not in svcs:
                        svcs[str(port)] = server
                        self._state.update(services=svcs)
                    break
        return result.summary

    def _do_whatweb(self, args: dict) -> str:
        url = _normalize_http_tool_url(args.get("url") or _default_http_url(self._state), self._state)
        result = self._runner.whatweb(url=url)
        return result.summary

    def _do_msf_exploit(self, args: dict) -> str:
        if self._msf is None:
            return "Metasploit RPC not connected."
        # Delegate to ToolRunner if available
        if hasattr(self._runner, "msf_exploit"):
            return self._runner.msf_exploit(args).summary
        return "msf_exploit not implemented in this build."

    def _do_shell_cmd(self, args: dict) -> str:
        if self._msf is None:
            return "shell_cmd: Metasploit RPC not connected."
        cmd = args.get("cmd", "id")
        session_id = int(args.get("session_id", 1))
        result = self._runner.shell_cmd(cmd=cmd, session_id=session_id)
        return result.summary

    def _do_linpeas(self, args: dict) -> str:
        if self._msf is None:
            return "linpeas: Metasploit RPC not connected."
        session_id = int(args.get("session_id", 1))
        result = self._runner.linpeas(session_id=session_id)
        return result.summary

    def _do_add_finding(self, args: dict) -> str:
        required = ("title", "severity", "description")
        missing = [k for k in required if not args.get(k)]
        if missing:
            return f"add_finding skipped — missing fields: {missing}"
        finding = {
            "title": args.get("title", ""),
            "severity": args.get("severity", "info"),
            "port": int(args.get("port", 0)),
            "service": args.get("service", ""),
            "cvss": float(args.get("cvss", 0.0)),
            "cve": args.get("cve", ""),
            "exploit_available": bool(args.get("exploit_available", False)),
            "description": args.get("description", ""),
            "remediation": args.get("remediation", ""),
        }
        if self._kb:
            self._kb.add_from_dict(finding)
        else:
            self._state.add_finding(finding)
        return f"Finding added: [{finding['severity'].upper()}] {finding['title']}"

    def _do_add_note(self, args: dict) -> str:
        note = args.get("note", "")
        if not note:
            return "add_note skipped — no note text"
        self._state.add_note(note)
        return f"Note saved: {note[:100]}"

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _anti_loop_check(self, tool: str, args: dict) -> bool:
        key = f"{tool}:{json.dumps(args, sort_keys=True)}"
        self._action_history.append(key)
        tail = self._action_history[-self.MAX_SAME_ACTION:]
        return len(tail) == self.MAX_SAME_ACTION and len(set(tail)) == 1

    def _sync_kb_to_state(self) -> None:
        if self._kb is None:
            return
        try:
            self._state.update(findings=self._kb.to_state_dicts())
        except Exception:
            pass

    def _check_phase_gate(self) -> Optional[str]:
        if not self._phase_ctrl.is_phase_complete():
            return None
        current = self._state.phase
        if current == "POST_EXPLOIT":
            self._state.update(phase="REPORT")
            return "DONE"
        if current in ("REPORT", "DONE"):
            return "DONE"
        old = current
        new = self._state.advance_phase()
        if self._verbose:
            self._print_info(f"Phase gate: {old} → {new}")
        return None

    # ── Console output ───────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        try:
            from rich.console import Console
            from rich.panel import Panel
            Console().print(
                Panel(
                    f"[bold green]Kira[/bold green] — target: [cyan]{self._state.target}[/cyan]  "
                    f"phase: [yellow]{self._state.phase}[/yellow]",
                    title="Agent loop started",
                    border_style="dim",
                )
            )
        except Exception:
            print(f"\n[KIRA] target={self._state.target}  phase={self._state.phase}")

    def _print_iter_header(self, i: int, total: int) -> None:
        try:
            from rich.console import Console
            Console().print(f"\n[dim]─── iteration {i}/{total} │ phase: {self._state.phase} ───[/dim]")
        except Exception:
            print(f"\n--- iter {i}/{total}  phase={self._state.phase} ---")

    def _print_action(self, tool: str, args: dict, reasoning: str) -> None:
        try:
            from rich.console import Console
            c = Console()
            c.print(f"  [bold cyan]THINK[/bold cyan]  tool=[green]{tool}[/green]  args={args}")
            c.print(f"  [dim]reason: {reasoning[:120]}[/dim]")
        except Exception:
            print(f"  THINK  tool={tool}  args={args}\n  reason: {reasoning[:120]}")

    def _print_result(self, summary: str) -> None:
        try:
            from rich.console import Console
            Console().print(f"  [bold]RESULT[/bold]  {summary[:160]}")
        except Exception:
            print(f"  RESULT  {summary[:160]}")

    def _print_info(self, msg: str) -> None:
        try:
            from rich.console import Console
            Console().print(f"  [bold green]INFO[/bold green]   {msg}")
        except Exception:
            print(f"  INFO   {msg}")

    def _print_warn(self, msg: str) -> None:
        try:
            from rich.console import Console
            Console().print(f"  [bold yellow]WARN[/bold yellow]   {msg}")
        except Exception:
            print(f"  WARN   {msg}")


# ── URL helpers ───────────────────────────────────────────────────────────────

def _url_to_port(url: str) -> Optional[int]:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80
    except Exception:
        return None


def _normalize_http_tool_url(url: str, state) -> str:
    from urllib.parse import urlparse, urlunparse

    raw = (url or "").strip()
    if not raw:
        return raw
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return raw

    auth = ""
    hostpart = parsed.netloc
    if "@" in hostpart:
        auth, hostpart = hostpart.split("@", 1)
        auth = auth + "@"
    host = hostpart.split(":")[0]
    if not host:
        return raw

    open_ports = set(state.get("open_ports") or [])

    # Fix http://host/8080(/path) → http://host:8080(/path)
    if parsed.port is None and parsed.path not in ("", "/"):
        rest = parsed.path.lstrip("/")
        if rest:
            first, _, remainder = rest.partition("/")
            if first.isdigit():
                port = int(first)
                if 1 <= port <= 65535:
                    new_path = "/" + remainder if remainder else "/"
                    netloc = f"{auth}{host}:{port}"
                    raw = urlunparse((parsed.scheme, netloc, new_path, "", parsed.query, parsed.fragment))
                    parsed = urlparse(raw)

    cur = _url_to_port(raw)
    if not open_ports or cur in open_ports:
        return raw

    preference = (80, 443, 8080, 8443, 8000, 8888, 8090)
    pick = next((hp for hp in preference if hp in open_ports), None)
    if pick is None:
        services = dict(state.get("services") or {})
        for p_str, svc in services.items():
            if not any(k in str(svc).lower() for k in ("http", "web", "apache", "nginx", "iis", "httpd")):
                continue
            try:
                pi = int(p_str)
            except ValueError:
                continue
            if pi in open_ports:
                pick = pi
                break
    if pick is None:
        return raw

    scheme = "https" if pick in (443, 8443) else "http"
    netloc = f"{auth}{host}" if pick in (80, 443) else f"{auth}{host}:{pick}"
    pth = parsed.path if parsed.path else "/"
    return urlunparse((scheme, netloc, pth, "", parsed.query, parsed.fragment))


NMAP_HEAVY_PORTS = "22,25,53,80,443,3128,4443,4444,8090,8443"


def _normalize_ports_arg(ports: Optional[str]) -> Optional[str]:
    if not ports:
        return None
    p = str(ports).strip()
    if p.startswith("-p "):
        return p[3:].strip()
    if p.startswith("-p"):
        return p[2:].strip()
    return p


def _default_http_url(state) -> str:
    target = state.target or "127.0.0.1"
    open_ports = list(state.get("open_ports") or [])
    for p in (80, 443, 8080, 8443, 8000, 8888, 55553):
        if p in open_ports:
            scheme = "https" if p == 443 else "http"
            return f"{scheme}://{target}" if p in (80, 443) else f"{scheme}://{target}:{p}"

    services = dict(state.get("services") or {})
    for p_str, svc in services.items():
        svc_l = str(svc).lower()
        if "http" in svc_l or "web" in svc_l:
            try:
                p = int(p_str)
            except Exception:
                continue
            scheme = "https" if p == 443 else "http"
            return f"{scheme}://{target}" if p in (80, 443) else f"{scheme}://{target}:{p}"

    return f"http://{target}"