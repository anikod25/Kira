"""
main.py — Kira Autonomous Penetration Testing Agent
=====================================================
CLI entry point. Wires all Day 1-3 modules together and launches
the Planner loop autonomously — no human input after startup.

Usage:
    python main.py --target 10.10.10.5 --authorized-by "Lab VM"
    python main.py --target 10.10.10.5 --authorized-by "HTB" --ollama-host http://192.168.1.42:11434
    python main.py --target 10.10.10.5 --authorized-by "test" --no-msf --verbose

Changes from Day 1 version                             ← NEW Day 3
─────────────────────────────────────────────────────
  - Replaced inline StateManager / ToolExecutor / LLMPlanner with
    the real kira.* module classes built Days 1-3.
  - Added MSFClient instantiation + graceful degradation if msfrpcd
    is not running (EXPLOIT phase skipped with a clear warning).
  - Replaced hand-rolled agent loop with Planner.run().
  - Added session summary table printed on exit.
  - Kept original BANNER, color codes, and --authorized-by guard.
"""

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Kira modules ──────────────────────────────────────────────────────────────
# Each import is wrapped so a missing file gives a clear message instead of
# a cryptic ModuleNotFoundError.

def _require_module(name: str, path: str):
    try:
        return __import__(name)
    except ImportError:
        print(f"[KIRA] ERROR: cannot import '{name}'. Is {path} in your project?")
        sys.exit(1)

from kira.state       import StateManager
from kira.tool_runner import ToolRunner
from kira.llm         import LLMClient
from kira.planner     import Planner

# findings.py is built on Day 2 — import gracefully if missing
try:
    from kira.findings import KnowledgeBase
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False

# MSF RPC — optional; only available after `gem install msfrpc` + msfrpcd running
try:
    from pymetasploit3.msfrpc import MsfRpcClient as _MsfRpcClient
    _MSF_LIB_AVAILABLE = True
except ImportError:
    _MSF_LIB_AVAILABLE = False


# ── Constants ──────────────────────────────────────────────────────────────────

VERSION = "0.3.0"   # bumped Day 3

PHASES = ["RECON", "ENUM", "VULN_SCAN", "EXPLOIT", "POST_EXPLOIT", "REPORT", "DONE"]

MSF_DEFAULT_HOST = "127.0.0.1"
MSF_DEFAULT_PORT = 55553
MSF_DEFAULT_PASS = "kirapass"      # set with: msfrpcd -P kirapass -p 55553 -a 127.0.0.1


# ── ANSI colour helper ─────────────────────────────────────────────────────────

class C:
    BLUE_BRIGHT = "\033[94m"
    BLUE_DIM    = "\033[34m"
    CYAN        = "\033[96m"
    CYAN_DIM    = "\033[36m"
    WHITE       = "\033[97m"
    YELLOW      = "\033[93m"
    GREEN       = "\033[92m"
    DIM         = "\033[2m"
    BOLD        = "\033[1m"
    RESET       = "\033[0m"


BANNER = f"""
{C.BLUE_BRIGHT}{C.BOLD}  _  ___
 | |/ (_)_ _ __ _
 | ' <| | '_/ _` |
 |_|\\_\\_|_| \\__,_|{C.RESET}
{C.DIM}{C.CYAN}  AUTONOMOUS PENTEST AGENT v{VERSION}{C.RESET}
{C.YELLOW}  ⚠  Authorized environments only{C.RESET}
"""

# STATUS_BOX = f"""
# {C.BLUE_DIM}┌─────────────────────────────┐
# │{C.RESET} {C.CYAN_DIM}SYSTEM STATUS{C.RESET}                {C.BLUE_DIM}│
# ├─────────────────────────────┤
# │{C.RESET}  Target  {C.BLUE_DIM}────{C.RESET}  192.168.1.0/24 {C.BLUE_DIM}│
# │{C.RESET}  Mode    {C.BLUE_DIM}────{C.RESET}  Stealth Recon  {C.BLUE_DIM}│
# │{C.RESET}  Threads {C.BLUE_DIM}────{C.RESET}  {C.GREEN}16 / active{C.RESET}    {C.BLUE_DIM}│
# │{C.RESET}  Auth    {C.BLUE_DIM}────{C.RESET}  {C.GREEN}✓ Verified{C.RESET}     {C.BLUE_DIM}│
# └─────────────────────────────┘{C.RESET}
# """


# ── MSF connection helper ──────────────────────────────────────────────────────

class MSFClient:
    """
    Thin wrapper around pymetasploit3.MsfRpcClient.
    Exposes a connect() class method that returns (client, ok, message).
    Used by main() so the rest of the code never imports pymetasploit3 directly.
    """

    @classmethod
    def connect(
        cls,
        host:     str = MSF_DEFAULT_HOST,
        port:     int = MSF_DEFAULT_PORT,
        password: str = MSF_DEFAULT_PASS,
        ssl:      bool = True,
    ):
        """
        Attempt to connect to msfrpcd.

        Returns
        -------
        (client, True,  "connected")              on success
        (None,   False, "<reason string>")        on failure
        """
        if not _MSF_LIB_AVAILABLE:
            return None, False, (
                "pymetasploit3 not installed. "
                "Run: pip install pymetasploit3"
            )

        try:
            client = _MsfRpcClient(password, server=host, port=port, ssl=ssl)
            return client, True, f"connected to {host}:{port}"
        except ConnectionRefusedError:
            return None, False, (
                f"msfrpcd not running on {host}:{port}. "
                f"Start it: msfrpcd -P {password} -p {port} -a {host}"
            )
        except Exception as exc:
            return None, False, f"MSF connection error: {exc}"


# ── Session summary ────────────────────────────────────────────────────────────

def _print_session_summary(state: StateManager, session_dir: Path, elapsed_s: float):
    """Print a compact summary table after the planner loop exits."""
    findings  = state.get("findings") or []
    ports     = state.get("open_ports") or []
    sessions  = state.get("sessions") or []
    is_root   = state.get("is_root", False)
    phase     = state.get("phase", "?")

    # Action log stats
    log_path = session_dir / "actions.jsonl"
    stats    = ToolRunner.summarise_action_log(str(log_path))

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print(f"\n{C.BOLD}{'─' * 50}{C.RESET}")
    print(f"{C.BOLD}  Kira Session Summary{C.RESET}")
    print(f"{'─' * 50}")
    print(f"  Target          {state.target}")
    print(f"  Final phase     {phase}")
    print(f"  Root obtained   {'YES ✓' if is_root else 'no'}")
    print(f"  Sessions open   {len(sessions)}")
    print(f"  Open ports      {len(ports)}")
    print(f"  Findings        {len(findings)}  "
          + "  ".join(f"{C.RED if k=='critical' else C.YELLOW}{k}:{v}{C.RESET}"
                      for k, v in sev_counts.items()))
    print(f"  Actions run     {stats['total_actions']}  "
          f"(ok={stats['successful']}  failed={stats['failed']})")
    print(f"  Tools used      {', '.join(stats['tools_used']) or 'none'}")
    print(f"  Elapsed         {elapsed_s:.0f}s")
    print(f"  Session dir     {session_dir}")
    print(f"{'─' * 50}")

    if findings:
        print(f"\n{C.BOLD}  Top findings:{C.RESET}")
        sorted_findings = sorted(
            findings,
            key=lambda f: f.get("cvss", 0),
            reverse=True,
        )
        for f in sorted_findings[:5]:
            sev = f.get("severity", "info").upper()
            color = {
                "CRITICAL": C.RED, "HIGH": C.RED,
                "MEDIUM": C.YELLOW, "LOW": C.BLUE,
            }.get(sev, C.DIM)
            print(f"  {color}[{sev:8s}]{C.RESET} CVSS {f.get('cvss', '?'):<4}  "
                  f"port {f.get('port', '?'):<5}  {f.get('title', 'untitled')}")

    print()


# ── CLI argument parser ────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kira",
        description="Kira — Autonomous Penetration Testing Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --target 10.10.10.5 --authorized-by 'HTB Lab'\n"
            "  python main.py --target 10.10.10.5 --authorized-by 'test' --no-msf\n"
            "\n"
            "  [!] Only use against targets you are explicitly authorized to test."
        ),
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP address or hostname",
    )
    parser.add_argument(
        "--authorized-by",
        required=True,
        metavar="AUTHORIZATION",
        help="Required: written confirmation of authorization (e.g. 'HTB Lab VM')",
    )
    parser.add_argument(
        "--ollama-host",
        default=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        metavar="URL",
        help="Ollama API URL (default: http://localhost:11434 or $OLLAMA_HOST)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./kira_sessions",
        metavar="DIR",
        help="Root directory for session output (default: ./kira_sessions)",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=50,
        metavar="N",
        help="Maximum planner loop iterations (default: 50)",
    )

    # MSF options
    msf_group = parser.add_argument_group("Metasploit RPC (optional)")
    msf_group.add_argument(
        "--no-msf",
        action="store_true",
        help="Disable Metasploit integration (RECON→VULN_SCAN only)",
    )
    msf_group.add_argument(
        "--msf-host",   default=MSF_DEFAULT_HOST, help=f"msfrpcd host (default: {MSF_DEFAULT_HOST})",
    )
    msf_group.add_argument(
        "--msf-port",   type=int, default=MSF_DEFAULT_PORT, help=f"msfrpcd port (default: {MSF_DEFAULT_PORT})",
    )
    msf_group.add_argument(
        "--msf-pass",   default=MSF_DEFAULT_PASS, help="msfrpcd password",
    )
    msf_group.add_argument(
        "--msf-no-ssl", action="store_true",      help="Disable SSL for msfrpcd connection",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (tool stdout streamed to terminal)",
    )
    parser.add_argument(
        "--version", action="version", version=f"Kira {VERSION}",
    )

    return parser


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    print(f"{C.DIM}{'─' * 50}{C.RESET}")
    print(f"  {C.YELLOW}WARNING:{C.RESET} For authorized environments only.")
    print(f"  Unauthorized use is illegal and unethical.")
    print(f"{C.DIM}{'─' * 50}{C.RESET}\n")

    parser = _build_parser()
    args   = parser.parse_args()

    # ── 1. Parse args early so --version/--help work before the prompt ────────
    # Authorization confirmation is enforced by --authorized-by flag, but we
    # also print a visible reminder at startup.
    print(f"  Target        : {C.CYAN}{args.target}{C.RESET}")
    print(f"  Authorized by : {C.GREEN}{args.authorized_by}{C.RESET}")
    print(f"  Ollama host   : {args.ollama_host}")
    print(f"  MSF           : {'disabled (--no-msf)' if args.no_msf else f'{args.msf_host}:{args.msf_port}'}")
    print()

    # ── 2. Session directory ──────────────────────────────────────────────────
    safe_target  = args.target.replace(".", "_").replace("/", "_")
    timestamp    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    session_dir  = Path(args.output) / f"{safe_target}_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    print(f"  Session dir   : {session_dir}\n")

    # ── 3. StateManager ───────────────────────────────────────────────────────
    state = StateManager(session_dir=str(session_dir))
    state.init(target=args.target, authorized_by=args.authorized_by)

    # ── 4. LLM client + ping ──────────────────────────────────────────────────
    print(f"{C.DIM}[INIT] Connecting to LLM at {args.ollama_host}...{C.RESET}")
    llm = LLMClient(
        host=args.ollama_host,
        verbose=args.verbose,
    )
    llm_ok, llm_msg = llm.ping()
    if llm_ok:
        print(f"{C.GREEN}[OK  ] LLM: {llm_msg}{C.RESET}")
    else:
        print(f"{C.RED}[FAIL] LLM: {llm_msg}{C.RESET}")
        print(f"\n  Kira cannot run without a working LLM connection.")
        print(f"  Fix: ensure Ollama is running on {args.ollama_host}")
        print(f"       ollama pull gemma3:4b && OLLAMA_HOST=0.0.0.0 ollama serve")
        sys.exit(1)

    # ── 5. MSF client (optional — graceful degradation if unavailable) ────────
    # NEW Day 3: attempt MSF connection; if it fails, Kira continues but the
    # EXPLOIT phase will be skipped by the planner (msf_exploit returns an
    # informative error string instead of crashing).

    msf_client = None

    if args.no_msf:
        print(f"{C.YELLOW}[SKIP] MSF disabled via --no-msf flag{C.RESET}")
        print(f"       Kira will run RECON → ENUM → VULN_SCAN then stop before EXPLOIT.")
    else:
        print(f"{C.DIM}[INIT] Connecting to msfrpcd at {args.msf_host}:{args.msf_port}...{C.RESET}")
        msf_client, msf_ok, msf_msg = MSFClient.connect(      # ← NEW Day 3
            host=args.msf_host,
            port=args.msf_port,
            password=args.msf_pass,
            ssl=not args.msf_no_ssl,
        )
        if msf_ok:
            print(f"{C.GREEN}[OK  ] MSF: {msf_msg}{C.RESET}")
        else:
            print(f"{C.YELLOW}[WARN] MSF unavailable: {msf_msg}{C.RESET}")
            print(f"       Kira will run RECON → ENUM → VULN_SCAN then stop before EXPLOIT.")
            print(f"       To enable exploitation, start msfrpcd:")
            print(f"         msfrpcd -P {args.msf_pass} -p {args.msf_port} -a {args.msf_host}")
            msf_client = None   # explicit — planner handles None gracefully

    # ── 6. ToolRunner ─────────────────────────────────────────────────────────
    runner = ToolRunner(                                        # ← NEW Day 3: passes msf
        session_dir=str(session_dir),
        verbose=args.verbose,
        msf=msf_client,
    )

    # Print tool availability at startup
    avail  = runner.check_tools()
    missing = [t for t, ok in avail.items() if not ok]
    present = [t for t, ok in avail.items() if ok]
    if present:
        print(f"{C.DIM}[TOOLS] Available: {', '.join(present)}{C.RESET}")
    if missing:
        print(f"{C.YELLOW}[WARN ] Missing:   {', '.join(missing)}{C.RESET}")
        print(f"        Install missing tools for full coverage.")

    # ── 7. KnowledgeBase (optional — Day 2 module) ────────────────────────────
    kb = KnowledgeBase() if _KB_AVAILABLE else None
    if not _KB_AVAILABLE:
        print(f"{C.DIM}[INFO] findings.py not yet built — kb=None (state.add_finding used){C.RESET}")

    # ── 8. Planner ────────────────────────────────────────────────────────────
    planner = Planner(                                          # ← NEW Day 3
        state=state,
        runner=runner,
        llm=llm,
        msf=msf_client,
        kb=kb,
        verbose=True,
    )

    # ── 9. Run ────────────────────────────────────────────────────────────────
    print(f"\n{C.GREEN}{C.BOLD}[KIRA] Agent loop starting...{C.RESET}")
    print(f"{C.DIM}       Target: {args.target}  |  Max iterations: {args.max_iter}{C.RESET}\n")

    t_start = time.monotonic()

    try:
        outcome = planner.run(max_iterations=args.max_iter)    # ← NEW Day 3
    except KeyboardInterrupt:
        outcome = "INTERRUPTED"
        print(f"\n{C.YELLOW}[KIRA] Interrupted by user.{C.RESET}")
    except Exception as exc:
        outcome = "ERROR"
        print(f"\n{C.RED}[KIRA] Unhandled error: {exc}{C.RESET}")
        import traceback; traceback.print_exc()

    elapsed = time.monotonic() - t_start

    # ── 10. Exit summary ──────────────────────────────────────────────────────
    outcome_colors = {
        "DONE":        C.GREEN,
        "ROOT":        C.GREEN,
        "HALTED":      C.YELLOW,
        "MAX_ITER":    C.YELLOW,
        "INTERRUPTED": C.YELLOW,
        "ERROR":       C.RED,
    }
    color = outcome_colors.get(outcome, C.DIM)
    print(f"\n{color}{C.BOLD}[KIRA] Session ended: {outcome}{C.RESET}")

    _print_session_summary(state, session_dir, elapsed)        # ← NEW Day 3

    # Remind user of next step
    if outcome == "DONE":
        print(f"  {C.DIM}Next: run reporter.py to generate the full pentest report.{C.RESET}")
    elif outcome in ("HALTED", "MAX_ITER"):
        print(f"  {C.DIM}Tip: review {session_dir}/actions.jsonl for why the agent stopped.{C.RESET}")
    if not msf_client and not args.no_msf:
        print(f"  {C.DIM}Tip: start msfrpcd to enable the EXPLOIT phase next run.{C.RESET}")

    print()
    return 0 if outcome in ("DONE", "ROOT") else 1


if __name__ == "__main__":
    sys.exit(main())