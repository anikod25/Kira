"""
kira/llm.py — LLM Interface (Ollama backend)
=============================================
All LLM communication goes through a local Ollama instance.

API used:
    POST http://localhost:11434/api/generate
    {"model": "gemma3:4b", "prompt": "...", "stream": false}

Config (env vars or .env):
    OLLAMA_HOST   — base URL, default http://localhost:11434
    OLLAMA_MODEL  — model tag,  default gemma3:4b

Usage:
    llm = LLMClient()
    action = llm.next_action(context_summary, phase="ENUM")
    text   = llm.generate_text("Write an exec summary...")

Swapping backends later:
    Replace _call() and ping() with a new provider's implementation.
    Everything above those methods (prompt building, JSON parsing,
    validation, retry logic) is provider-agnostic and stays the same.
"""

import json
import os
import time
import textwrap
from datetime import datetime, timezone
from typing import Optional

import requests


# ── Ollama configuration ──────────────────────────────────────────────────────

OLLAMA_HOST    = "http://localhost:11434"
OLLAMA_MODEL   = "gemma3:4b"

DEFAULT_TIMEOUT = 120
MAX_RETRIES     = 3
RETRY_DELAY     = 1.5

# Per-phase temperature — lower = more deterministic
PHASE_TEMPERATURE = {
    "RECON":        0.2,
    "ENUM":         0.2,
    "VULN_SCAN":    0.15,
    "EXPLOIT":      0.15,
    "POST_EXPLOIT": 0.15,
    "REPORT":       0.30,
}
DEFAULT_TEMPERATURE = 0.2


# ── Valid tools ───────────────────────────────────────────────────────────────

VALID_TOOLS = [
    "nmap_scan", "gobuster_dir", "searchsploit", "enum4linux",
    "curl_probe", "whatweb", "msf_search", "msf_exploit",
    "shell_cmd", "linpeas",
    "add_finding", "add_note", "advance_phase", "REPORT", "HALT",
]


# ── Prompts ───────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""
You are Kira, an autonomous penetration testing AI agent.
Reply with ONLY a raw JSON object — no markdown, no prose, no code fences.

Required keys:
  "tool"      : tool name (string)
  "args"      : arguments (object, can be {})
  "reasoning" : one sentence (string)

RULES:
1. Never repeat a tool+args combo already in recent actions.
2. In ENUM: run curl_probe → whatweb → gobuster_dir → searchsploit (short query e.g. "apache 2.4").
3. In EXPLOIT: call msf_search FIRST, then use a module name from its results.
4. Never invent Metasploit module names. Only use names returned by msf_search.
5. Always include the correct port in URLs (e.g. http://IP:8080/ not http://IP/).
6. If stuck with no valid action, emit HALT.

TOOLS:
  nmap_scan     : {"target":"IP","flags":"-sV -sC"} — omit "ports" to scan all 65535 ports
  gobuster_dir  : {"url":"http://IP:PORT/","wordlist":"/usr/share/wordlists/dirb/common.txt"}
  searchsploit  : {"query":"apache 2.4"}
  enum4linux    : {"target":"IP"}
  curl_probe    : {"url":"http://IP:PORT/","flags":"-sIL --max-time 10"}
  whatweb       : {"url":"http://IP:PORT/"}
  msf_search    : {"query":"apache"}
  msf_exploit   : {"module":"exploit/path/from/msf_search","options":{"RHOSTS":"IP","RPORT":8080}}
  shell_cmd     : {"cmd":"whoami","session_id":1}
  linpeas       : {"session_id":1}
  add_finding   : {"title":"...","severity":"critical|high|medium|low|info","port":8080,"cvss":7.5,"description":"...","remediation":"..."}
  add_note      : {"note":"..."}
  advance_phase : {}
  REPORT        : {}
  HALT          : {}

EXAMPLE:
{"tool":"nmap_scan","args":{"target":"10.10.10.5","flags":"-sV -sC"},"reasoning":"Start recon with a full port sweep."}
""").strip()


CORRECTION_PROMPT = textwrap.dedent("""
Your previous response was not valid JSON. Parse error: {error}

Reply with ONLY a raw JSON object with exactly these keys:
  "tool"      : string
  "args"      : object
  "reasoning" : string

No markdown. No prose. No code fences. Just the JSON object.
""").strip()


# ── LLMClient ─────────────────────────────────────────────────────────────────

class LLMClient:
    """
    Ollama-backed LLM client for Kira.

    Parameters
    ----------
    host    : Ollama base URL (default: OLLAMA_HOST env var or http://localhost:11434)
    model   : model tag       (default: OLLAMA_MODEL env var or gemma3:4b)
    timeout : HTTP timeout in seconds
    verbose : print call latency and token counts

    Swapping backends:
        Subclass or replace _call() and ping() — everything else is
        provider-agnostic (prompt building, JSON parsing, retry logic).
    """

    def __init__(
        self,
        host:    str  = None,
        model:   str  = None,
        timeout: int  = DEFAULT_TIMEOUT,
        verbose: bool = True,
        # Accept (and ignore) legacy kwargs so callers don't break
        provider: str = None,
        api_key:  str = None,
        project:  str = None,
        location: str = None,
    ):
        self.provider = "ollama"
        self.host     = (host  or os.getenv("OLLAMA_HOST",  OLLAMA_HOST)).rstrip("/")
        self.model    = (model or os.getenv("OLLAMA_MODEL", OLLAMA_MODEL))
        self.timeout  = timeout
        self.verbose  = verbose
        self._call_log: list[dict] = []

        if self.verbose:
            print(f"[LLM] Ollama | host={self.host} | model={self.model}")

    # ── Public: structured action (JSON mode) ─────────────────────────────────

    def ask(
        self,
        user:        str,
        system:      str   = SYSTEM_PROMPT,
        temperature: float = 0.2,
    ) -> dict:
        """
        Send a prompt, return a validated action dict.
        Retries up to MAX_RETRIES on bad JSON.
        Returns a safe HALT dict after all retries are exhausted.
        """
        # Build a single prompt string: system block + user message
        messages = [{"role": "user", "content": user}]

        for attempt in range(1, MAX_RETRIES + 1):
            raw, meta = self._call(system=system, messages=messages, temperature=temperature)

            if raw is None:
                return self._halt(f"LLM call failed: {meta.get('error')}", meta)

            parsed, parse_error = self._parse_json(raw)
            if parsed is not None:
                validated, val_error = self._validate_action(parsed)
                if validated is not None:
                    validated["_meta"] = meta
                    self._record(attempt, meta, ok=True)
                    if self.verbose:
                        self._print_ok(validated, meta)
                    return validated
                parse_error = val_error

            if self.verbose:
                self._print_retry(attempt, parse_error)

            # Feed the bad response back so the model can self-correct
            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": CORRECTION_PROMPT.format(error=parse_error),
            })
            time.sleep(RETRY_DELAY)

        return self._halt(f"All {MAX_RETRIES} JSON parse attempts failed.", {})

    def next_action(self, context_summary: str, phase: str = "") -> dict:
        """Build user prompt from context + phase, return action dict."""
        phase_hint  = f"\nCurrent phase: {phase}" if phase else ""
        user_msg    = f"{context_summary}{phase_hint}\n\nWhat is your next action?"
        temperature = PHASE_TEMPERATURE.get(phase, DEFAULT_TEMPERATURE)
        return self.ask(user=user_msg, temperature=temperature)

    # ── Public: free-text generation (reporter mode) ──────────────────────────

    def generate_text(
        self,
        prompt:      str,
        temperature: float = 0.3,
        max_tokens:  int   = 500,
    ) -> str:
        """
        Free-text generation for ReportGenerator — no JSON enforcement.
        """
        payload = {
            "model":   self.model,
            "prompt":  prompt,
            "stream":  False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = requests.post(
                    f"{self.host}/api/generate",
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp.json().get("response", "").strip()
            except Exception as e:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                    continue
                return f"(generate_text failed: {str(e)[:80]})"
        return "(Max retries exceeded)"

    # ── Public: ping ──────────────────────────────────────────────────────────

    def ping(self) -> tuple[bool, str]:
        """
        Verify Ollama is reachable and the model is available.
        Sends a minimal /api/generate request and prints the raw response.
        Returns (True, model_name) on success, (False, error_msg) on failure.
        """
        payload = {
            "model":   self.model,
            "prompt":  "Reply with the single word: ok",
            "stream":  False,
            "options": {"temperature": 0.1, "num_predict": 5},
        }
        try:
            resp = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=15,
            )

            if self.verbose:
                print(f"[LLM] Ping → HTTP {resp.status_code} | url={self.host}/api/generate")

            if resp.status_code == 404:
                # Model not pulled yet
                body = resp.json() if resp.content else {}
                return False, (
                    f"Model '{self.model}' not found on Ollama. "
                    f"Run: ollama pull {self.model}"
                )

            resp.raise_for_status()
            data = resp.json()

            if self.verbose:
                print(f"[LLM] Ping response: {data.get('response', '')!r}")

            return True, self.model

        except requests.exceptions.ConnectionError:
            return False, (
                f"Cannot connect to Ollama at {self.host}. "
                f"Is Ollama running? Start it with: ollama serve"
            )
        except requests.exceptions.HTTPError as e:
            return False, f"HTTP {e.response.status_code}: {e}"
        except Exception as e:
            return False, str(e)

    # ── Internal: Ollama call ─────────────────────────────────────────────────

    def _call(self, system: str, messages: list, temperature: float) -> tuple:
        """
        POST to Ollama /api/generate.
        Builds a single prompt string from system + conversation history.
        Returns (raw_text, meta) — raw_text is None on failure.
        """
        prompt = self._build_prompt(system, messages)
        payload = {
            "model":   self.model,
            "prompt":  prompt,
            "stream":  False,
            "options": {
                "temperature": temperature,
                "num_predict": 1024,
            },
        }

        start = time.monotonic()
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = requests.post(
                    f"{self.host}/api/generate",
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data     = resp.json()
                raw_text = data.get("response", "")
                meta = {
                    "latency_s":     round(time.monotonic() - start, 2),
                    "output_tokens": data.get("eval_count", 0),
                    "model":         self.model,
                    "provider":      "ollama",
                    "attempts":      attempt,
                }
                return raw_text, meta

            except Exception as e:
                if attempt < MAX_RETRIES:
                    if self.verbose:
                        print(f"[LLM] Error: {str(e)[:80]}. Retry {attempt}/{MAX_RETRIES}...")
                    time.sleep(RETRY_DELAY)
                    continue
                meta = {
                    "error":     str(e),
                    "latency_s": round(time.monotonic() - start, 2),
                    "provider":  "ollama",
                    "attempts":  attempt,
                }
                return None, meta

        meta = {"error": "Max retries exceeded", "provider": "ollama", "attempts": MAX_RETRIES}
        return None, meta

    # ── Internal: prompt builder ──────────────────────────────────────────────

    @staticmethod
    def _build_prompt(system: str, messages: list) -> str:
        """
        Flatten system prompt + conversation into a single string for
        Ollama's /api/generate endpoint (which takes a plain prompt, not
        a messages array).

        Format:
            <system>
            ### SYSTEM
            {system}
            </system>

            ### USER
            {msg1}

            ### ASSISTANT
            {msg2}

            ### USER
            {msg3}
        """
        parts = []
        if system:
            parts.append(f"### SYSTEM\n{system}")

        for msg in messages:
            role  = "USER" if msg["role"] == "user" else "ASSISTANT"
            parts.append(f"### {role}\n{msg['content']}")

        # Prompt the model to respond as ASSISTANT
        parts.append("### ASSISTANT")
        return "\n\n".join(parts)

    # ── Internal: JSON parsing + validation ───────────────────────────────────

    def _parse_json(self, raw: str) -> tuple[Optional[dict], Optional[str]]:
        text = raw.strip()
        # Strip markdown code fences if the model wraps output
        if text.startswith("```"):
            lines = text.splitlines()
            text  = "\n".join(lines[1:-1]).strip()
        # Some models prefix with a label like "json\n{...}"
        if text.lower().startswith("json"):
            text = text[4:].strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            return None, f"{e} — raw: {text[:120]!r}"
        # Unwrap single-key wrapper objects e.g. {"action": {...}}
        if isinstance(parsed, dict) and len(parsed) == 1:
            inner = next(iter(parsed.values()))
            if isinstance(inner, dict):
                parsed = inner
        return parsed, None

    def _validate_action(self, obj: dict) -> tuple[Optional[dict], Optional[str]]:
        missing = [k for k in ("tool", "args", "reasoning") if k not in obj]
        if missing:
            return None, f"Missing required keys: {missing}"
        tool = obj["tool"]
        if tool not in VALID_TOOLS:
            close = [t for t in VALID_TOOLS if tool.lower() in t.lower()]
            hint  = f" Did you mean: {close}?" if close else ""
            return None, f"Unknown tool '{tool}'.{hint} Valid: {VALID_TOOLS}"
        if not isinstance(obj["args"], dict):
            return None, f"'args' must be a JSON object, got {type(obj['args']).__name__}"
        if not isinstance(obj["reasoning"], str):
            return None, "'reasoning' must be a string"
        return {
            "tool":      tool,
            "args":      obj["args"],
            "reasoning": obj["reasoning"].strip(),
        }, None

    # ── Internal: helpers ─────────────────────────────────────────────────────

    def _halt(self, reason: str, meta: dict = None) -> dict:
        return {"tool": "HALT", "args": {}, "reasoning": reason, "_meta": meta or {}}

    def _record(self, attempts: int, meta: dict, ok: bool) -> None:
        self._call_log.append({
            "timestamp": _ts(),
            "attempts":  attempts,
            "ok":        ok,
            "latency_s": meta.get("latency_s"),
            "tokens":    meta.get("output_tokens"),
            "provider":  "ollama",
        })

    def _print_ok(self, action: dict, meta: dict) -> None:
        try:
            from rich.console import Console
            Console().print(
                f"[dim][LLM/ollama][/dim] "
                f"[green]{action['tool']}[/green] "
                f"[dim]({meta.get('latency_s','?')}s, "
                f"{meta.get('output_tokens','?')} tokens)[/dim]"
            )
        except ImportError:
            print(f"[LLM/ollama] {action['tool']} ({meta.get('latency_s')}s)")

    def _print_retry(self, attempt: int, error: str) -> None:
        try:
            from rich.console import Console
            Console().print(
                f"[dim][LLM][/dim] [yellow]Attempt {attempt} — bad JSON: {error[:80]}[/yellow]"
            )
        except ImportError:
            print(f"[LLM] Attempt {attempt} failed: {error[:80]}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ── Smoke test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    print("=== llm.py smoke test (Ollama) ===\n")

    # [1] Default init
    print("[1] Default init")
    c = LLMClient(verbose=False)
    assert c.provider == "ollama"
    assert c.host == OLLAMA_HOST
    assert c.model == OLLAMA_MODEL
    print(f"    OK — provider={c.provider} host={c.host} model={c.model}")

    # [2] Custom host + model
    print("\n[2] Custom host + model")
    c2 = LLMClient(host="http://10.0.0.1:11434", model="llama3:8b", verbose=False)
    assert c2.host == "http://10.0.0.1:11434"
    assert c2.model == "llama3:8b"
    print(f"    OK — host={c2.host} model={c2.model}")

    # [3] Trailing slash stripped from host
    print("\n[3] Trailing slash stripped")
    c3 = LLMClient(host="http://localhost:11434/", verbose=False)
    assert not c3.host.endswith("/")
    print(f"    OK — host={c3.host}")

    # [4] Prompt builder
    print("\n[4] _build_prompt")
    prompt = LLMClient._build_prompt(
        system="You are a tester.",
        messages=[
            {"role": "user",      "content": "hello"},
            {"role": "assistant", "content": "hi"},
            {"role": "user",      "content": "go"},
        ],
    )
    assert "### SYSTEM" in prompt
    assert "You are a tester." in prompt
    assert "### USER\nhello" in prompt
    assert "### ASSISTANT\nhi" in prompt
    assert prompt.endswith("### ASSISTANT")
    print(f"    OK — {len(prompt)} chars")

    # [5] JSON parse — clean
    print("\n[5] _parse_json — clean JSON")
    parsed, err = c._parse_json(
        '{"tool":"nmap_scan","args":{"target":"10.0.0.1"},"reasoning":"Start."}'
    )
    assert parsed and not err
    print(f"    OK — {parsed}")

    # [6] JSON parse — strips code fences
    print("\n[6] _parse_json — strips markdown fences")
    parsed2, err2 = c._parse_json(
        '```json\n{"tool":"HALT","args":{},"reasoning":"done"}\n```'
    )
    assert parsed2 and not err2 and parsed2["tool"] == "HALT"
    print(f"    OK — {parsed2}")

    # [7] Validate action
    print("\n[7] _validate_action")
    validated, verr = c._validate_action(
        {"tool": "searchsploit", "args": {"query": "apache"}, "reasoning": "check vulns"}
    )
    assert validated and not verr
    print(f"    OK — tool={validated['tool']}")

    # [8] Unknown tool rejected
    print("\n[8] Unknown tool rejected")
    _, verr2 = c._validate_action(
        {"tool": "fake_tool", "args": {}, "reasoning": "test"}
    )
    assert verr2 and "Unknown tool" in verr2
    print(f"    OK — {verr2[:60]}")

    # [9] msf_search in VALID_TOOLS
    print("\n[9] msf_search in VALID_TOOLS")
    assert "msf_search" in VALID_TOOLS
    print(f"    OK")

    # [10] Live ping
    print("\n[10] Live Ollama ping")
    host  = os.getenv("OLLAMA_HOST", OLLAMA_HOST)
    model = os.getenv("OLLAMA_MODEL", OLLAMA_MODEL)
    live  = LLMClient(host=host, model=model, verbose=True)
    ok, msg = live.ping()
    if ok:
        print(f"    PASS — model: {msg}")
    else:
        print(f"    FAIL — {msg}")
        print(f"    (Start Ollama with: ollama serve && ollama pull {model})")

    print("\nAll offline tests passed.")
