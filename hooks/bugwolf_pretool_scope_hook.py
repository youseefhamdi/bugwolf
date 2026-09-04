#!/usr/bin/env python3
"""BugWolf PreToolUse scope hook (master plan Phase 3.1 — the killer feature).

Harness-level scope enforcement: the deny-by-default boundary holds even
when the model improvises outside BugWolf's tools, because this hook runs
in Claude Code's hook pipeline — OUTSIDE the model's compliance.  Every
outbound-looking Bash command and WebFetch is checked against the mission's
scope contract before the tool executes.

Lifecycle:
    * BugWolf's mission runner binds the scope gate and WRITES the contract
      (``state/scope_contract.json``, via tools.runtime.scope);
    * while a contract exists, this hook denies any candidate host that is
      outside it — exit 2 + a policy fact on stderr (the one outcome tool
      JSON cannot override), so the model sees WHY it was refused;
    * no contract (no mission) => INERT: exit 0, zero UX cost;
    * the runner clears the contract when the mission closes (and the
      operator can force it: ``bugwolf_pretool_scope_hook.py clear``).

Fail-open contract: a hook failure must never break the operator's
session.  Malformed input, missing files, and internal errors all
continue (exit 0).  Denials are the ONLY hard outcome, and they carry
the policy reason.

Stdlib only, no network, milliseconds — same shim doctrine as
bugwolf_stop_hook.py.

stdin event (Claude Code PreToolUse):
    {"tool_name": "Bash", "tool_input": {"command": "..."},
     "session_id": "...", ...}
    {"tool_name": "WebFetch", "tool_input": {"url": "..."}, ...}
"""

import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

CONTRACT_SCHEMA = "bugwolf-scope-contract/v1"
HOOK_SCHEMA = "bugwolf-pretool-scope/v1"

_LOOPBACK_HOSTS = {"localhost", "::1"}


def _contract_path() -> Path:
    root = Path(os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
    return root / "state" / "scope_contract.json"


def load_contract() -> dict:
    """The mission's declared boundary ({} when none — inert mode)."""
    try:
        data = json.loads(_contract_path().read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - missing/corrupt contract = inert
        return {}
    if not isinstance(data, dict) or data.get("schema") != CONTRACT_SCHEMA:
        return {}
    return data


def _journal(mission_id: str, line: dict) -> None:
    """Append the audit record (best-effort; never fatal)."""
    try:
        root = Path(os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
        d = root / "state" / "orchestrator" / (mission_id or "default")
        d.mkdir(parents=True, exist_ok=True)
        with (d / "hooks.jsonl").open("a") as fh:
            fh.write(json.dumps(line, default=str) + "\n")
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Host extraction (bounded, honest, conservative — denials are disruptive,
# so only unambiguous network targets are candidates)
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s'\"<>\\]+")
# curl -H 'Host: evil.test'  /  --header "Host: evil.test"
_HOST_HEADER_RE = re.compile(
    r"(?:--header|-H)\s+['\"]?host:\s*([^\s'\"']+)", re.IGNORECASE)
# Network-tool target flags: curl/wget httpx nuclei ffuf ... -u|--url|-t|--target
_TARGET_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-u|--url|-t|--target|-login-url)\s+['\"]?"
    r"(https?://[^\s'\"<>]+|"
    r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|"
    r"[\w.-]+\.[A-Za-z]{2,24}(?::\d+)?)", re.IGNORECASE)


def _host_of(value: str) -> str:
    """Hostname from a URL/host/IP token (lowercase, brackets stripped)."""
    token = value.strip().rstrip(".,;")
    if "://" not in token:
        token = "//" + token
    try:
        return (urlparse(token).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_HOSTS:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255
                                   for p in parts) and parts[0] == "127"


def extract_hosts(tool_name: str, tool_input: dict) -> list:
    """Candidate outbound hosts for one tool call (deduped, order-stable)."""
    hosts: list = []
    if tool_name == "WebFetch":
        url = str((tool_input or {}).get("url") or "")
        host = _host_of(url)
        if host:
            hosts.append(host)
        return hosts
    if tool_name != "Bash":
        return hosts
    command = str((tool_input or {}).get("command") or "")
    if not command:
        return hosts
    for match in _URL_RE.findall(command):
        host = _host_of(match)
        if host:
            hosts.append(host)
    for match in _HOST_HEADER_RE.findall(command):
        host = _host_of(match)
        if host:
            hosts.append(host)
    for match in _TARGET_FLAG_RE.findall(command):
        host = _host_of(match)
        if host:
            hosts.append(host)
    out: list = []
    for host in hosts:
        if host and host not in out:
            out.append(host)
    return out


# ---------------------------------------------------------------------------
# The boundary decision (mirrors ScopeGate._authorized_host exactly — the
# hook must agree with the in-engine gate or the doctrine is worthless)
# ---------------------------------------------------------------------------

def _denied(contract: dict, host: str) -> bool:
    for entry in contract.get("deny_entries") or []:
        entry = str(entry).lower().rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def _authorized(contract: dict, host: str) -> bool:
    target = str(contract.get("target") or "").lower().rstrip(".")
    if not target:
        return False
    if host == target or host.endswith("." + target):
        return True
    for entry in contract.get("extra_hosts") or []:
        entry = str(entry).lower().rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    # Loopback is authorized only for local campaigns (same rule as the
    # engine gate): a remote-target mission never needs us fetching 127.0.0.1.
    if _is_loopback(host) and _is_loopback(target):
        return True
    return False


def evaluate(tool_name: str, tool_input: dict,
             contract: dict) -> tuple:
    """-> (verdict, reason, hosts).  verdict: 'allow' | 'deny' | 'inert'."""
    if not contract:
        return "inert", "no scope contract (no active mission)", []
    hosts = extract_hosts(tool_name, tool_input)
    if not hosts:
        return "allow", "no outbound host candidate", []
    mission_id = str(contract.get("mission_id") or "")
    for host in hosts:
        if _denied(contract, host):
            return "deny", (
                f"BugWolf scope gate: host {host!r} is EXCLUDED by policy "
                f"(deny-entry beats any wildcard; mission {mission_id!r})."
            ), hosts
        if not _authorized(contract, host):
            return "deny", (
                f"BugWolf scope gate: host {host!r} is outside the "
                f"operator-declared scope (target {contract.get('target')!r}, "
                f"mission {mission_id!r}). Out-of-scope requests are refused "
                f"at the harness level — declare it via --scope or use an "
                f"in-scope host."), hosts
    return "allow", "all candidate hosts in scope", hosts


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0                      # malformed event: fail open
    if not isinstance(event, dict):
        return 0
    tool_name = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    try:
        contract = load_contract()
        verdict, reason, hosts = evaluate(tool_name, tool_input, contract)
    except Exception:  # noqa: BLE001 - a hook bug must never block work
        return 0
    if verdict == "deny":
        # Belt and braces: the structured decision (some harness versions
        # read stdout JSON on any exit code) AND exit 2 (the un-overridable
        # block that feeds stderr back to the model).
        print(json.dumps({
            "schema": HOOK_SCHEMA,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }))
        print(reason, file=sys.stderr)
        _journal(str(contract.get("mission_id") or ""), {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hook": "pretool-scope", "event": "denied",
            "tool": tool_name, "hosts": hosts,
            "target": contract.get("target"),
            "mission_id": contract.get("mission_id"),
        })
        return 2
    return 0


def clear() -> int:
    """Operator escape hatch: remove the contract (hook goes inert)."""
    try:
        _contract_path().unlink(missing_ok=True)
        print("scope contract cleared (hook inert)")
    except Exception as exc:  # noqa: BLE001
        print(f"clear failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clear":
        raise SystemExit(clear())
    raise SystemExit(main())
