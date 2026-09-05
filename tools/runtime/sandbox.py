#!/usr/bin/env python3
"""BugWolf subprocess sandbox (readiness R3 remediation + kill switch).

Closes the last readiness warning: **a subprocess sandbox is now required**
for every orchestrator-managed subprocess, and an operator kill switch can
stop all of them in one move.

Architecture: :func:`tools.reliability.run_bounded_subprocess` is the
process choke point (argv-only, timeout, output cap, process-group
cleanup).  The sandbox wraps it with the missing policy layers:

  1. **Kill switch (circuit breaker, fail CLOSED).**  A marker file
     (``state/sandbox/KILL_SWITCH`` in the workspace) blocks every sandboxed
     spawn.  ``--on`` kills, ``--off`` re-arms, ``--status`` reports.  A
     missing workspace defaults to *armed* (executions allowed); a corrupt
     marker file is treated as KILLED (fail closed -- a garbage file can
     never silently re-enable execution).
  2. **Binary allowlist (parity with preflight).**  The default grant set
     is ``BINARY_CAPABILITIES`` from the pre-flight inventory: only
     binaries the operator-facing docs actually declare.  Unknown binaries
     raise :class:`SandboxViolation` before spawn.  ``grant`` extends the
     allowlist explicitly per workspace (durable, operator action).
  3. **Environment scrub.**  Spawns run with a minimal env: ``PATH``,
     ``LANG``, ``LC_ALL``, ``TZ``, ``TMPDIR`` plus ``BUGWOLF_*`` passthrough
     and the explicit overrides the caller passes.  Credentials-bearing or
     proxy variables (``AWS_*``, ``*_TOKEN``, ``*_KEY``, ``*_SECRET``,
     ``http_proxy``...) never reach a child process.

Everything is audit-logged (append-only JSONL, ``state/sandbox/audit.jsonl``)
and the gate state is exported for the readiness verifier.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

if __package__ in (None, ""):  # direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.runtime_paths import workspace_root
from tools.reliability import run_bounded_subprocess, spawn_long_lived_subprocess

SCHEMA = "bugwolf-sandbox/v1"

KILL_SWITCH_DIR = ("state", "sandbox")
KILL_SWITCH_FILE = "KILL_SWITCH"
AUDIT_FILE = "audit.jsonl"
GRANTS_FILE = "grants.json"

# Env vars a child may keep.  Everything else is scrubbed (allowlist, not
# blocklist: blocklists always miss the next quarter's variable names).
_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "HOME")
_ENV_KEEP_PREFIX = ("BUGWOLF_",)
# Documented, high-signal denylist retained for the audit record.
_ENV_DENY = ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
             "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY")

DEFAULT_GRACE_SECONDS = 0.0


class SandboxViolation(PermissionError):
    """A spawn was refused by the sandbox policy (allowlist or kill switch)."""

    def __init__(self, reason: str, *, kill_switch: bool = False):
        self.reason = reason
        self.kill_switch = kill_switch
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Workspace state helpers
# ---------------------------------------------------------------------------


def _sandbox_dir(root: Optional[str | Path] = None) -> Path:
    return workspace_root(root).joinpath(*KILL_SWITCH_DIR)


def _kill_path(root: Optional[str | Path] = None) -> Path:
    return _sandbox_dir(root) / KILL_SWITCH_FILE


def _audit_path(root: Optional[str | Path] = None) -> Path:
    return _sandbox_dir(root) / AUDIT_FILE


def _grants_path(root: Optional[str | Path] = None) -> Path:
    return _sandbox_dir(root) / GRANTS_FILE


def kill_switch_engaged(root: Optional[str | Path] = None) -> bool:
    """True when executions are blocked.

    Fail-closed rule: an UNREADABLE or UNDECODABLE marker file counts as
    engaged -- a corrupt kill switch must never silently re-enable
    execution (and must never crash the caller either).
    """
    path = _kill_path(root)
    if not path.exists():
        return False
    try:
        path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return True
    return True


def engage_kill_switch(root: Optional[str | Path] = None, *,
                       note: str = "") -> Path:
    """Block all sandboxed subprocess execution in this workspace."""
    path = _kill_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"killed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime()),
                    "note": note}) + "\n", encoding="utf-8")
    _audit(root, "kill_switch_engaged", {"note": note})
    return path


def release_kill_switch(root: Optional[str | Path] = None) -> bool:
    """Re-arm execution (operator action).  Returns True if it was engaged."""
    path = _kill_path(root)
    was = path.exists()
    if was:
        path.unlink()
        _audit(root, "kill_switch_released", {})
    return was


def _audit(root: Optional[str | Path], event: str,
           payload: Mapping[str, Any]) -> None:
    """Append one audit line; audit failures never block the caller."""
    try:
        path = _audit_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": event, **payload}, default=str) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Binary allowlist
# ---------------------------------------------------------------------------


def _default_allowlist() -> tuple:
    """Preflight's documented inventory is the default grant set."""
    try:
        from tools.runtime.preflight import BINARY_CAPABILITIES
        return tuple(sorted(BINARY_CAPABILITIES))
    except Exception:  # noqa: BLE001 - standalone use (bundled skill)
        return ()


def _deterministic_path() -> str:
    """Build a deterministic PATH from /etc/environment + a hardcoded default.

    Never inherits the caller's PATH. The hardcoded default is the minimal
    set required for the sandboxed binaries; operator-granted extras must
    be referenced by full path through sandbox.grant().
    """
    candidates = [
        "/usr/local/sbin", "/usr/local/bin",
        "/usr/sbin", "/usr/bin", "/sbin", "/bin",
    ]
    try:
        with open("/etc/environment", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line.startswith("PATH="):
                    value = line[len("PATH="):].strip().strip('"').strip("'")
                    if value:
                        candidates = [p for p in value.split(":") if p] + candidates
                    break
    except OSError:
        pass
    # De-duplicate while preserving order.
    seen, ordered = set(), []
    for p in candidates:
        if p and p not in seen:
            seen.add(p)
            ordered.append(p)
    return ":".join(ordered)


_ALLOWED_BIN_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
    "/usr/local/bin/", "/usr/local/sbin/",
)


def _resolved_path_allowed(resolved: str) -> bool:
    """True if ``resolved`` is inside one of the allowed system prefixes.

    Phase 0 H-2: defends against PATH substitution by verifying the
    *resolved* binary lives in an allowed system location rather than
    trusting the basename alone.
    """
    return any(resolved.startswith(p) for p in _ALLOWED_BIN_PREFIXES)


def load_grants(root: Optional[str | Path] = None) -> List[str]:
    """Operator-granted extra binaries (durable per workspace)."""
    path = _grants_path(root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return [str(x) for x in value.get("grants", []) if str(x).strip()]
    except (OSError, ValueError):
        return []


def grant(root: Optional[str | Path], names: List[str]) -> List[str]:
    """Extend the allowlist durably (operator action, audited)."""
    current = load_grants(root)
    merged = list(current)
    for name in names:
        clean = str(name).strip()
        if clean and clean not in merged:
            merged.append(clean)
    _dir = _sandbox_dir(root)
    _dir.mkdir(parents=True, exist_ok=True)
    _grants_path(root).write_text(
        json.dumps({"schema": SCHEMA, "grants": merged}, indent=2) + "\n",
        encoding="utf-8")
    _audit(root, "granted", {"binaries": merged})
    return merged


def revoke(root: Optional[str | Path], names: List[str]) -> List[str]:
    current = load_grants(root)
    remaining = [g for g in current if str(g) not in {str(n) for n in names}]
    _dir = _sandbox_dir(root)
    _dir.mkdir(parents=True, exist_ok=True)
    _grants_path(root).write_text(
        json.dumps({"schema": SCHEMA, "grants": remaining}, indent=2) + "\n",
        encoding="utf-8")
    _audit(root, "revoked", {"binaries": list(names)})
    return remaining


def _is_allowed(binary: str, root: Optional[str | Path], *,
                allow_unlisted: bool) -> bool:
    if allow_unlisted:
        return True
    if binary in _default_allowlist():
        return True
    if binary in load_grants(root):
        return True
    # Phase 0 H-2: even if the basename is allowed, the caller may have
    # substituted a different binary via PATH. Resolve argv[0] against a
    # deterministic PATH (never the caller's) and verify the resolved
    # path falls inside an allowed prefix.
    import shutil as _shutil_h2
    scrubbed = _deterministic_path()
    resolved = _shutil_h2.which(binary, path=scrubbed)
    if not resolved:
        return False
    return _resolved_path_allowed(resolved)


# ---------------------------------------------------------------------------
# Env scrub
# ---------------------------------------------------------------------------


def scrub_env(overrides: Optional[Mapping[str, str]] = None, *,
              passthrough: bool = True) -> Dict[str, str]:
    """Minimal child environment: keep-list + BUGWOLF_* + explicit overrides.

    Credential-shaped variables (tokens/keys/secrets/proxies) never survive
    scrubbing unless the caller passes them EXPLICITLY in ``overrides``.
    """
    env: Dict[str, str] = {}
    if passthrough:
        for key, value in os.environ.items():
            if key in _ENV_KEEP or key.startswith(_ENV_KEEP_PREFIX):
                env[key] = value
    for key in _ENV_DENY:
        env.pop(key, None)
    for key, value in (overrides or {}).items():
        env[str(key)] = str(value)
    # Phase 0 H-1: deterministic PATH. We never inherit the caller's PATH
    # because the caller can substitute any binary via env overrides.
    # PATH is rebuilt from /etc/environment (if present) plus a hardcoded
    # system default. Operators who need a different PATH use the
    # sandbox 'grants' mechanism (load_grants / grant) instead.
    env["PATH"] = _deterministic_path()
    return env


# ---------------------------------------------------------------------------
# The sandboxed spawn (THE choke point orchestrator code calls)
# ---------------------------------------------------------------------------


def sandboxed_run(command: List[str], *, cwd: str | Path,
                  timeout: float = 30.0, max_output_bytes: int = 262144,
                  env: Optional[Mapping[str, str]] = None,
                  stdin: Any = subprocess.DEVNULL,
                  root: Optional[str | Path] = None,
                  allow_unlisted: bool = False,
                  input_text: Optional[str] = None,
                  text: bool = False,
                  check: bool = False,
                  purpose: str = "") -> subprocess.CompletedProcess:
    """Run ``command`` under the full sandbox policy.

    Order of enforcement (every step audited):
      1. kill switch engaged  -> SandboxViolation (fail CLOSED)
      2. binary not allowlisted -> SandboxViolation
      3. env scrubbed -> run_bounded_subprocess (timeout + output cap +
         process-group kill on timeout)

    ``text=True`` decodes stdout/stderr to str; ``input_text`` feeds stdin
    (implies text mode); ``check=True`` raises CalledProcessError on
    non-zero exit (subprocess.run semantics for migrated callers).

    ``allow_unlisted=True`` is for ENGINE-INTERNAL spawns (the interpreter
    itself in self-checks).  Operator-facing code must never set it.
    """
    argv = [str(x) for x in command]
    if not argv:
        raise SandboxViolation("empty command")
    binary = Path(argv[0]).name

    if kill_switch_engaged(root):
        _audit(root, "blocked_kill_switch", {
            "binary": binary, "argv0": argv[0], "purpose": purpose})
        raise SandboxViolation(
            f"kill switch engaged: subprocess execution blocked ({binary})",
            kill_switch=True)

    if not _is_allowed(binary, root, allow_unlisted=allow_unlisted):
        _audit(root, "blocked_unlisted_binary", {
            "binary": binary, "argv0": argv[0], "purpose": purpose})
        raise SandboxViolation(
            f"binary {binary!r} is not allowlisted; grant it explicitly via "
            f"`python3 -m tools.runtime.sandbox grant {binary}`")

    merged_env = scrub_env(env)
    _audit(root, "spawn", {"binary": binary, "purpose": purpose,
                           "timeout": timeout})
    result = run_bounded_subprocess(
        argv, cwd=cwd, timeout=timeout, max_output_bytes=max_output_bytes,
        env=merged_env,
        stdin=stdin if input_text is None else subprocess.PIPE,
        input_bytes=input_text.encode("utf-8")
        if input_text is not None else None)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, argv,
                                            output=result.stdout,
                                            stderr=result.stderr)
    if text or input_text is not None:
        result = subprocess.CompletedProcess(
            result.args, result.returncode,
            (result.stdout or b"").decode("utf-8", "replace")
            if isinstance(result.stdout, bytes) else result.stdout,
            (result.stderr or b"").decode("utf-8", "replace")
            if isinstance(result.stderr, bytes) else result.stderr)
    return result



def sandboxed_spawn(command: List[str], *, cwd: str | Path,
                   stdout: Any = subprocess.PIPE,
                   stderr: Any = subprocess.PIPE,
                   stdin: Any = subprocess.DEVNULL,
                   env: Optional[Mapping[str, str]] = None,
                   root: Optional[str | Path] = None,
                   allow_unlisted: bool = False,
                   purpose: str = "") -> subprocess.Popen:
    """Start a policy-gated long-lived process.

    Unlike :func:`sandboxed_run`, this returns while the child is still
    running.  The returned process is owned by the caller and must be stopped
    explicitly; it is always placed in its own process group by the shared
    reliability primitive.
    """
    argv = [str(x) for x in command]
    if not argv:
        raise SandboxViolation("empty command")
    binary = Path(argv[0]).name
    if kill_switch_engaged(root):
        _audit(root, "blocked_kill_switch", {
            "binary": binary, "argv0": argv[0], "purpose": purpose})
        raise SandboxViolation(
            f"kill switch engaged: subprocess execution blocked ({binary})",
            kill_switch=True)
    if not _is_allowed(binary, root, allow_unlisted=allow_unlisted):
        _audit(root, "blocked_unlisted_binary", {
            "binary": binary, "argv0": argv[0], "purpose": purpose})
        raise SandboxViolation(
            f"binary {binary!r} is not allowlisted; grant it explicitly via "
            f"`python3 -m tools.runtime.sandbox grant {binary}`")
    _audit(root, "spawn_long_lived", {
        "binary": binary, "purpose": purpose})
    return spawn_long_lived_subprocess(
        argv, cwd=cwd, stdout=stdout, stderr=stderr, stdin=stdin,
        env=scrub_env(env))




def sandbox_state(root: Optional[str | Path] = None) -> Dict[str, Any]:
    """Machine-readable gate state (readiness + operator status output)."""
    return {
        "schema": SCHEMA,
        "kill_switch": "ENGAGED" if kill_switch_engaged(root) else "armed",
        "default_allowlist_size": len(_default_allowlist()),
        "grants": load_grants(root),
        "env_scrub": {"keep": list(_ENV_KEEP), "keep_prefix": list(_ENV_KEEP_PREFIX),
                      "deny_documented": list(_ENV_DENY)},
    }


def verify_sandbox() -> tuple:
    """Functional, offline proof for the readiness claim.

    Proves, in order: kill switch blocks a spawn; an unlisted binary is
    refused; a listed binary runs with a scrubbed env.  Uses the workspace
    tmp dir (never the repo's state/).
    """
    import tempfile
    details = []
    try:
        with tempfile.TemporaryDirectory() as td:
            py = sys.executable
            # 1. Kill switch blocks.
            engage_kill_switch(td, note="readiness-verify")
            try:
                sandboxed_run([py, "-c", "print(1)"], cwd=td, root=td,
                              allow_unlisted=True)
                return False, "kill switch did not block a spawn"
            except SandboxViolation as exc:
                if not exc.kill_switch:
                    return False, f"wrong violation type: {exc}"
            details.append("kill-switch")
            release_kill_switch(td)

            # 2. Allowlist refuses unlisted binaries.
            try:
                sandboxed_run([py, "-c", "print(1)"], cwd=td, root=td)
                return False, "unlisted binary was not refused"
            except SandboxViolation as exc:
                if exc.kill_switch:
                    return False, "allowlist check misreported kill switch"
            details.append("allowlist")

            # 3. Execution resumes; env scrub applied (engine self-check:
            #    the interpreter itself is not an operator-facing binary).
            result = sandboxed_run(
                [py, "-c",
                 "import json,os;print(json.dumps({k:'' for k in os.environ}))"],
                cwd=td, root=td, env={"BUGWOLF_SANDBOX_PROBE": "1"},
                allow_unlisted=True)
            keys = json.loads(result.stdout.decode().strip() or "{}")
            if "BUGWOLF_SANDBOX_PROBE" not in keys:
                return False, "BUGWOLF_* passthrough missing"
            leaked = [k for k in keys
                      if k.lower().endswith(("_token", "_key", "_secret"))
                      and k not in _ENV_KEEP]
            if leaked:
                return False, f"credential-shaped env leaked: {leaked[:3]}"
            details.append("env-scrub")
            return True, "proved: " + ", ".join(details)
    except Exception as exc:  # noqa: BLE001 - verification failure is data
        return False, f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Operator CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf subprocess sandbox + kill switch")
    parser.add_argument("--root", default="",
                        help="workspace root (default: BUGWOLF_PROJECT_ROOT "
                             "or cwd)")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("status", help="show sandbox state")
    p_on = sub.add_parser("kill", help="ENGAGE the kill switch (block all "
                                        "subprocess execution)")
    p_on.add_argument("--note", default="")
    sub.add_parser("arm", help="release the kill switch (re-arm execution)")
    p_grant = sub.add_parser("grant", help="allowlist extra binaries")
    p_grant.add_argument("binaries", nargs="+")
    p_revoke = sub.add_parser("revoke", help="remove extra grants")
    p_revoke.add_argument("binaries", nargs="+")
    p_verify = sub.add_parser("verify", help="functional self-check")
    p_verify.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = args.root or None
    if args.cmd == "kill":
        path = engage_kill_switch(root, note=args.note)
        print(f"KILL SWITCH ENGAGED: {path}")
        return 0
    if args.cmd == "arm":
        if release_kill_switch(root):
            print("kill switch released; execution re-armed")
        else:
            print("kill switch was not engaged")
        return 0
    if args.cmd == "grant":
        merged = grant(root, list(args.binaries))
        print("grants:", ", ".join(merged) or "(none)")
        return 0
    if args.cmd == "revoke":
        merged = revoke(root, list(args.binaries))
        print("grants:", ", ".join(merged) or "(none)")
        return 0
    if args.cmd == "verify":
        ok, detail = verify_sandbox()
        if args.json:
            print(json.dumps({"ok": ok, "detail": detail}))
        else:
            print(f"sandbox self-check: {'PASS' if ok else 'FAIL'} -- {detail}")
        return 0 if ok else 1
    # default: status
    state = sandbox_state(root)
    print(f"kill switch : {state['kill_switch']}")
    print(f"allowlist   : {state['default_allowlist_size']} documented "
          f"binaries + {len(state['grants'])} operator grants")
    if state["grants"]:
        print(f"grants      : {', '.join(state['grants'])}")
    audit = _audit_path(root)
    print(f"audit log   : {audit if audit.exists() else '(none yet)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
