#!/usr/bin/env python3
"""BugWolf symbolic execution adapter v1.24.1+.

Unified interface to symbolic execution / abstract-interpretation engines:

  - angr       (binary symbolic execution, Python)
  - KLEE       (LLVM IR symbolic execution, CLI)
  - Mythril    (EVM symbolic execution, CLI)
  - Mythril-classic (alias)
  - Mythos     (alias)
  - Halmos     (SMT-based EVM symbolic execution, CLI)
  - Certora   (SMT-based Solidity verification, CLI)
  - Manticore  (binary symbolic execution, Python)

For each engine, this adapter:
  1. Checks binary / library availability (shutil.which / importlib.util).
  2. Builds a deterministic, scope-gated invocation command.
  3. Captures the engine output to a structured JSONL record.
  4. Records findings in a uniform schema so the mission_runner can ingest.

The adapter does NOT call the engine itself (operator runs the actual
analysis outside BugWolf). It generates the spec + runbook + parses the
output when present.

Output schema (one JSONL line per finding):
  {
    "schema": "bugwolf-symexec/v1",
    "engine": "mythril",
    "target": "0xabc...",
    "function": "withdraw()",
    "issue": "integer overflow",
    "severity": "high",
    "evidence": "...",
    "raw_path": "/path/to/output.json"
  }
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from tools.core.medium_safety import path_open_text
except Exception:  # pragma: no cover - tools.* not always importable
    def path_open_text(path, mode="r", **kw):  # type: ignore[no-redef]
        return open(path, mode, encoding=kw.get("encoding", "utf-8"),
                     errors=kw.get("errors", "replace"))


SCHEMA = "bugwolf-symexec/v1"

ENGINES = {
    "angr":       "Binary symbolic execution (Python, x86/ARM/MIPS)",
    "klee":       "LLVM IR symbolic execution (C/C++/Rust)",
    "manticore":  "Binary symbolic execution (Python, EVM-capable)",
    "mythril":    "EVM symbolic execution (Python/Solidity)",
    "halmos":     "SMT-based EVM symbolic execution (Solidity)",
    "certora":    "SMT-based Solidity verification (cloud)",
    "mythos":     "Alias for mythril",
}


def is_available(engine: str) -> bool:
    """True if the engine binary is on PATH or importable."""
    eng = engine.lower()
    if eng in ("angr", "manticore"):
        try:
            __import__(eng)
            return True
        except Exception:  # noqa: BLE001
            return False
    binary_map = {
        "klee": "klee",
        "mythril": "myth",
        "halmos": "halmos",
        "certora": "certoraRun",
    }
    bin_ = binary_map.get(eng)
    return bool(bin_ and shutil.which(bin_))


# ---------------------------------------------------------------------------
# Spec generators
# ---------------------------------------------------------------------------

def spec_angr(binary: str, *, target_func: Optional[str] = None,
              output: str = "angr-findings.json") -> Dict[str, Any]:
    """angr spec — a Python script that calls angr.Project and explores."""
    target_func = target_func or "main"
    return {
        "engine": "angr",
        "binary": binary,
        "target_func": target_func,
        "output": output,
        "script": f'''
import angr
import json
import sys

p = angr.Project("{binary}", auto_load_libs=False)
init_state = p.factory.entry_state()
sm = p.factory.simulation_manager(init_state)
sm.explore(find=lambda s: b"win" in s.posix.dumps(1),
            avoid=lambda s: b"lose" in s.posix.dumps(1))
for found in sm.found:
    out = {{
        "schema": "bugwolf-symexec/v1",
        "engine": "angr",
        "target": "{binary}",
        "function": "{target_func}",
        "issue": "path-constraint-satisfied",
        "severity": "medium",
        "evidence": str(found.posix.dumps(0))[:200],
    }}
    print(json.dumps(out))
''',
        "run": "python3 explore.py",
    }


def spec_klee(source: str, *, output: str = "klee-findings.json") -> Dict[str, Any]:
    """KLEE spec — build with -emit-llvm, then run klee."""
    return {
        "engine": "klee",
        "source": source,
        "output": output,
        "build": f"clang -I/usr/include -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone {source} -o {source}.bc",
        "run": f"klee --output-dir=klee-out {source}.bc",
        "parse": "klee-out/*.json",
    }


def spec_mythril(target: str, *, sol_file: Optional[str] = None,
                 output: str = "mythril-findings.json") -> Dict[str, Any]:
    """Mythril spec — analyze EVM bytecode or Solidity source."""
    if sol_file:
        cmd = f"myth analyze {sol_file}:{target} --output json"
    else:
        cmd = f"myth analyze {target} --output json"
    return {
        "engine": "mythril",
        "target": target,
        "sol_file": sol_file,
        "output": output,
        "run": cmd,
    }


def spec_halmos(contract: str, *, output: str = "halmos-findings.json") -> Dict[str, Any]:
    """Halmos spec — SMT-based EVM verification."""
    return {
        "engine": "halmos",
        "contract": contract,
        "output": output,
        "run": f"halmos --contract {contract} --output {output}",
    }


def spec_certora(spec_file: str, *, output: str = "certora-findings.json") -> Dict[str, Any]:
    """Certora spec — cloud verification."""
    return {
        "engine": "certora",
        "spec_file": spec_file,
        "output": output,
        "run": f"certoraRun {spec_file} --output {output}",
    }


def spec_manticore(bytecode: str, *, output: str = "manticore-findings.json") -> Dict[str, Any]:
    """Manticore spec — binary symbolic execution."""
    return {
        "engine": "manticore",
        "bytecode": bytecode,
        "output": output,
        "script": f'''
from manticore.ethereum import ManticoreEVM

m = ManticoreEVM()
account = m.create_account(balance=10**18)
user = m.create_account(balance=10**18)
contract = m.deploy_contract({bytecode}, owner=account)
symbolic_data = m.make_symbolic_buffer(320)
contract.f(symbolic_data, caller=user)
m.finalize()
print("findings: ", m.global_coverage)
''',
        "run": "python3 manticore_explore.py",
    }


_SPEC_DISPATCH = {
    "angr": spec_angr,
    "klee": spec_klee,
    "manticore": spec_manticore,
    "mythril": spec_mythril,
    "halmos": spec_halmos,
    "certora": spec_certora,
}


def generate_spec(engine: str, **kwargs) -> Dict[str, Any]:
    """Generate a spec dict for the given engine + kwargs."""
    if engine not in _SPEC_DISPATCH:
        raise ValueError(f"unknown engine: {engine}")
    spec = _SPEC_DISPATCH[engine](**kwargs)
    spec["available"] = is_available(engine)
    spec["generated_at"] = datetime.now(timezone.utc).isoformat()
    return spec


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

def parse_mythril_output(stdout: str) -> List[Dict[str, Any]]:
    """Parse Mythril JSON output into BugWolf symexec records."""
    findings: List[Dict[str, Any]] = []
    if not stdout:
        return findings
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, dict):
        return findings
    issues = data.get("issues", []) or data.get("results", [])
    for issue in issues:
        findings.append({
            "schema": SCHEMA,
            "engine": "mythril",
            "target": str(issue.get("address", "")),
            "function": str(issue.get("function", "")),
            "issue": str(issue.get("title", issue.get("description", ""))),
            "severity": str(issue.get("severity", "medium")).lower(),
            "evidence": json.dumps(issue)[:500],
        })
    return findings


def parse_klee_output(klee_dir: Path) -> List[Dict[str, Any]]:
    """Parse KLEE's per-path JSON output."""
    findings: List[Dict[str, Any]] = []
    if not klee_dir.exists():
        return findings
    for path in klee_dir.rglob("*.json"):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        findings.append({
            "schema": SCHEMA,
            "engine": "klee",
            "target": str(data.get("SourceLocation", "unknown")),
            "function": "klee-path",
            "issue": str(data.get("Termination", "path-constraint")),
            "severity": "medium",
            "evidence": json.dumps(data)[:500],
            "raw_path": str(path),
        })
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="BugWolf symbolic execution adapter")
    sub = p.add_subparsers(dest="cmd", required=True)

    g_spec = sub.add_parser("spec", help="Generate a spec for an engine")
    g_spec.add_argument("--engine", required=True, choices=list(ENGINES.keys()))
    g_spec.add_argument("--binary", help="Binary path (angr, manticore)")
    g_spec.add_argument("--source", help="Source path (klee)")
    g_spec.add_argument("--target", help="Target (mythril, halmos)")
    g_spec.add_argument("--contract", help="Contract name (halmos, certora)")
    g_spec.add_argument("--sol-file", help="Solidity file (mythril)")
    g_spec.add_argument("--output", help="Output spec path")

    g_run = sub.add_parser("parse", help="Parse engine output")
    g_run.add_argument("--engine", required=True, choices=["mythril", "klee"])
    g_run.add_argument("--input", required=True, help="Input path (file or dir)")
    g_run.add_argument("--output", help="Output JSONL path")

    args = p.parse_args()

    if args.cmd == "spec":
        kwargs: Dict[str, Any] = {}
        for k in ("binary", "source", "target", "contract", "sol_file"):
            v = getattr(args, k, None)
            if v:
                kwargs[k] = v
        spec = generate_spec(args.engine, **kwargs)
        if args.output:
            Path(args.output).write_text(json.dumps(spec, indent=2))
            print(f"[+] spec written to {args.output}")
        else:
            print(json.dumps(spec, indent=2))
        return 0

    if args.cmd == "parse":
        inp = Path(args.input)
        if args.engine == "mythril":
            findings = parse_mythril_output(inp.read_text())
        else:
            findings = parse_klee_output(inp)
        out = sys.stdout
        if args.output:
            out = path_open_text(args.output, "w")
        for f in findings:
            out.write(json.dumps(f) + "\n")
        if out is not sys.stdout:
            out.close()
        print(f"[+] {len(findings)} findings parsed", file=sys.stderr)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
