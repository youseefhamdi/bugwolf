#!/usr/bin/env python3
"""BugWolf binary RE adapter v1.24.1+.

Unified interface to native binary reverse-engineering tooling:

  - Ghidra       (headless analyzer; emit function signatures, CFG, strings)
  - GhidrA       (alias)
  - Binary Ninja (headless; emit function signatures, types)
  - BinaryNinja  (alias)
  - radare2 / r2 (CLI; emit function list, xrefs, strings)
  - rizin        (alias)
  - Frida        (runtime instrumentation; emit hook scripts)
  - objdump      (fallback; emit function symbols)
  - nm           (fallback; emit symbols)
  - strings      (fallback; emit printable strings)

For each tool, this adapter:
  1. Verifies availability (shutil.which / importlib.util).
  2. Generates a deterministic invocation command for the target binary.
  3. Parses output to a uniform JSONL record.
  4. Persists findings to state/ for the mission_runner to ingest.

The adapter does NOT call the RE tools itself (operator runs them).
It generates specs + runbooks + parses output when present.

Output schema:
  {
    "schema": "bugwolf-binary-re/v1",
    "tool": "ghidra",
    "binary": "/path/to/binary",
    "function": "process_request",
    "address": "0x401000",
    "signature": "int process_request(void *req)",
    "issue": "missing length check",
    "severity": "high",
    "evidence": "..."
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


SCHEMA = "bugwolf-binary-re/v1"

TOOLS = {
    "ghidra":      "NSA Ghidra headless analyzer",
    "binja":       "Binary Ninja headless",
    "r2":          "radare2 CLI",
    "rizin":       "rizin CLI (radare2 fork)",
    "frida":       "Frida runtime instrumentation",
    "objdump":     "binutils objdump (fallback)",
    "nm":          "binutils nm (fallback)",
    "strings":     "binutils strings (fallback)",
}


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

def is_available(tool: str) -> bool:
    """True if the tool is on PATH or importable."""
    t = tool.lower()
    binary_map = {
        "ghidra":   "analyzeHeadless",
        "binja":    "binaryninja",
        "r2":       "r2",
        "rizin":    "rizin",
        "objdump":  "objdump",
        "nm":       "nm",
        "strings":  "strings",
        "frida":    "frida",
    }
    if t == "frida":
        try:
            import frida  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False
    bin_ = binary_map.get(t)
    return bool(bin_ and shutil.which(bin_))


# ---------------------------------------------------------------------------
# Spec generators
# ---------------------------------------------------------------------------

def spec_ghidra(binary: str, *, project: str = "bugwolf_proj",
                output: str = "ghidra-out") -> Dict[str, Any]:
    """Ghidra headless analysis spec.

    The PostScript exports a function list + decompiled signatures to JSON.
    """
    return {
        "tool": "ghidra",
        "binary": binary,
        "project": project,
        "output": output,
        "post_script": textwrap.dedent('''
            # @category BugWolf
            from ghidra.app.script import GhidraScript
            from ghidra.program.model.listing import Function
            import json

            out = []
            fm = currentProgram.getFunctionManager()
            for func in fm.getFunctions(True):
                entry = func.getEntryPoint()
                sig = func.getSignature()
                out.append({
                    "name": func.getName(),
                    "address": str(entry),
                    "signature": str(sig) if sig else "",
                    "size": func.getBody().getNumAddresses(),
                })
            with open("functions.json", "w") as f:
                json.dump(out, f, indent=2)
            print(f"Exported {len(out)} functions to functions.json")
        '''),
        "run": (
            f"analyzeHeadless {project} {binary} "
            f"-postScript /tmp/bugwolf_postscript.py "
            f"-deleteProject"
        ),
    }


def spec_r2(binary: str, *, output: str = "r2-functions.json") -> Dict[str, Any]:
    """radare2 function-list + strings spec."""
    return {
        "tool": "r2",
        "binary": binary,
        "output": output,
        "run": (
            f"r2 -q -c 'aaa; afl~[0-9] > functions.txt; izz~[A-Za-z] > strings.txt; "
            f"pdf @ main > main_decompile.txt' {binary}"
        ),
        "parse": "functions.txt + strings.txt + main_decompile.txt",
    }


def spec_rizin(binary: str, *, output: str = "rizin-functions.json") -> Dict[str, Any]:
    return spec_r2(binary, output=output) | {"tool": "rizin"}


def spec_objdump(binary: str) -> Dict[str, Any]:
    return {
        "tool": "objdump",
        "binary": binary,
        "run": f"objdump -d {binary} | head -2000",
        "parse": "stdout (TUI-style disassembly)",
    }


def spec_nm(binary: str) -> Dict[str, Any]:
    return {
        "tool": "nm",
        "binary": binary,
        "run": f"nm -D {binary} 2>/dev/null || nm {binary}",
        "parse": "stdout (symbol table)",
    }


def spec_strings(binary: str, *, min_length: int = 6) -> Dict[str, Any]:
    return {
        "tool": "strings",
        "binary": binary,
        "run": f"strings -n {min_length} {binary}",
        "parse": "stdout (printable strings)",
    }


def spec_frida(binary: str, *, target_func: str = "main",
               output: str = "frida-trace.json") -> Dict[str, Any]:
    """Frida runtime hook spec — instrument a function and trace args."""
    return {
        "tool": "frida",
        "binary": binary,
        "target_func": target_func,
        "output": output,
        "script": textwrap.dedent(f'''
            import frida
            import json
            import sys

            session = frida.attach("{binary}")
            script = session.create_script(\"""
            var target = Module.findExportByName(null, "{target_func}");
            if (target) {{
                Interceptor.attach(target, {{
                    onEnter: function(args) {{
                        console.log(JSON.stringify({{
                            event: "enter",
                            function: "{target_func}",
                            args: [args[0].toString(), args[1].toString()],
                        }}));
                    }},
                }});
            }}
            \""")
            script.load()
            import time; time.sleep(5)
            session.detach()
        '''),
        "run": "python3 frida_hook.py",
    }


import textwrap  # late import for spec_ghidra/spec_frida

_SPEC_DISPATCH = {
    "ghidra": spec_ghidra,
    "r2": spec_r2,
    "rizin": spec_rizin,
    "objdump": spec_objdump,
    "nm": spec_nm,
    "strings": spec_strings,
    "frida": spec_frida,
}


def generate_spec(tool: str, **kwargs) -> Dict[str, Any]:
    if tool not in _SPEC_DISPATCH:
        raise ValueError(f"unknown tool: {tool}")
    spec = _SPEC_DISPATCH[tool](**kwargs)
    spec["available"] = is_available(tool)
    spec["generated_at"] = datetime.now(timezone.utc).isoformat()
    return spec


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

def parse_ghidra_functions(functions_json: Path) -> List[Dict[str, Any]]:
    if not functions_json.exists():
        return []
    try:
        data = json.loads(functions_json.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out: List[Dict[str, Any]] = []
    for entry in data:
        out.append({
            "schema": SCHEMA,
            "tool": "ghidra",
            "function": entry.get("name", ""),
            "address": entry.get("address", ""),
            "signature": entry.get("signature", ""),
            "size": entry.get("size", 0),
            "issue": "function-exported",
            "severity": "info",
            "evidence": entry.get("signature", "")[:200],
        })
    return out


def parse_objdump(stdout: str, binary: str) -> List[Dict[str, Any]]:
    """Parse objdump output for function symbols and suspicious gadgets."""
    findings: List[Dict[str, Any]] = []
    if not stdout:
        return findings
    for line in stdout.splitlines():
        # <address> <flags> <section> <size> <name>
        m = re.match(r"^([0-9a-f]+)\s+<\.?(.*?)>:$", line)
        if m:
            findings.append({
                "schema": SCHEMA,
                "tool": "objdump",
                "binary": binary,
                "function": m.group(2),
                "address": "0x" + m.group(1),
                "issue": "function-symbol",
                "severity": "info",
                "evidence": line.strip(),
            })
    return findings


import re  # late import for parse_objdump


def parse_nm(stdout: str, binary: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, typ, name = parts[0], parts[1], parts[2]
        findings.append({
            "schema": SCHEMA,
            "tool": "nm",
            "binary": binary,
            "function": name,
            "address": addr,
            "type": typ,
            "issue": "symbol",
            "severity": "info",
            "evidence": line.strip(),
        })
    return findings


def parse_strings(stdout: str, binary: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sensitive_patterns = (
        "password", "secret", "api_key", "apikey", "token",
        "private_key", "BEGIN RSA", "BEGIN OPENSSH", "AKIA",
    )
    for i, line in enumerate(stdout.splitlines(), 1):
        if not line.strip():
            continue
        if any(pat in line.lower() for pat in sensitive_patterns):
            findings.append({
                "schema": SCHEMA,
                "tool": "strings",
                "binary": binary,
                "function": "string-table",
                "address": "0x" + format(i, "08x"),
                "issue": "sensitive-string",
                "severity": "high" if "key" in line.lower() else "medium",
                "evidence": line[:200],
            })
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="BugWolf binary RE adapter")
    sub = p.add_subparsers(dest="cmd", required=True)

    g_spec = sub.add_parser("spec", help="Generate a spec for a tool")
    g_spec.add_argument("--tool", required=True, choices=list(TOOLS.keys()))
    g_spec.add_argument("--binary", required=True, help="Binary path")
    g_spec.add_argument("--output", help="Output spec path")
    g_spec.add_argument("--target-func", help="Target function (frida)")

    g_run = sub.add_parser("parse", help="Parse tool output")
    g_run.add_argument("--tool", required=True, choices=["ghidra", "objdump", "nm", "strings"])
    g_run.add_argument("--binary", required=True)
    g_run.add_argument("--input", required=True, help="Path to output file")
    g_run.add_argument("--output", help="Output JSONL path")

    args = p.parse_args()

    if args.cmd == "spec":
        kwargs: Dict[str, Any] = {"binary": args.binary}
        if args.target_func:
            kwargs["target_func"] = args.target_func
        spec = generate_spec(args.tool, **kwargs)
        if args.output:
            Path(args.output).write_text(json.dumps(spec, indent=2))
            print(f"[+] spec written to {args.output}")
        else:
            print(json.dumps(spec, indent=2))
        return 0

    if args.cmd == "parse":
        inp = Path(args.input)
        if not inp.exists():
            print(f"[!] input not found: {args.input}", file=sys.stderr)
            return 2
        if args.tool == "ghidra":
            findings = parse_ghidra_functions(inp)
        elif args.tool == "objdump":
            findings = parse_objdump(inp.read_text(), args.binary)
        elif args.tool == "nm":
            findings = parse_nm(inp.read_text(), args.binary)
        else:
            findings = parse_strings(inp.read_text(), args.binary)
        out = sys.stdout
        if args.output:
            out = path_open_text(args.output, "w")
        for f in findings:
            out.write(json.dumps(f) + "\n")
        if out is not sys.stdout:
            out.close()
        print(f"[+] {len(findings)} records parsed", file=sys.stderr)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
