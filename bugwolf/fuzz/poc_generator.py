## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: tools/exploit_gen.py — PoC scaffolding conventions
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""PoC generator for the BugWolf fuzzing substrate.

:class:`PoCGenerator` turns a :class:`CrashReport` into a minimal
reproducer — either a Python script (when the crash is a fuzz input)
or a curl command (when the crash is HTTP-shaped).  The generator
NEVER raises; on failure it returns ``None``.
"""
from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


SCHEMA = "bugwolf-fuzz-poc-v1"


@dataclass(frozen=True)
class PoCResult:
    """One generated PoC artefact."""

    path: Path
    kind: str          # "python" | "curl" | "shell"
    crash_path: str
    category: str
    bytes_written: int


@dataclass
class PoCGenerator:
    """Auto-generate a minimal reproducer from a crash report."""

    output_dir: Path = field(default_factory=lambda: Path("/tmp/bugwolf-poc"))
    method_fallback: str = "POST"
    safe_methods: Tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

    # ----------------------------------------------------------------- API

    def generate(self, crash: Any) -> Optional[PoCResult]:
        """Produce a reproducer file for ``crash``.

        ``crash`` may be a :class:`CrashReport` or a plain dict; the
        function tolerates either.  Returns ``None`` when no PoC can
        be written.
        """
        try:
            payload = self._load_payload(crash)
            if payload is None:
                return None
            out_dir = Path(self.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            crash_path = str(getattr(crash, "crash_path", "") or "crash")
            category = str(getattr(crash, "category", "UNKNOWN") or "UNKNOWN")
            kind, body = self._build(crash, payload, category)
            fname = self._safe_filename(crash_path, category, kind)
            target = out_dir / fname
            target.write_text(body, encoding="utf-8")
            try:
                target.chmod(0o755)
            except Exception:
                pass
            return PoCResult(
                path=target,
                kind=kind,
                crash_path=crash_path,
                category=category,
                bytes_written=len(body),
            )
        except Exception:
            return None

    # ------------------------------------------------------------ internals

    def _load_payload(self, crash: Any) -> Optional[bytes]:
        """Read the original crash payload from disk if possible."""
        crash_path = getattr(crash, "crash_path", "") or ""
        if not crash_path:
            return None
        try:
            path = Path(crash_path)
            if not path.exists():
                return None
            return path.read_bytes()
        except Exception:
            return None

    def _build(self, crash: Any, payload: bytes, category: str) -> Tuple[str, str]:
        """Choose a PoC template and render it.

        Falls back to a Python driver when the payload isn't
        HTTP-shaped.
        """
        sample = payload[:2048]
        try:
            text = sample.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        first_line = text.splitlines()[0] if text else ""
        if first_line.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")):
            return "curl", self._curl_template(text, category)
        if sample.startswith(b"{") or sample.startswith(b"["):
            return "python", self._python_template(sample, category, json_payload=True)
        return "python", self._python_template(sample, category, json_payload=False)

    def _curl_template(self, text: str, category: str) -> str:
        first = (text.splitlines() or ["GET / HTTP/1.1"])[0]
        parts = first.split(" ")
        method = parts[0] if parts else "GET"
        if method not in self.safe_methods:
            method = self.method_fallback
        path = parts[1] if len(parts) > 1 else "/"
        headers: List[str] = []
        for line in text.splitlines()[1:]:
            if not line.strip() or line.lower() in ("\r", ""):
                continue
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if not k or not v:
                continue
            headers.append(f"  -H {k!r}: {v!r}")
        header_block = "\n".join(headers) if headers else "  # (no headers captured)"
        return textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            # Auto-generated reproducer for {category} crash.
            # Review before running.  No hardcoded UA; no file:// / gopher:// URLs.

            set -euo pipefail

            curl -sS -X {method} \\
            {header_block} \\
              --data-binary @- \\
              "https://TARGET_HOST{path}"
            """
        )

    def _python_template(self, sample: bytes, category: str, *, json_payload: bool) -> str:
        body_literal = self._python_repr(sample)
        if json_payload:
            driver = textwrap.dedent(
                f"""\
                import json
                import urllib.request

                payload = {body_literal}
                try:
                    obj = json.loads(payload.decode("utf-8"))
                except Exception:
                    obj = None

                req = urllib.request.Request(
                    "https://TARGET_HOST/api/endpoint",
                    data=payload,
                    headers={{"Content-Type": "application/json"}},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    print(resp.status, resp.read()[:200])
                """
            )
        else:
            driver = textwrap.dedent(
                f"""\
                import urllib.request

                payload = {body_literal}
                req = urllib.request.Request(
                    "https://TARGET_HOST/api/endpoint",
                    data=payload,
                    headers={{"Content-Type": "application/octet-stream"}},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    print(resp.status, resp.read()[:200])
                """
            )
        return (
            "#!/usr/bin/env python3\n"
            f"# Auto-generated reproducer for {category} crash.\n"
            "# Review before running.  Uses stdlib only.\n\n"
            + driver
        )

    def _python_repr(self, sample: bytes) -> str:
        # Avoid embedding massive binaries in the template; cap at 2 KiB.
        if len(sample) > 2048:
            sample = sample[:2048]
        return "b" + repr(sample)

    def _safe_filename(self, crash_path: str, category: str, kind: str) -> str:
        from pathlib import PurePosixPath

        stem = PurePosixPath(crash_path).stem or "crash"
        safe_stem = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in stem)[:48]
        return f"{safe_stem}_{category.lower()}.{kind}.sh"


__all__ = [
    "PoCGenerator",
    "PoCResult",
]
