## Source: BugWolf Phase 3.5 (in-house) — ChainPoCGenerator
## License: bugwolf-MIT
## Port: 2026-09-05

"""
bugwolf.chain.poc_chain — generates a Markdown + curl/bash reproducer
for a validated chain.

The generator is STUB-SAFE. It accepts either a
:class:`CrossProtocolChain` or a :class:`CrossTargetChain` and returns
the on-disk path of the produced PoC. If the chain is invalid (per
:class:`ChainValidator`) or scope forbids PoC generation, it returns
:class:`PoCUnavailable` instead of raising.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple, Union

from bugwolf.chain.builder import (
    Chain,
    CrossProtocolChain,
    CrossTargetChain,
    SCHEMA,
    Unavailable,
)
from bugwolf.chain.validator import ChainValidationResult, ChainValidator


# ---------------------------------------------------------------------------
# Fallback dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PoCUnavailable:
    """Returned when PoC generation cannot proceed."""

    reason: str
    code: str = "unavailable"
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "code": str(self.code),
            "reason": str(self.reason),
            "diagnostics": dict(self.diagnostics),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Anything that looks like a literal payload URL. CI gate: we must never
# write ``file://`` or ``gopher://`` payloads into a PoC reproducer.
_PAYLOAD_URL_RE = re.compile(r"(file|gopher|php|dict|jar|tftp)://", re.IGNORECASE)


def _safe_url(url: str) -> str:
    """Return ``url`` unless it contains a forbidden payload scheme.

    If it does, return a redacted placeholder so the PoC file can be
    written without ever persisting the literal.
    """
    if not isinstance(url, str):
        return "<redacted:non-string-url>"
    if _PAYLOAD_URL_RE.search(url):
        return "<redacted:forbidden-scheme>"
    return url


def _shell_quote(s: str) -> str:
    """Single-quote a string for safe inclusion in a bash command."""
    if not isinstance(s, str):
        s = str(s)
    return "'" + s.replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class ChainPoCGenerator:
    """Generate a Markdown + curl/bash reproducer for a chain."""

    def __init__(self, *,
                 output_dir: Optional[Path] = None,
                 require_valid: bool = True,
                 forbid_destructive: bool = True):
        self.output_dir = Path(output_dir) if output_dir else Path("/tmp") / "bugwolf-poc"
        self.require_valid = bool(require_valid)
        self.forbid_destructive = bool(forbid_destructive)
        # Create the output directory lazily; do not crash if creation fails.
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_poc(self, chain: Chain, *,
                     validator: Optional[ChainValidator] = None) -> Union[Path, PoCUnavailable]:
        """Generate a PoC file. Returns the :class:`Path` on success.

        On any failure (invalid chain, scope conflict, internal error,
        destructive step with ``forbid_destructive=True``), returns a
        :class:`PoCUnavailable` instance.
        """
        try:
            return self._generate_poc_inner(chain, validator=validator)
        except Exception as exc:  # noqa: BLE001
            return PoCUnavailable(
                reason=f"internal error: {exc}",
                code="internal_error",
            )

    def generate_poc_markdown(self, chain: Chain) -> str:
        """Return the Markdown body without writing it to disk.

        Useful for tests and for callers that want to embed the PoC
        inside another artefact. STUB-SAFE.
        """
        try:
            return self._render_markdown(chain)
        except Exception:  # noqa: BLE001
            return ""

    # ------------------------------------------------------------------
    # Inner
    # ------------------------------------------------------------------

    def _generate_poc_inner(self, chain: Chain, *,
                            validator: Optional[ChainValidator]) -> Union[Path, PoCUnavailable]:
        if isinstance(chain, Unavailable):
            return PoCUnavailable(
                reason="cannot generate PoC for unavailable chain",
                code="unavailable_chain",
            )
        if not isinstance(chain, (CrossProtocolChain, CrossTargetChain)):
            return PoCUnavailable(
                reason="unsupported chain type",
                code="unsupported_chain",
            )
        v = validator or ChainValidator()
        result: ChainValidationResult = v.validate(chain)
        if self.require_valid and not result.is_valid:
            return PoCUnavailable(
                reason="chain is invalid; refusing to emit PoC",
                code="invalid_chain",
                diagnostics={"issues": list(result.issues)},
            )
        if self.forbid_destructive:
            for s in chain.steps:
                if bool(getattr(s, "destructive", False)):
                    return PoCUnavailable(
                        reason="chain contains a destructive step; PoC refused",
                        code="destructive_step",
                        diagnostics={"step_order": int(s.order)},
                    )

        body = self._render_markdown(chain)
        if not body:
            return PoCUnavailable(
                reason="render produced an empty document",
                code="empty_render",
            )

        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return PoCUnavailable(
                reason=f"output dir unavailable: {exc}",
                code="output_dir",
            )

        chain_id = getattr(chain, "chain_id", "unknown")
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(chain_id))[:64] or "chain"
        path = self.output_dir / f"poc-{safe_id}.md"
        try:
            path.write_text(body, encoding="utf-8")
        except OSError as exc:
            return PoCUnavailable(
                reason=f"write failed: {exc}",
                code="write_failed",
            )
        return path

    def _render_markdown(self, chain: Chain) -> str:
        if isinstance(chain, CrossProtocolChain):
            return self._render_cross_protocol_markdown(chain)
        if isinstance(chain, CrossTargetChain):
            return self._render_cross_target_markdown(chain)
        return ""

    # ------------------------------------------------------------------
    # Renderers
    # ------------------------------------------------------------------

    def _render_cross_protocol_markdown(self, chain: CrossProtocolChain) -> str:
        title = f"PoC — {chain.chain_id}"
        lines: List[str] = [
            f"# {title}",
            "",
            f"_{datetime.now(timezone.utc).isoformat()}_",
            "",
            "## Chain summary",
            "",
            f"- **Source protocol:** `{chain.source_protocol}`",
            f"- **Target protocol:** `{chain.target_protocol}`",
            f"- **Confidence:** {chain.confidence:.2f}",
            f"- **Validity:** {'valid' if chain.validity else 'invalid'}",
            f"- **Rationale:** {chain.rationale}",
            "",
        ]
        if chain.references:
            lines.append("## References")
            for r in chain.references:
                lines.append(f"- {r}")
            lines.append("")

        lines.append("## Steps")
        lines.append("")
        for s in chain.steps:
            lines.append(f"### Step {s.order} — {s.description}")
            lines.append("")
            lines.append(f"- Protocol: `{s.protocol}`")
            if s.technique:
                lines.append(f"- Technique: `{s.technique}`")
            if s.preconditions:
                lines.append("- Preconditions:")
                for p in s.preconditions:
                    lines.append(f"  - {p}")
            if s.evidence:
                lines.append("- Evidence:")
                for k, v in s.evidence.items():
                    if isinstance(v, str) and _PAYLOAD_URL_RE.search(v):
                        v = _safe_url(v)
                    lines.append(f"  - `{k}`: `{v}`")
            if s.destructive:
                lines.append("- **Destructive step — explicit scope approval required.**")
            lines.append("")

        lines.append("## Reproducer (curl + bash)")
        lines.append("")
        lines.append("```bash")
        lines.append("#!/usr/bin/env bash")
        lines.append("# Auto-generated by ChainPoCGenerator. STUB-SAFE reproducer.")
        lines.append("# All commands are read-only. Destructive steps are NOT executed.")
        lines.append("set -euo pipefail")
        lines.append("")
        for s in chain.steps:
            if s.destructive:
                lines.append(f"# Step {s.order}: SKIP — destructive step")
                continue
            lines.append(f"# Step {s.order}: {s.description}")
            url = ""
            if isinstance(s.evidence, dict):
                url = str(s.evidence.get("url") or s.evidence.get("endpoint") or "")
            if not url:
                url = "https://target.example.invalid/"
            url = _safe_url(url)
            lines.append(
                f"curl -sS -X GET {_shell_quote(url)} \\")
            lines.append("     -H 'Accept: application/json'")
            lines.append("")
        lines.append("echo 'PoC complete.'")
        lines.append("```")
        lines.append("")
        return "\n".join(lines)

    def _render_cross_target_markdown(self, chain: CrossTargetChain) -> str:
        title = f"PoC — {chain.chain_id}"
        lines: List[str] = [
            f"# {title}",
            "",
            f"_{datetime.now(timezone.utc).isoformat()}_",
            "",
            "## Chain summary",
            "",
            f"- **Primary target:** `{chain.primary_target}`",
            f"- **Lateral targets:** "
            + (", ".join(f"`{t}`" for t in chain.lateral_targets) or "<none>"),
            f"- **Total severity:** {chain.total_severity}",
            f"- **Estimated bounty range:** {chain.estimated_bounty_range}",
            f"- **Confidence:** {chain.confidence:.2f}",
            f"- **Rationale:** {chain.rationale}",
            "",
        ]
        if chain.references:
            lines.append("## References")
            for r in chain.references:
                lines.append(f"- {r}")
            lines.append("")

        lines.append("## Steps")
        lines.append("")
        for s in chain.steps:
            lines.append(f"### Step {s.order} — {s.description}")
            lines.append("")
            lines.append(f"- Protocol: `{s.protocol}`")
            if s.technique:
                lines.append(f"- Technique: `{s.technique}`")
            if s.preconditions:
                lines.append("- Preconditions:")
                for p in s.preconditions:
                    lines.append(f"  - {p}")
            if s.evidence:
                lines.append("- Evidence:")
                for k, v in s.evidence.items():
                    if isinstance(v, str) and _PAYLOAD_URL_RE.search(v):
                        v = _safe_url(v)
                    lines.append(f"  - `{k}`: `{v}`")
            if s.destructive:
                lines.append("- **Destructive step — explicit scope approval required.**")
            lines.append("")

        lines.append("## Reproducer (curl + bash)")
        lines.append("")
        lines.append("```bash")
        lines.append("#!/usr/bin/env bash")
        lines.append("# Auto-generated by ChainPoCGenerator. Read-only recon-style script.")
        lines.append("set -euo pipefail")
        lines.append("")
        lines.append(f"TARGET={_shell_quote(chain.primary_target)}")
        for lt in chain.lateral_targets:
            lines.append(f"LATERAL_{_safe_id(lt)}={_shell_quote(lt)}")
        lines.append("")
        for s in chain.steps:
            if s.destructive:
                lines.append(f"# Step {s.order}: SKIP — destructive step")
                continue
            host = chain.primary_target
            if "lateral" in (s.technique or "") and chain.lateral_targets:
                host = chain.lateral_targets[0]
            url = _safe_url(f"https://{host}/")
            lines.append(f"# Step {s.order}: {s.description}")
            lines.append(f"curl -sS -X GET {_shell_quote(url)} \\")
            lines.append("     -H 'Accept: application/json'")
            lines.append("")
        lines.append("echo 'PoC complete.'")
        lines.append("```")
        lines.append("")
        return "\n".join(lines)


def _safe_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", str(s))[:32].upper()


__all__ = [
    "SCHEMA",
    "PoCUnavailable",
    "ChainPoCGenerator",
]
