"""Zero-day mutation fuzzer — SHELL-LEVEL.

Produces deterministic mutations of an arbitrary byte buffer and
returns them as a tuple.  In a real deployment the fuzzer would feed
each mutation to the transport in turn and look for crashes / new
status codes.  This module ships the **mutation engine** portion of
that pipeline as a shell so the orchestrator and test suite can verify
the surface; the dispatch loop is intentionally not implemented (the
per-mutation transport loop belongs to the campaign driver, not the
mutation engine itself).

The engine itself is implemented (not stubbed): it deterministically
yields mutated variants from a seed input.  The shell-level status
applies to the higher-level ``scan()`` method, which returns ``[]``
when no transport is supplied.

Mutations supported:

  * bit-flip (single-bit, single-byte)
  * byte insertion (0x00 / 0xFF)
  * byte deletion (skip a byte)
  * arithmetic (+1 / -1) on each byte
  * copy-paste (duplicate a 4-byte window)
  * swap adjacent bytes
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class ZeroDayFuzzerMutationEngine(Scanner):
    """Deterministic byte-level mutation engine + minimal scan() shell."""

    name = "zero-day-fuzzer"
    bug_class = "zero-day-fuzz"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = (
        "BugWolfSeed",
        "AAAAAAAA",
        "GET / HTTP/1.1\r\n\r\n",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "zero-day-fuzzer: shell-mode (no transport); returning [] "
                "— supply a transport to dispatch mutations"
            )
            return []
        findings: List[Finding] = []
        for seed_str in self.PAYLOADS:
            seed = seed_str.encode("utf-8")
            for mutation in self.mutate(seed)[:8]:
                try:
                    resp: Dict[str, Any] = transport(
                        "POST", target,
                        headers={"Content-Type": "application/octet-stream"},
                        body=mutation.decode("latin-1"),
                    )
                except Exception as exc:
                    logger.debug("zero-day: transport error: %s", exc)
                    continue
                status = resp.get("status")
                if status in (500, 502, 503):
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=(f"mutation caused {status} for "
                                  f"seed {seed_str!r}"),
                        severity="medium",
                        detail={"seed": seed_str,
                               "mutation": mutation[:64].hex(),
                               "status": status},
                    ))
        return findings

    @staticmethod
    def mutate(seed: bytes) -> Tuple[bytes, ...]:
        """Return a tuple of deterministic mutations of ``seed``.

        Pure function: same input → same output tuple.  Does NOT
        perform IO.
        """
        if not seed:
            return (b"BugWolfFuzzEmpty",)
        variants: List[bytes] = []

        # bit-flip on first byte
        b = bytearray(seed)
        b[0] ^= 0x01
        variants.append(bytes(b))

        # byte insertion
        variants.append(seed + b"\x00")
        variants.append(seed + b"\xff")

        # byte deletion (drop the second byte if available)
        if len(seed) > 1:
            variants.append(seed[:1] + seed[2:])

        # arithmetic +/-1 on first byte
        if seed[0] < 0xFF:
            variants.append(bytes([seed[0] + 1]) + seed[1:])
        if seed[0] > 0x00:
            variants.append(bytes([seed[0] - 1]) + seed[1:])

        # swap adjacent bytes (first two)
        if len(seed) >= 2:
            variants.append(seed[1:2] + seed[0:1] + seed[2:])

        # copy-paste (duplicate first 4 bytes at the end)
        window = seed[:4]
        variants.append(seed + window)

        # duplicate seed
        variants.append(seed + seed)

        # truncate
        variants.append(seed[:-1])
        # extend with a marker
        variants.append(seed + b"BugWolfFuzzMark")

        # dedupe but preserve order
        seen = set()
        unique: List[bytes] = []
        for v in variants:
            if v in seen:
                continue
            seen.add(v)
            unique.append(v)
        return tuple(unique)


__all__ = ["ZeroDayFuzzerMutationEngine"]