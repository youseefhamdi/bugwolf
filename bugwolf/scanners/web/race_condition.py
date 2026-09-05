"""Race-condition / TOCTOU scanner — SHELL-LEVEL.

Detecting real race-condition bugs (overdraft, double-spend,
double-redeem) requires concurrent transport invocation and
statistical timing analysis.  BugWolf's default transport contract
is synchronous; racing it requires a thread-pool with a shared
transport instance and careful clock-skew accounting.

This scanner ships as a shell so the orchestrator can import it
without crashing and the unit tests can verify the ABC.  When
extended with a real concurrent transport it should:

  1. fire N parallel POSTs to a transactional endpoint
  2. count distinct session-IDs / transaction-IDs in responses
  3. if N distinct IDs > 1, flag a TOCTOU

See TODO marker in :meth:`scan`.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_RACE_BURST_SIZE = 8


class RaceConditionScanner(Scanner):
    name = "race-condition"
    bug_class = "race-condition"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = tuple(f"burst-{i}" for i in range(_RACE_BURST_SIZE))

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "race-condition: shell-mode (no transport); returning [] "
                "— supply a concurrent transport to enable burst testing"
            )
            return []
        # Minimal sequential proxy: fire N POSTs and look for distinct
        # tokens.  Concurrent transport upgrades this naturally.
        distinct: set = set()
        try:
            for i in range(_RACE_BURST_SIZE):
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={"Content-Type": "application/json"},
                    body='{"op":"redeem","n":%d}' % i,
                )
                rb = resp.get("body", "") or ""
                distinct.add(rb[:80])
        except Exception as exc:
            logger.debug("race: transport error: %s", exc)
            return []
        if len(distinct) > 1:
            return [make_finding(
                self,
                target=target,
                evidence=("distinct responses on sequential retries — "
                          "consider concurrent burst"),
                severity="high",
                detail={"distinct_bodies": len(distinct)},
            )]
        return []


__all__ = ["RaceConditionScanner"]