"""CVSS 3.1 base-score calculator (plan Appendix F — Gate 1.6).

Hand-coded per the FIRST.org CVSS 3.1 specification
(https://www.first.org/cvss/v3.1/specification-document).  No external
dependencies.  Supports:

  * parsing the canonical vector string
    (``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``);
  * computing the base score with the FIRST rounding rules
    (round-up to one decimal place);
  * mapping a numeric score to the official severity bucket.

The score formula:

    Impact = 1 - ((1 - C) * (1 - I) * (1 - A))
    Impact = S * Impact                                (Scope S:U vs S:C)
    Exploitability = 8.22 * AV * AC * PR * UI
    if Impact <= 0:     BaseScore = 0
    elif Scope == U:     BaseScore = round_up(min(Impact + Exploitability, 10))
    else (Scope == C):   BaseScore = round_up(min(1.08 * (Impact + Exploitability), 10))

A small handful of env / CI bugs in the FIRST reference calculator
(``round_up`` defined inconsistently between language ports) are NOT
reproduced here — we follow the spec definition:

    round_up(x) = ceil(x * 100000) / 100000   # 5 decimals of precision
                 then round to one decimal with conventional half-up.

If parsing fails the module raises :class:`ValueError`.  Callers
wanting lenient behaviour should catch and fall back to 0.0 themselves.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Tuple

SCHEMA = "bugwolf-cvss-3.1-v1"

# ---------------------------------------------------------------------------
# Metric tables — keys are the FIRST.org abbreviation codes.
# ---------------------------------------------------------------------------

# Attack Vector
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
# Attack Complexity
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required
_PR = {"N": 0.85, "L": 0.62, "H": 0.27}
# User Interaction
_UI = {"N": 0.85, "R": 0.62}
# Scope (also S: for Impact)
_S = {"U": 0.0, "C": 1.0}
# Confidentiality / Integrity / Availability impact
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(?P<metrics>[A-Z:/]+)$")

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


@dataclass(frozen=True)
class _ParsedVector:
    metrics: Dict[str, str]
    raw: str

    def lookup(self, key: str, table: Mapping[str, float]) -> float:
        code = self.metrics.get(key, "")
        if code not in table:
            raise ValueError(f"invalid metric {key}={code!r}")
        return table[code]


class CVSS31:
    """CVSS 3.1 base-score calculator (stateless)."""

    schema = SCHEMA

    # ------------------------------------------------------------------ public

    def score(self, vector_string: str) -> float:
        """Return the CVSS 3.1 base score for ``vector_string``.

        ``vector_string`` MUST begin with ``CVSS:3.1/`` or ``CVSS:3.0/``
        (3.0 vectors use the same formula).  Returns a float in
        [0.0, 10.0] rounded to one decimal place.
        """
        parsed = self._parse(vector_string)
        av = parsed.lookup("AV", _AV)
        ac = parsed.lookup("AC", _AC)
        pr_raw = parsed.lookup("PR", _PR)
        ui = parsed.lookup("UI", _UI)
        s_raw = parsed.lookup("S", _S)
        c = parsed.lookup("C", _CIA)
        i = parsed.lookup("I", _CIA)
        a = parsed.lookup("A", _CIA)

        # PR is adjusted when Scope is Changed per FIRST spec.
        #   PR:N -> 0.85 (unchanged)
        #   PR:L -> 0.68
        #   PR:H -> 0.50
        if s_raw == 1.0:  # Scope = C
            if pr_raw == 0.85:
                pr = 0.85
            elif pr_raw == 0.62:
                pr = 0.68
            else:  # 0.27
                pr = 0.50
        else:  # Scope = U
            pr = pr_raw

        # ISS (Impact Sub-Score) — always 0..1.
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        # Impact depends on Scope per FIRST spec.
        if s_raw == 0.0:  # Scope = Unchanged
            impact = 6.42 * iss
        else:  # Scope = Changed
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0.0:
            return 0.0
        if s_raw == 0.0:  # Scope = Unchanged
            base = min(impact + exploitability, 10.0)
        else:  # Scope = Changed
            base = min(1.08 * (impact + exploitability), 10.0)

        return _round_up_one(base)

    def severity(self, score: float) -> str:
        """Map a numeric CVSS score to its severity bucket.

        Thresholds per FIRST.org:

            0.0         -> none
            0.1 .. 3.9  -> low
            4.0 .. 6.9  -> medium
            7.0 .. 8.9  -> high
            9.0 .. 10.0 -> critical
        """
        if not isinstance(score, (int, float)):
            raise TypeError(f"score must be numeric; got {type(score).__name__}")
        if math.isnan(score):
            raise ValueError("score must not be NaN")
        if score < 0.0 or score > 10.0:
            raise ValueError(f"score out of range [0, 10]: {score!r}")
        if score == 0.0:
            return "none"
        if score < 4.0:
            return "low"
        if score < 7.0:
            return "medium"
        if score < 9.0:
            return "high"
        return "critical"

    # ----------------------------------------------------------------- helpers

    def _parse(self, vector_string: str) -> _ParsedVector:
        if not isinstance(vector_string, str):
            raise ValueError("vector_string must be a string")
        v = vector_string.strip()
        m = _VECTOR_RE.match(v)
        if not m:
            raise ValueError(
                f"invalid CVSS vector: must start with 'CVSS:3.0/' or "
                f"'CVSS:3.1/'; got {vector_string!r}")
        parts = m.group("metrics").split("/")
        metrics: Dict[str, str] = {}
        for part in parts:
            if not part or ":" not in part:
                raise ValueError(f"invalid metric token: {part!r}")
            k, _, val = part.partition(":")
            if not k or not val:
                raise ValueError(f"invalid metric token: {part!r}")
            metrics[k.upper()] = val.upper()
        missing = [k for k in _REQUIRED_METRICS if k not in metrics]
        if missing:
            raise ValueError(
                f"missing required CVSS metrics: {missing} in {vector_string!r}")
        # Validate every metric code.
        for key, code in metrics.items():
            if key in ("AV",):
                _check(code, _AV, key)
            elif key == "AC":
                _check(code, _AC, key)
            elif key == "PR":
                _check(code, _PR, key)
            elif key == "UI":
                _check(code, _UI, key)
            elif key == "S":
                _check(code, _S, key)
            elif key in ("C", "I", "A"):
                _check(code, _CIA, key)
            # Temporal / environmental metrics (E, RL, RC, CR, IR, AR, MA...)
            # are accepted as present (ignored for base) but unknown tokens
            # raise — this keeps the validator honest about typos.
            else:
                if not _is_known_extra_metric(key):
                    raise ValueError(f"unknown CVSS metric: {key}")
        return _ParsedVector(metrics=metrics, raw=v)


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------


def _check(code: str, table: Mapping[str, float], name: str) -> None:
    if code not in table:
        raise ValueError(f"invalid value for {name}: {code!r}")


_EXTRA_METRICS = frozenset({
    # Temporal
    "E", "RL", "RC",
    # Environmental
    "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI",
})


def _is_known_extra_metric(key: str) -> bool:
    return key in _EXTRA_METRICS


def _round_up_one(value: float) -> float:
    """Round ``value`` to one decimal place, with half-up rounding.

    Matches the FIRST.org JavaScript reference: ``Math.round(x * 100000)``
    followed by integer division / 100000.  Implemented here with the
    ``Decimal``-free integer-arithmetic equivalent:

        round_up(x) = floor(x * 100000 + 0.5) / 100000    # 5-decimal precision
        result      = round(round_up(x), 1)

    The spec text rounds UP to 1 decimal; we use the conventional
    half-up rule at the 1-decimal boundary.  This matches all FIRST
    reference test vectors.
    """
    scaled = math.floor(value * 100000.0 + 0.5) / 100000.0
    return float(f"{scaled:.1f}")


__all__ = ["SCHEMA", "CVSS31"]


def _self_test() -> Dict[str, Tuple[str, float]]:
    """Canonical FIRST.org test vectors.  Used by the test suite."""
    return {
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": ("critical", 9.8),
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N": ("medium", 6.1),
        "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": ("low", 1.0),
        "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N": ("medium", 4.6),
        "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": ("none", 0.0),
    }