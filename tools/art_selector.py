#!/usr/bin/env python3
"""Adaptive Random Testing (ART) selection for BugWolf's discovery core.

The classic ART reference is Chen, Kuo, Liu, Wong: *Adaptive Random Testing*
(2004). This module implements the payload-aware variant proposed by Zhang,
Zhang, Wang, Zhao, Zhang: *ART4SQLi: The ART of SQL Injection Vulnerability
Discovery* (IEEE Transactions on Reliability). ART4SQLi treats the payload
collection as an input space and selects, at each step, the payload *farthest*
from every payload evaluated so far, on the intuition that effective (working)
payloads cluster together in that space — so spreading out maximizes the
chance of landing inside the cluster within a limited budget. Their
experiments show a ~26% average reduction in attempts before the first
successful injection versus plain random selection.

The method has three parts, all reproduced here deterministically:

1. **Tokenization (paper §III-C1)** — each SQLi payload string is decomposed
   into grammar tokens (quotes, comment terminators, whitespace/encoding
   tactics, SQL keywords/functions, operators, literals) via
   :func:`payload_tokens`.
2. **TF-IDF feature vectors (paper §III-C2, eq. 2)** — a payload's vector is
   the token-frequency × inverse-document-frequency weights,
   ``w = log(F_i + 1) * log(k / N_i)``, L2-normalized. ``F_i`` is the token's
   frequency in the payload, ``N_i`` the number of payloads containing it,
   ``k`` the size of the payload collection.
3. **Distance and selection (paper §III-B/C3, eq. 3, Alg. 1+2)** — distance
   between two payloads is ``1 / cosine(v_p, v_q)`` in ``[1, +inf)``
   (1 = identical, +inf = orthogonal). Selection is FSCS (Fixed-Size
   Candidate Selection): from a fixed-size candidate set drawn per iteration
   (FixedSize = 10, the value suggested in the paper), pick the candidate
   maximizing its minimum distance to the already-selected set.

The structural, value-independent Hamming selector from BugWolf's original
ART layer is preserved as the fallback for mutations that do not carry SQLi
payloads (boundary, state, sibling, header-trust, ...). Payload-bearing
mutations (``injection`` / ``blind_sqli`` with a string ``mutated``) use the
ART4SQLi token space instead.

Everything here is offline-only and deterministic (a fixed ``seed`` replaces
the paper's RNG, and ``mutation_id`` hashes drive candidate-set draws).

Usage:
  python3 tools/art_selector.py --input mutations.jsonl --budget 100 --fixed-size 10 --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from tools.mutator import Mutation
except ImportError:  # direct script execution
    from mutator import Mutation

SCHEMA_VERSION = "bugwolf-art-selector-v2"

LOG = logging.getLogger(__name__)

# Kinds whose ``mutated`` value is an SQLi payload string. Only these take
# part in the ART4SQLi token space; everything else falls back to the
# structural vector below.
PAYLOAD_KINDS = ("injection", "blind_sqli")

# Stable ordering — used both as the feature-vector index and as the schema
# for the JSON output. DO NOT reorder without bumping SCHEMA_VERSION.
_KIND_INDEX = (
    "sibling_differential",
    "header_trust",
    "state",
    "required_tamper",
    "mass_assignment",
    "boundary",
    "pollution",
    "injection",
    "blind_sqli",
)

# FixedSize candidate-set size suggested by the ART literature and used in the
# ART4SQLi experiments (paper §IV-D: "we let the global parameter FixedSize to
# be a suggested value 10 according to [10]").
DEFAULT_FIXED_SIZE = 10


# ---------------------------------------------------------------------------
# 1. SQLi payload tokenization (ART4SQLi §III-C1)
# ---------------------------------------------------------------------------

# SQL keywords/functions the tokenizer normalizes to their canonical upper-case
# form. Anything else identifier-like becomes the generic ``id`` token.
SQL_KEYWORDS = {
    "OR", "AND", "NOT", "XOR", "NULL", "TRUE", "FALSE", "IS", "IN", "LIKE",
    "BETWEEN", "EXISTS", "IF", "ELSE", "THEN", "CASE", "WHEN", "END",
    "SELECT", "UNION", "ALL", "FROM", "WHERE", "HAVING", "GROUP", "BY",
    "ORDER", "ASC", "DESC", "LIMIT", "OFFSET", "DISTINCT", "JOIN", "INNER",
    "LEFT", "RIGHT", "FULL", "OUTER", "ON", "AS",
    "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE", "DROP", "CREATE",
    "ALTER", "TABLE", "COLUMN", "INDEX", "DATABASE", "SCHEMA", "TRUNCATE",
    "RENAME", "GRANT", "REVOKE", "SHOW", "USE", "EXEC", "EXECUTE", "DECLARE",
    "BEGIN", "COMMIT", "ROLLBACK", "PROCEDURE", "FUNCTION", "TRIGGER",
    "INFORMATION_SCHEMA", "TABLES", "COLUMNS", "USERS", "PASSWORDS",
    "SLEEP", "PG_SLEEP", "WAITFOR", "DELAY", "BENCHMARK", "IFNULL",
    "CONCAT", "CONCAT_WS", "SUBSTR", "SUBSTRING", "MID", "LEFT", "RIGHT",
    "ASCII", "CHAR", "UNICODE", "ORD", "HEX", "UNHEX", "LENGTH", "OCT",
    "BIN", "CONV", "CAST", "CONVERT", "COUNT", "MAX", "MIN", "SUM", "AVG",
    "GROUP_CONCAT", "DATABASE", "USER", "VERSION", "CURRENT_USER",
    "SYSTEM_USER", "SESSION_USER", "LOAD_FILE", "INTO", "OUTFILE",
    "DUMPFILE", "EXTRACTVALUE", "UPDATEXML", "GTID_SUBSET", "EXP", "FLOOR",
    "RAND", "SIN", "COS", "TAN", "COT", "LN", "LOG", "POW", "POWER", "MOD",
    "DIV", "SIGN", "ABS", "CEIL", "CEILING", "ROUND", "TRUNCATE", "PI",
    "REGEXP", "RLIKE", "BINARY", "NATURAL", "USING", "UNION", "UNIQUE",
    "PRIMARY", "FOREIGN", "KEY", "REFERENCES", "CONSTRAINT", "CHECK",
    "DEFAULT", "AUTO_INCREMENT", "CASCADE", "RESTRICT", "PROCEDURE",
    "ANALYSE", "ST_LATFROMWKB", "ST_LONGFROMWKB", "ST_TOUPPER",
    "TO_CHAR", "TO_NUMBER", "TO_DATE", "DBMS_PIPE", "DBMS_OUTPUT",
    "UTL_HTTP", "UTL_FILE", "SYS_CONTEXT", "V$VERSION", "V$TABLESPACE",
    "PASSWORD", "MD5", "SHA1", "SHA2", "ENCODE", "DECODE", "REPLACE",
    "UPPER", "LOWER", "REVERSE", "TRIM", "LTRIM", "RTRIM", "LPAD", "RPAD",
    "INSTR", "LOCATE", "POSITION", "CHAR_LENGTH", "CHARACTER_LENGTH",
    "OCTET_LENGTH", "BIT_LENGTH", "STRCMP", "SOUNDEX", "SPACE", "REPEAT",
    "ELT", "FIELD", "FIND_IN_SET", "MAKE_SET", "EXPORT_SET", "FORMAT",
    "INTERVAL", "DATE", "TIME", "TIMESTAMP", "NOW", "SYSDATE", "CURDATE",
    "CURTIME", "UNIX_TIMESTAMP", "FROM_UNIXTIME", "DATE_ADD", "DATE_SUB",
    "DATEDIFF", "TIMEDIFF", "DAY", "MONTH", "YEAR", "HOUR", "MINUTE",
    "SECOND", "WEEK", "QUARTER", "LAST_DAY", "STR_TO_DATE",
}

# Tokenizer patterns, longest-first so multi-char operators/comments win over
# single-char ones. Each pattern maps to a normalization function.
_TOKEN_PATTERNS: List[Tuple[str, str]] = [
    # percent-encodings used as whitespace/quote tactics (e.g. %27, %20, %09)
    (r"%[0-9a-fA-F]{2}", "pct"),
    # the whitespace-substitute comment tactic /**/ is its own token (space-
    # filtered pages force it); other block/version comments collapse to
    # ``comment``
    (r"/\*\*/", "ws_comment"),
    # MySQL version / block comments
    (r"/\*.*?\*/", "comment"),
    (r"--", "line_comment"),
    (r"#", "hash_comment"),
    (r">=", "op"),
    (r"<=", "op"),
    (r"<>", "op"),
    (r"!=", "op"),
    (r"&&", "op"),
    (r"\|\|", "op"),
    (r"0x[0-9a-fA-F]+", "hex"),
    (r"\d+(?:\.\d+)?", "num"),
    (r"[A-Za-z_][A-Za-z0-9_]*", "word"),
    (r"\s+", "ws"),
    (r"[=><;(),.:+\-*/|&^~!%]", "op"),
    (r".", "op"),  # any remaining single char
]

_TOKEN_REGEX = re.compile(
    "|".join(f"({pattern})" for pattern, _ in _TOKEN_PATTERNS),
    re.IGNORECASE | re.DOTALL,
)


def _normalize_token(group_name: str, text: str) -> Optional[str]:
    """Map one regex group match to a canonical token (None = skip)."""
    if group_name == "pct":
        return "%" + text[1:].upper()
    if group_name == "comment":
        return "comment"
    if group_name == "ws_comment":
        return "/**/"
    if group_name == "line_comment":
        return "--"
    if group_name == "hash_comment":
        return "#"
    if group_name in ("op", "hex", "num"):
        return {"op": text.lower(), "hex": "hex", "num": "num"}[group_name]
    if group_name == "word":
        upper = text.upper()
        return upper if upper in SQL_KEYWORDS else "id"
    if group_name == "ws":
        return None
    return text.lower()


def payload_tokens(value: str) -> List[str]:
    """Decompose an SQLi payload string into grammar tokens.

    Deterministic: quotes/encodings/comments/operators/literals are kept as
    canonical tokens, digit runs collapse to ``num``, hex literals to ``hex``,
    unknown identifiers to ``id``, and SQL keywords to their upper-case form.
    Whitespace runs produce no token (whitespace tactics are represented by
    the ``/**/`` / ``%20`` / ``%09`` tokens instead). Matches the paper's
    'string decomposition' step for single-quote, numeric, comment, and
    time-based payload forms.
    """
    if not value:
        return []
    tokens: List[str] = []
    for match in _TOKEN_REGEX.finditer(value):
        for group_index, (_, name) in enumerate(_TOKEN_PATTERNS):
            if match.group(group_index + 1) is None:
                continue
            token = _normalize_token(name, match.group(group_index + 1))
            if token is not None:
                tokens.append(token)
            break
    return tokens


def _is_payload_mutation(mutation: Mutation) -> bool:
    mutated = getattr(mutation, "mutated", None)
    return (isinstance(mutated, str) and bool(mutated)
            and getattr(mutation, "kind", "") in PAYLOAD_KINDS)


# ---------------------------------------------------------------------------
# 2. TF-IDF payload space (ART4SQLi §III-C2/C3, eq. 2 & 3)
# ---------------------------------------------------------------------------


@dataclass
class PayloadSpace:
    """TF-IDF token space over a payload collection (eq. 2).

    Built once over the whole payload collection (the paper's ``PC``), then
    used to embed and compare payload strings. Distance between two embedded
    payloads is ``1 / cosine`` (eq. 3): 1.0 for identical vectors, +inf for
    orthogonal ones.
    """

    idf: Dict[str, float] = field(default_factory=dict)
    vocab: List[str] = field(default_factory=list)
    _index: Dict[str, int] = field(default_factory=dict, repr=False)
    _norm_cache: Dict[str, Dict[str, float]] = field(default_factory=dict,
                                                     repr=False)

    def __post_init__(self) -> None:
        if not self._index and self.vocab:
            self._index = {t: i for i, t in enumerate(self.vocab)}

    @classmethod
    def fit(cls, payloads: Sequence[str]) -> "PayloadSpace":
        """Build the space from a payload collection (deterministic)."""
        documents: List[Counter] = [Counter(payload_tokens(p)) for p in payloads]
        k = max(1, len(payloads))
        df: Counter = Counter()
        for doc in documents:
            for token in doc:
                df[token] += 1
        # log(k / N_i): classic IDF; N_i <= k so weights are non-negative.
        idf = {token: math.log(k / count) for token, count in df.items()}
        vocab = sorted(idf)  # deterministic dimension order
        return cls(idf=idf, vocab=vocab, _index={t: i for i, t in enumerate(vocab)})

    @property
    def dimension(self) -> int:
        return len(self.vocab)

    def vector_sparse(self, value: str) -> Dict[str, float]:
        """L2-normalized TF-IDF weights as a sparse dict (token -> weight)."""
        if value in self._norm_cache:
            return self._norm_cache[value]
        freq = Counter(payload_tokens(value))
        weights = {
            token: math.log(count + 1.0) * self.idf.get(token, 0.0)
            for token, count in freq.items() if token in self.idf
        }
        norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
        normalized = {t: w / norm for t, w in weights.items()}
        if len(self._norm_cache) < 100_000:  # bounded cache
            self._norm_cache[value] = normalized
        return normalized

    def vector(self, value: str) -> List[float]:
        """Dense vocab-aligned L2-normalized TF-IDF vector for a payload."""
        sparse = self.vector_sparse(value)
        return [sparse.get(t, 0.0) for t in self.vocab]

    def distance(self, a: str, b: str) -> float:
        """ART4SQLi eq. (3): ``1 / cosine(v_a, v_b)`` in ``[1, +inf)``.

        1.0 means identical vectors; ``inf`` means orthogonal (no shared
        tokens). Non-negative weights keep cosine in ``[0, 1]``.
        """
        va, vb = self.vector_sparse(a), self.vector_sparse(b)
        dot = 0.0
        for token, weight in va.items():
            if token in vb:
                dot += weight * vb[token]
        if dot <= 0.0:
            return math.inf
        return 1.0 / dot

    def distance_vectors(self, va: Dict[str, float],
                         vb: Dict[str, float]) -> float:
        dot = 0.0
        for token, weight in va.items():
            if token in vb:
                dot += weight * vb[token]
        if dot <= 0.0:
            return math.inf
        return 1.0 / dot


def build_payload_space(mutations: Sequence[Mutation]) -> Optional[PayloadSpace]:
    """Fit a :class:`PayloadSpace` over the payload-bearing mutations.

    Returns ``None`` when no mutation in the collection carries an SQLi
    payload (the selection then uses the structural distance only).
    """
    payloads = [m.mutated for m in mutations
                if _is_payload_mutation(m)]
    if not payloads:
        return None
    return PayloadSpace.fit(payloads)


# ---------------------------------------------------------------------------
# 3. Distance and selection (ART4SQLi §III-B/C3, Alg. 1 + 2)
# ---------------------------------------------------------------------------


def _bucket(name: str, mod: int = 64) -> int:
    """Deterministic, value-independent bucket for a string feature."""
    if not name:
        return 0
    digest = hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest()
    return int(digest[:8], 16) % mod


def feature_vector(mutation: Mutation) -> Tuple:
    """Structural (value-independent) feature vector for a single Mutation.

    Fields: kind, method, bug_class, risk, variable-bucket, path-bucket.
    Two mutations with identical vectors produce distance 0; orthogonal ones
    produce distance 1. Used as the fallback for non-payload mutations and
    kept for backward compatibility with the original ART layer.
    """
    risk_value = (mutation.risk.value
                  if hasattr(mutation.risk, "value") else str(mutation.risk))
    kind_index = (_KIND_INDEX.index(mutation.kind)
                  if mutation.kind in _KIND_INDEX else len(_KIND_INDEX))
    return (
        kind_index,
        (mutation.method or "").upper(),
        mutation.bug_class or "",
        risk_value,
        _bucket(mutation.variable),
        _bucket(mutation.path),
    )


def distance(a: Tuple, b: Tuple) -> float:
    """Categorical Hamming-style distance in ``[0, 1]`` (structural)."""
    if not a or not b:
        return 1.0
    if len(a) != len(b):
        return 1.0
    mismatches = sum(1 for x, y in zip(a, b) if x != y)
    return mismatches / len(a)


def payload_aware_distance(a: Mutation, b: Mutation,
                           space: Optional[PayloadSpace] = None) -> float:
    """Distance between two mutations.

    When both mutations carry SQLi payloads and a ``space`` is available, the
    ART4SQLi token distance (eq. 3) applies; otherwise the structural Hamming
    distance is used. Deterministic either way.
    """
    if space is not None and _is_payload_mutation(a) and _is_payload_mutation(b):
        return space.distance(a.mutated, b.mutated)
    return distance(feature_vector(a), feature_vector(b))


def _min_distance_to_any(candidate: Mutation,
                         selected: Sequence[Mutation],
                         space: Optional[PayloadSpace]) -> float:
    if not selected:
        return 1.0
    return min(payload_aware_distance(candidate, other, space)
               for other in selected)


def _candidate_set(remaining: Sequence[Mutation], fixed_size: Optional[int],
                   round_no: int, seed: int) -> List[Mutation]:
    """Deterministic fixed-size candidate set (FSCS Step 4b).

    The paper draws a random ``FixedSize``-sized subset of the payload
    collection each iteration. Here the subset is the ``fixed_size`` items
    with the smallest ``sha256(seed:round:mutation_id)`` — reproducible across
    runs while still re-sampling the pool every round.
    """
    if fixed_size is None or fixed_size <= 0 or len(remaining) <= fixed_size:
        return list(remaining)
    return sorted(
        remaining,
        key=lambda m: hashlib.sha256(
            f"art4sqli:{seed}:{round_no}:{m.mutation_id}".encode()
        ).hexdigest(),
    )[:fixed_size]


def select_next(candidates: Sequence[Mutation],
                evaluated: Sequence[Mutation], *,
                fixed_size: Optional[int] = DEFAULT_FIXED_SIZE,
                space: Optional[PayloadSpace] = None,
                seed: int = 0, round_no: int = 0) -> Optional[Mutation]:
    """ART4SQLi Step 4: select the *next single* payload to evaluate.

    Draws a deterministic fixed-size candidate set from ``candidates`` (the
    remaining payload collection) and returns the candidate maximizing its
    minimum distance to ``evaluated`` (the evaluated set, eq. 1). With an
    empty evaluated set (the paper's Step 1) the first candidate in input
    order is returned. Returns ``None`` when ``candidates`` is empty. This is
    the primitive the paper's iterative process (evaluate -> stop or select
    next) is built on, and what an F-measure simulation should call per round.
    """
    if not candidates:
        return None
    candidate_set = _candidate_set(list(candidates), fixed_size, round_no, seed)
    if not evaluated:
        return candidate_set[0]
    return max(
        candidate_set,
        key=lambda u: _min_distance_to_any(u, evaluated, space),
    )


def adaptive_select(candidates: Sequence[Mutation], k: int, *,
                    fixed_size: Optional[int] = None,
                    space: Optional[PayloadSpace] = None,
                    seed: int = 0) -> List[Mutation]:
    """FSCS farthest-nearest-candidate selection (ART4SQLi Alg. 1 + 2).

    Seeding follows the input order (the scheduler supplies impact-ranked
    mutations, so a high-focus payload leads), then each iteration draws a
    deterministic fixed-size candidate set and picks the candidate whose
    *minimum* distance to the already-selected set is the largest (eq. 1).
    Only the selected payload leaves the pool — the rest are re-sampled next
    round, exactly as in the paper's FSCS.

    ``fixed_size=None`` degrades to max-min over *all* remaining candidates,
    which reproduces the original greedy farthest-first selector, so existing
    callers and reports keep their semantics. ``k`` is clamped to
    ``[0, len(candidates)]``.
    """
    n = len(candidates)
    k = max(0, min(k, n))
    if k == 0 or n == 0:
        return []
    if k >= n:
        return list(candidates)

    remaining: List[Mutation] = list(candidates)
    selected: List[Mutation] = [remaining.pop(0)]
    round_no = 0
    while len(selected) < k and remaining:
        chosen = select_next(remaining, selected, fixed_size=fixed_size,
                             space=space, seed=seed, round_no=round_no)
        remaining.remove(chosen)
        selected.append(chosen)
        round_no += 1
    return selected


def art_allocate(untried: Sequence[Mutation], tried: Sequence[Mutation],
                 budget: int, *, fixed_size: Optional[int] = DEFAULT_FIXED_SIZE,
                 seed: int = 0) -> List[Mutation]:
    """Allocate a budget-worth of mutations for the discovery scheduler.

    ART4SQLi selection over the *untried* mutations first (payload-aware
    TF-IDF space fit over the whole pool); when the budget exceeds the number
    of untried mutations, the remainder is refilled from the tried set with
    the same farthest-nearest discipline. Deterministic for a given seed.
    """
    budget = max(0, budget)
    untried = list(untried)
    tried = [m for m in tried if m not in untried]
    pool = list(untried) + tried
    space = build_payload_space(pool)
    if budget == 0 or not pool:
        return []

    selected = adaptive_select(untried, min(budget, len(untried)),
                               fixed_size=fixed_size, space=space, seed=seed)
    needed = budget - len(selected)
    remaining = [m for m in tried if m not in selected]
    while needed > 0 and remaining:
        chosen = max(remaining, key=lambda u: _min_distance_to_any(u, selected,
                                                                   space))
        remaining.remove(chosen)
        selected.append(chosen)
        needed -= 1
    return selected[:budget]


def nearest_neighbor_score(batch: Sequence[Mutation],
                           space: Optional[PayloadSpace] = None) -> float:
    """Mean of each candidate's distance to its nearest in-batch neighbor.

    With ``space=None`` this is the structural score in ``[0, 1]`` (a batch
    close to 1.0 has near-orthogonal members). With a payload space, payload
    pairs use the ART4SQLi ``1/cosine`` distance, so values are in
    ``[1, +inf)`` — higher means more spread-out in token space.
    """
    if len(batch) < 2:
        return 0.0
    total = 0.0
    for i, candidate in enumerate(batch):
        others = [batch[j] for j in range(len(batch)) if j != i]
        total += _min_distance_to_any(candidate, others, space)
    return total / len(batch)


def f_measure(selection: Sequence[Mutation],
              is_effective) -> Optional[int]:
    """ART4SQLi F-measure (paper §IV-E2): payloads evaluated before the first
    effective one, ``1 + index`` of the first payload for which
    ``is_effective(mutation)`` is truthy, or ``None`` when none is effective.

    Lower is better; this is the paper's headline metric for comparing
    selection strategies (e.g. ART4SQLi vs random).
    """
    for index, mutation in enumerate(selection):
        if is_effective(mutation):
            return index + 1
    return None


@dataclass
class ArtSelection:
    """The ART-selected batch together with diversity diagnostics."""

    selection: List[Mutation]
    diversity_score: float
    coverage: float
    fixed_size: Optional[int] = DEFAULT_FIXED_SIZE
    payload_vocab_size: int = 0
    payload_bearing: int = 0
    schema: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "diversity_score": self.diversity_score,
            "coverage": self.coverage,
            "fixed_size": self.fixed_size,
            "payload_vocab_size": self.payload_vocab_size,
            "payload_bearing": self.payload_bearing,
            "selection": [m.to_dict() if hasattr(m, "to_dict") else dict(m)
                          for m in self.selection],
        }


def select_and_report(candidates: Sequence[Mutation], k: int, *,
                      fixed_size: Optional[int] = DEFAULT_FIXED_SIZE,
                      seed: int = 0) -> ArtSelection:
    pool = list(candidates)
    space = build_payload_space(pool)
    batch = adaptive_select(pool, k, fixed_size=fixed_size, space=space,
                            seed=seed)
    payloads = [m for m in batch if _is_payload_mutation(m)]
    return ArtSelection(
        selection=batch,
        diversity_score=nearest_neighbor_score(batch, space=space),
        coverage=k / max(1, len(pool)),
        fixed_size=fixed_size,
        payload_vocab_size=space.dimension if space else 0,
        payload_bearing=len(payloads),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply ART4SQLi Adaptive Random Testing selection over a "
                    "mutation list (payload TF-IDF + FSCS). Reads JSONL of "
                    "Mutation records.")
    parser.add_argument("--input", required=True,
                        help="Mutation JSONL file (each line a Mutation dict).")
    parser.add_argument("--budget", type=int, default=20,
                        help="Number of mutations to ART-select.")
    parser.add_argument("--fixed-size", type=int, default=DEFAULT_FIXED_SIZE,
                        help="FSCS candidate-set size (paper: 10). Use 0 for "
                             "max-min over all candidates.")
    parser.add_argument("--seed", type=int, default=0,
                        help="Deterministic selection seed (replaces the "
                             "paper's RNG).")
    parser.add_argument("--json", action="store_true",
                        help="Print JSON output instead of text summary.")
    args = parser.parse_args()

    try:
        from tools.mutator import Mutation as _Mutation
    except ImportError:
        _Mutation = Mutation

    with open(args.input, "r", encoding="utf-8") as stream:
        mutations: List[Mutation] = []
        for raw in stream:
            raw = raw.strip()
            if not raw:
                continue
            mutations.append(_Mutation.from_dict(json.loads(raw)))

    fixed_size = args.fixed_size or None
    report = select_and_report(mutations, args.budget,
                               fixed_size=fixed_size, seed=args.seed)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
        LOG.info("art_selector.report keys=%s budget=%d",
                 sorted(report.to_dict().keys()), args.budget)
        return

    print(f"[*] ART4SQLi selection: budget={args.budget} "
          f"candidates={len(mutations)} fixed_size={fixed_size or 'all'}")
    LOG.info("art_selector.summary budget=%d candidates=%d diversity=%.3f",
             args.budget, len(mutations), report.diversity_score)
    print(f"    diversity: {report.diversity_score:.3f}  "
          f"coverage: {report.coverage:.3f}  "
          f"payload vocab: {report.payload_vocab_size}  "
          f"payload-bearing selected: {report.payload_bearing}")
    for m in report.selection:
        print(f"    [{m.risk.value}] {m.kind} {m.method} {m.path} "
              f"{m.variable or ''}")
        LOG.debug("art_selector.pick %s %s %s risk=%s",
                  m.kind, m.method, m.path, m.risk.value)
    if not mutations:
        sys.exit(2)


if __name__ == "__main__":
    main()
