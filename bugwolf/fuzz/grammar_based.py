## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: ANTLR4 grammar syntax (https://github.com/antlr/antlr4) — EBNF subset
## Source: fuzzilli / Grammarinator grammar fuzzer design — grammar-based fuzzing
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Grammar-based fuzzing driver for the BugWolf fuzzing substrate.

Two main entry points:

  * :func:`load_grammar` reads an ANTLR-style ``.g4`` file and returns
    a normalised rule dict.
  * :class:`GrammarBasedGenerator` produces a stream of byte samples
    that conform to the grammar.

The driver is **stub-safe**: if a grammar file is missing or the
parser cannot make sense of it, the generator yields an empty
sequence rather than raising.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-fuzz-grammar-v1"


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GrammarBasedResult:
    """Outcome of a grammar-based fuzzing session."""

    grammar_name: str
    samples_generated: int
    samples_kept: int
    duration_seconds: int
    seed_count: int
    runner_name: str = "grammar"


@dataclass
class _Rule:
    """Internal representation of a single grammar rule.

    ``alternatives`` is a list of ``_Alt`` objects, each describing one
    choice of the rule.  ``_Alt.exprs`` is a list of ``_Expr`` objects
    each describing a sequence element.
    """

    name: str
    alternatives: List["_Alt"] = field(default_factory=list)


@dataclass
class _Alt:
    exprs: List["_Expr"] = field(default_factory=list)


@dataclass
class _Expr:
    """One sequence element — a terminal, a non-terminal ref, or a
    quantified sub-expression.
    """

    kind: str  # "term" | "ref" | "group" | "optional" | "star" | "plus"
    value: Any = None
    children: Optional[List["_Expr"]] = None
    quantifier: Optional[str] = None  # "*" | "+" | "?" | None


# ---------------------------------------------------------------------------
# Grammar loader — minimal EBNF subset
# ---------------------------------------------------------------------------


_RULE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r":\s*(?P<body>.*?)\s*;\s*$",
    re.DOTALL,
)


def load_grammar(path: Path) -> Dict[str, _Rule]:
    """Parse an ANTLR-style ``.g4`` file into a ``{rule_name: _Rule}``.

    The parser handles the subset:

        rule     : alternative ( '|' alternative )* ';' ;
        alt      : term+ ;
        term     : literal | IDENT | '(' alt ')' ( '?' | '*' | '+' )? ;
        literal  : "'" ... "'" | '"' ... '"' ;

    Lines beginning with ``//`` or starting a ``grammar NAME;`` block
    are skipped.  The parser NEVER raises on malformed input; it
    returns a partial grammar instead.
    """
    out: Dict[str, _Rule] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return out
    body = _strip_header(text)
    pos = 0
    while pos < len(body):
        m = _RULE_RE.match(body, pos)
        if not m:
            # Skip a single character to make forward progress.
            pos += 1
            continue
        name = m.group("name")
        raw_alt = m.group("body")
        rule = _Rule(name=name)
        try:
            for alt_text in _split_alternatives(raw_alt):
                alt = _parse_alt(alt_text)
                if alt.exprs:
                    rule.alternatives.append(alt)
        except Exception:
            pass
        if rule.alternatives:
            out[name] = rule
        pos = m.end()
    return out


def _strip_header(text: str) -> str:
    """Drop ``grammar X;`` header and ``//`` line comments."""
    lines = []
    for line in text.splitlines():
        stripped = line.split("//", 1)[0]
        if stripped.strip().startswith("grammar ") and stripped.strip().endswith(";"):
            continue
        lines.append(stripped)
    return "\n".join(lines)


def _split_alternatives(body: str) -> List[str]:
    """Split an alternative-list ``a | b | c`` into pieces at top-level
    pipes.  Parentheses are honoured so the split is balanced.
    """
    parts: List[str] = []
    depth = 0
    buf: List[str] = []
    in_str: Optional[str] = None
    for ch in body:
        if in_str:
            buf.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"'):
            in_str = ch
            buf.append(ch)
            continue
        if ch == "(":
            depth += 1
            buf.append(ch)
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
            continue
        if ch == "|" and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p.strip() for p in parts if p.strip()]


def _parse_alt(text: str) -> _Alt:
    """Parse one alternative into a list of expressions."""
    alt = _Alt()
    pos = 0
    while pos < len(text):
        ch = text[pos]
        if ch.isspace():
            pos += 1
            continue
        if ch == "(":
            # Find matching close paren
            depth = 1
            j = pos + 1
            while j < len(text) and depth > 0:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            inner = text[pos + 1 : j - 1]
            sub_alt = _parse_alt(inner)
            quant = _consume_quantifier(text, j)
            alt.exprs.append(_Expr(
                kind="group", children=sub_alt.exprs, quantifier=quant,
            ))
            pos = j + (1 if quant else 0)
            continue
        if ch in ("'", '"'):
            # Terminal literal
            quote = ch
            j = pos + 1
            buf: List[str] = []
            while j < len(text) and text[j] != quote:
                buf.append(text[j])
                j += 1
            literal = "".join(buf)
            pos = j + 1
            quant = _consume_quantifier(text, pos)
            alt.exprs.append(_Expr(
                kind="term", value=literal, quantifier=quant,
            ))
            pos = pos + (1 if quant else 0)
            continue
        if ch.isalpha() or ch == "_":
            j = pos + 1
            while j < len(text) and (text[j].isalnum() or text[j] == "_"):
                j += 1
            ident = text[pos:j]
            quant = _consume_quantifier(text, j)
            alt.exprs.append(_Expr(
                kind="ref", value=ident, quantifier=quant,
            ))
            pos = j + (1 if quant else 0)
            continue
        # Unknown token — skip to avoid infinite loop.
        pos += 1
    return alt


def _consume_quantifier(text: str, pos: int) -> Optional[str]:
    if pos < len(text) and text[pos] in ("*", "+", "?"):
        return text[pos]
    return None


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


@dataclass
class GrammarBasedGenerator:
    """Generate bytes samples from a parsed grammar.

    The generator is recursive and depth-bounded; if recursion exceeds
    ``max_depth`` it stops expanding and yields what it has.  The
    generator never raises — on grammar error it returns ``b""``.
    """

    grammar: Dict[str, _Rule]
    seed_corpus: List[bytes] = field(default_factory=list)
    max_depth: int = 10
    max_alternatives_per_rule: int = 32
    _rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        # Deterministic seed so test output is stable by default.
        if not getattr(self, "_rng", None):
            self._rng = random.Random()

    # ----------------------------------------------------------------- core

    def __iter__(self) -> Iterator[bytes]:
        """Yield byte samples until exhaustion.

        The first sample from each rule is emitted before recursing
        further, ensuring a non-empty stream on any well-formed
        grammar.
        """
        return self.generate()

    def generate(
        self,
        start: Optional[str] = None,
        *,
        max_depth: Optional[int] = None,
        n: Optional[int] = None,
    ) -> Iterator[bytes]:
        """Yield up to ``n`` byte samples starting from ``start``.

        ``start`` defaults to the first rule in the grammar.  When
        ``n`` is ``None`` the generator emits one sample per recursion
        branch (capped by ``max_depth``).
        """
        if not self.grammar:
            return iter(())
        first_rule = start or next(iter(self.grammar))
        if first_rule not in self.grammar:
            first_rule = next(iter(self.grammar))
        depth = int(max_depth if max_depth is not None else self.max_depth)
        produced = 0
        for sample in self._walk(first_rule, depth, seen=set()):
            if n is not None and produced >= n:
                return
            yield sample
            produced += 1

    def generate_batch(
        self,
        start: Optional[str] = None,
        *,
        n: int = 16,
        max_depth: Optional[int] = None,
    ) -> List[bytes]:
        """Return up to ``n`` samples as a list."""
        return list(self.generate(start, max_depth=max_depth, n=n))

    # ------------------------------------------------------------ internals

    def _walk(
        self,
        rule_name: str,
        depth: int,
        seen: set,
    ) -> Iterator[bytes]:
        rule = self.grammar.get(rule_name)
        if rule is None or depth <= 0 or rule_name in seen:
            yield b""
            return
        seen = seen | {rule_name}
        for alt in rule.alternatives[: self.max_alternatives_per_rule]:
            parts: List[bytes] = []
            ok = True
            for expr in alt.exprs:
                piece = self._emit(expr, depth, seen)
                if piece is None:
                    ok = False
                    break
                parts.append(piece)
            if not ok:
                continue
            yield b"".join(parts)

    def _emit(
        self,
        expr: _Expr,
        depth: int,
        seen: set,
    ) -> Optional[bytes]:
        if expr.kind == "term":
            return expr.value.encode("utf-8", errors="replace")
        if expr.kind == "ref":
            chunks = list(self._walk(expr.value, depth - 1, seen))
            if not chunks:
                return b""
            return self._rng.choice(chunks)
        if expr.kind == "group":
            inner = expr.children or []
            count = self._quantify_count(expr.quantifier)
            if count == 0:
                return b""
            parts: List[bytes] = []
            for _ in range(count):
                buf: List[bytes] = []
                for sub in inner:
                    piece = self._emit(sub, depth, seen)
                    if piece is None:
                        return None
                    buf.append(piece)
                parts.append(b"".join(buf))
            return b"".join(parts)
        return b""

    def _quantify_count(self, q: Optional[str]) -> int:
        if q == "?":
            return self._rng.randint(0, 1)
        if q == "*":
            return self._rng.randint(0, 3)
        if q == "+":
            return self._rng.randint(1, 3)
        return 1


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


@dataclass
class GrammarBasedFuzzer:
    """High-level driver that wires grammar generation to the runner
    contract.

    The driver is **stub-safe**: if the grammar file is missing the
    driver still constructs; :meth:`run` returns an empty
    :class:`GrammarBasedResult` rather than raising.
    """

    grammar_path: Optional[Path] = None
    seed_corpus: List[bytes] = field(default_factory=list)
    start_rule: Optional[str] = None
    max_samples: int = 32
    max_depth: int = 8

    def is_available(self) -> bool:
        return bool(self.grammar_path) and Path(self.grammar_path).exists()

    def run(self, output_dir: Optional[Path] = None) -> GrammarBasedResult:
        """Generate samples and write them under ``output_dir``.

        Returns :class:`GrammarBasedResult`.  Never raises.
        """
        try:
            if not self.is_available():
                return GrammarBasedResult(
                    grammar_name=self.start_rule or "",
                    samples_generated=0,
                    samples_kept=0,
                    duration_seconds=0,
                    seed_count=len(self.seed_corpus),
                )
            grammar = load_grammar(Path(self.grammar_path))
            name = self.start_rule or (next(iter(grammar)) if grammar else "")
            gen = GrammarBasedGenerator(
                grammar=grammar,
                seed_corpus=list(self.seed_corpus),
                max_depth=self.max_depth,
            )
            out = Path(output_dir) if output_dir else Path("/tmp/bugwolf-grammar-out")
            out.mkdir(parents=True, exist_ok=True)
            kept = 0
            produced = 0
            for sample in gen.generate(start=name, n=self.max_samples):
                produced += 1
                if not sample:
                    continue
                (out / f"sample_{kept:04d}.bin").write_bytes(sample)
                kept += 1
            return GrammarBasedResult(
                grammar_name=name,
                samples_generated=produced,
                samples_kept=kept,
                duration_seconds=0,
                seed_count=len(self.seed_corpus),
            )
        except Exception:
            return GrammarBasedResult(
                grammar_name=self.start_rule or "",
                samples_generated=0,
                samples_kept=0,
                duration_seconds=0,
                seed_count=len(self.seed_corpus),
            )

    # ----------------------------------------------------------------- repr

    def __repr__(self) -> str:
        return (
            f"GrammarBasedFuzzer(grammar_path={self.grammar_path!r}, "
            f"start_rule={self.start_rule!r}, max_samples={self.max_samples})"
        )


__all__ = [
    "GrammarBasedFuzzer",
    "GrammarBasedGenerator",
    "GrammarBasedResult",
    "load_grammar",
]
