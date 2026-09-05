## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""ANTLR-style grammar set for the BugWolf fuzzing substrate.

The grammars are parsed at runtime by :func:`bugwolf.fuzz.grammar_based.load_grammar`.
They are documentation as much as executable specs — there is no
ANTLR runtime here, but the EBNF subset used by the parser matches
the syntax in these files.
"""

__all__ = [
    "GRAMMARS",
]


# Relative paths under grammars/
GRAMMARS = (
    "http.g4",
    "graphql.g4",
    "grpc.g4",
    "json.g4",
)
