# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-scoring-chain-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Chain validity scorer — structural lint for chain dicts."""

SCHEMA = "bugwolf-benchmarks-scoring-chain-v1"


_VALID_KINDS = ("probe", "exploit", "analyze", "pivot")

# Heuristic hints for inferring a step kind from its ``technique`` field.
# Order matters — the first matching hint wins, so put analyze-only hints
# first to avoid being shadowed by the broader exploit list.
_ANALYZE_HINTS = (
    "analyze", "analyse", "detect", "introspect", "enum", "classify",
    "type_", "check", "verify", "probe", "discover", "fingerprint",
)
_PIVOT_HINTS = (
    "register", "delivery", "open_redirect", "subdomain", "build",
)
_EXPLOIT_HINTS = (
    "exploit", "attack", "rce", "smuggle", "hijack", "bypass",
    "double_spend", "leak", "poison", "takeover", "capture", "stealer",
    "spray", "fuzz", "craft", "replay", "redirect", "credential",
    "session_", "claim_", "impersonation", "harvest", "injection",
    "exec", "xss_", "desync", "pivot", "query", "walk", "low_priv",
    "ssrf", "xss", "leak_", "steal", "csrf", "confirm", "verify",
    "exchange", "hit_", "mass", "fanout", "spend", "measure", "window",
    "report",
)


def _infer_kind(step):
    """Return the canonical kind for a step dict.

    Accepts an explicit ``kind`` field or infers from the ``technique``
    name using ordered heuristics. Always returns one of the four valid
    kinds so the caller does not have to deal with ``None``.
    """
    kind = step.get("kind")
    if kind in _VALID_KINDS:
        return kind
    technique = (step.get("technique") or "").lower()
    if any(h in technique for h in _ANALYZE_HINTS):
        return "analyze"
    if any(h in technique for h in _PIVOT_HINTS):
        return "pivot"
    if any(h in technique for h in _EXPLOIT_HINTS):
        return "exploit"
    return "probe"


def chain_validity(chain):
    """Return ``{valid, errors, step_count, has_exploit}`` for a chain dict."""
    errors = []
    if not isinstance(chain, dict):
        return {"valid": False, "errors": ["chain must be a dict"],
                "step_count": 0, "has_exploit": False}

    if not chain.get("id"):
        errors.append("missing id")
    if not chain.get("title"):
        errors.append("missing title")

    steps = chain.get("steps") or []
    if len(steps) < 2:
        errors.append("chain has fewer than 2 steps")

    kinds = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            errors.append("step %d is not a dict" % i)
            continue
        # Strict validation: if a kind is explicitly set it must be valid;
        # otherwise we infer from ``technique`` (lenient for legacy YAMLs).
        explicit_kind = step.get("kind")
        if explicit_kind is None:
            kind = _infer_kind(step)
        elif explicit_kind in _VALID_KINDS:
            kind = explicit_kind
        else:
            errors.append("step %d has invalid kind=%r" % (i, explicit_kind))
            kind = explicit_kind
        kinds.append(kind)

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "step_count": len(steps),
        "has_exploit": "exploit" in kinds,
    }


def _run_self_tests():
    import unittest

    class ChainTests(unittest.TestCase):
        def test_valid_chain(self):
            chain = {
                "id": "01_demo",
                "title": "demo chain",
                "steps": [
                    {"order": 1, "kind": "probe"},
                    {"order": 2, "kind": "exploit"},
                ],
            }
            res = chain_validity(chain)
            self.assertTrue(res["valid"])
            self.assertEqual(res["step_count"], 2)
            self.assertTrue(res["has_exploit"])

        def test_invalid_kind(self):
            chain = {
                "id": "x", "title": "x",
                "steps": [{"kind": "nope"}],
            }
            res = chain_validity(chain)
            self.assertFalse(res["valid"])
            self.assertTrue(any("invalid kind" in e for e in res["errors"]))

        def test_too_few_steps(self):
            chain = {"id": "x", "title": "x", "steps": [{"kind": "probe"}]}
            res = chain_validity(chain)
            self.assertFalse(res["valid"])
            self.assertTrue(any("fewer than 2" in e for e in res["errors"]))

        def test_no_exploit(self):
            chain = {
                "id": "x", "title": "x",
                "steps": [{"kind": "probe"}, {"kind": "analyze"}],
            }
            res = chain_validity(chain)
            self.assertTrue(res["valid"])
            self.assertFalse(res["has_exploit"])

        def test_not_a_dict(self):
            res = chain_validity("not a dict")
            self.assertFalse(res["valid"])
            self.assertIn("chain must be a dict", res["errors"])

        def test_inferred_kind_from_technique(self):
            chain = {
                "id": "x", "title": "x",
                "steps": [
                    {"technique": "introspection_query"},
                    {"technique": "leak_payload"},
                ],
            }
            res = chain_validity(chain)
            self.assertTrue(res["valid"], res["errors"])
            self.assertTrue(res["has_exploit"])

        def test_inferred_analyze_first(self):
            chain = {
                "id": "x", "title": "x",
                "steps": [
                    {"technique": "type_discovery"},
                    {"technique": "ssrf_oob"},
                ],
            }
            res = chain_validity(chain)
            self.assertTrue(res["valid"], res["errors"])
            self.assertEqual(res["step_count"], 2)

    return unittest.TestLoader().loadTestsFromTestCase(ChainTests)


if __name__ == "__main__":
    import unittest
    unittest.TextTestRunner(verbosity=2).run(_run_self_tests())
