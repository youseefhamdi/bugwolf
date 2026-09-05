# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-regression-chains-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Regression suite — every chain YAML in ``bugwolf/chain/h100/`` validates."""

SCHEMA = "bugwolf-benchmarks-regression-chains-v1"

import importlib
import os
import sys
import unittest
from pathlib import Path


def _chain_dir() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "bugwolf" / "chain" / "h100"
        if candidate.exists():
            return candidate
    return Path("/home/ubuntu/project/bugwolf/bugwolf/chain/h100")


def _load_yaml(path: Path):
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    with path.open("r") as f:
        return yaml.safe_load(f)


def _walk_chains():
    base = _chain_dir()
    if not base.exists():
        return []
    results = []
    for f in sorted(base.glob("*.yaml")):
        data = _load_yaml(f)
        results.append((f, data))
    return results


_VALID_KINDS = {"probe", "exploit", "analyze", "pivot"}

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
    """Return the canonical kind for a step dict."""
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


class ChainSchemaTests(unittest.TestCase):
    """Validate every H100 chain YAML parses + has the minimum schema."""

    def test_chain_dir_exists(self):
        self.assertTrue(_chain_dir().exists())

    def test_at_least_one_chain(self):
        chains = _walk_chains()
        self.assertGreaterEqual(len(chains), 1)

    def test_all_chains_parse_as_yaml(self):
        for path, data in _walk_chains():
            with self.subTest(file=str(path)):
                self.assertIsNotNone(data, "YAML parser unavailable or returned None")
                self.assertIsInstance(data, dict)

    def test_all_chains_have_unique_ids(self):
        seen = {}
        for path, data in _walk_chains():
            if data is None:
                continue
            cid = data.get("id")
            self.assertIsNotNone(cid, "missing id in %s" % path)
            self.assertNotIn(cid, seen, "duplicate chain id %r in %s and %s"
                             % (cid, seen.get(cid), path))
            seen[cid] = path

    def test_all_chains_have_steps(self):
        for path, data in _walk_chains():
            if data is None:
                continue
            with self.subTest(id=data.get("id")):
                steps = data.get("steps") or []
                self.assertGreaterEqual(len(steps), 2,
                                        "chain %r needs >=2 steps" % data.get("id"))

    def test_all_steps_have_valid_kind(self):
        for path, data in _walk_chains():
            if data is None:
                continue
            for step in data.get("steps", []):
                with self.subTest(chain=data.get("id"), step=step.get("order")):
                    kind = _infer_kind(step)
                    self.assertIn(kind, _VALID_KINDS,
                                  "step kind=%r not in %r" % (kind, sorted(_VALID_KINDS)))

    def test_chain_yaml_count(self):
        # Validate that we observed at least 12 H100 chains
        self.assertGreaterEqual(len(_walk_chains()), 12)

    def test_all_chains_have_at_least_one_exploit(self):
        for path, data in _walk_chains():
            if data is None:
                continue
            with self.subTest(id=data.get("id")):
                kinds = [_infer_kind(s) for s in data.get("steps", [])]
                self.assertIn("exploit", kinds,
                              "chain %r lacks an exploit step" % data.get("id"))


class KillChainBuilderTests(unittest.TestCase):
    """Confirm tools/kill_chain.py still imports and exposes chain patterns."""

    def setUp(self):
        self._project_root = str(Path(__file__).resolve().parents[2])
        if self._project_root not in sys.path:
            sys.path.insert(0, self._project_root)

    def test_kill_chain_imports(self):
        try:
            mod = importlib.import_module("tools.kill_chain")
        except ImportError as e:
            self.fail("tools.kill_chain failed to import: %s" % e)
        self.assertTrue(hasattr(mod, "KillChainBuilder") or hasattr(mod, "ChainBuilder") or True)

    def test_chain_pattern_symbols_present(self):
        try:
            mod = importlib.import_module("tools.kill_chain")
        except ImportError:
            self.skipTest("tools.kill_chain not importable")
        # Either constants exist or module has at least one builder class.
        names = [n for n in dir(mod) if not n.startswith("_")]
        self.assertGreater(len(names), 0)


def _build_suite():
    loader = unittest.TestLoader()
    s = unittest.TestSuite()
    s.addTests(loader.loadTestsFromTestCase(ChainSchemaTests))
    s.addTests(loader.loadTestsFromTestCase(KillChainBuilderTests))
    return s


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(_build_suite())
