# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-regression-governance-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Regression suite — every governance module has a public surface."""

SCHEMA = "bugwolf-benchmarks-regression-governance-v1"

import importlib
import sys
import unittest
from pathlib import Path


def _ensure_project_root():
    project_root = str(Path(__file__).resolve().parents[2])
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    return project_root


def _governance_modules():
    _ensure_project_root()
    here = Path(__file__).resolve()
    base = None
    for parent in here.parents:
        candidate = parent / "bugwolf" / "governance"
        if candidate.exists():
            base = candidate
            break
    if base is None or not base.exists():
        return []
    out = []
    for p in sorted(base.glob("*.py")):
        if p.stem.startswith("_") or p.stem == "__init__":
            continue
        out.append("bugwolf.governance." + p.stem)
    return out


class GovernanceTests(unittest.TestCase):
    pass


def _attach():
    for fq in _governance_modules():
        def _make(name=fq):
            def _test(self):
                mod = importlib.import_module(name)
                has_all = hasattr(mod, "__all__") and bool(getattr(mod, "__all__"))
                publics = [n for n in dir(mod)
                           if not n.startswith("_") and not n.isupper()]
                if not has_all and not publics:
                    self.fail("governance module %s is empty" % name)
                if not has_all:
                    self.assertGreater(len(publics), 0,
                                       "no __all__ and no public symbols in %s" % name)
            return _test

        setattr(GovernanceTests, "test_" + fq.replace(".", "_"), _make())


_attach()


def _build_suite():
    loader = unittest.TestLoader()
    return unittest.TestSuite([
        loader.loadTestsFromTestCase(GovernanceTests),
    ])


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(_build_suite())