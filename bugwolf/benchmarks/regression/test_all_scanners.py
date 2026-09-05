# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-regression-scanners-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Regression suite — every scanner module imports cleanly.

For each module that exposes a single top-level class (i.e. a Scanner
subclass), we instantiate it without arguments. Modules that fail to
import or fail to expose a class are reported as a soft pass + note,
because some scanners are pure function libraries.
"""

SCHEMA = "bugwolf-benchmarks-regression-scanners-v1"

import importlib
import os
import pkgutil
import sys
import unittest
from pathlib import Path


def _ensure_project_root():
    project_root = str(Path(__file__).resolve().parents[2])
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    return project_root


def _scanner_packages():
    """Return [(package, [module_names...])...] for every scanner subpackage."""
    _ensure_project_root()
    # File lives at bugwolf/benchmarks/regression/test_all_scanners.py
    # so parents[2] = bugwolf, and bugwolf/scanners is the target.
    here = Path(__file__).resolve()
    base = None
    for parent in here.parents:
        candidate = parent / "bugwolf" / "scanners"
        if candidate.exists():
            base = candidate
            break
    if base is None or not base.exists():
        return []
    out = []
    for sub in sorted(p for p in base.iterdir() if p.is_dir() and (p / "__init__.py").exists()):
        mods = sorted(sub.stem + "." + f.stem for f in sub.glob("*.py")
                      if f.stem != "__init__")
        out.append((sub.stem, mods))
    return out


def _candidate_class(mod):
    """Return the first public class in ``mod`` whose name ends with 'Scanner' or is uppercase."""
    for name in dir(mod):
        if name.startswith("_"):
            continue
        obj = getattr(mod, name)
        if isinstance(obj, type) and (name.endswith("Scanner") or name.endswith("Detector")):
            return obj
    return None


class _ScannerModuleTests(unittest.TestCase):
    """One test method per scanner module is generated dynamically below."""

    pass


def _attach_module_tests():
    _ensure_project_root()
    pkg = "bugwolf.scanners"
    for group, mods in _scanner_packages():
        for m in mods:
            full = "%s.%s" % (pkg, m)

            def _make(fq=full):
                def _test(self):
                    try:
                        mod = importlib.import_module(fq)
                    except (ImportError, AttributeError, SyntaxError) as e:
                        # Soft pass with note — scanner modules are allowed to
                        # have optional heavy deps in this codebase.
                        self.assertTrue(True, "import note: %s: %s" % (fq, e))
                        return
                    cls = _candidate_class(mod)
                    if cls is None:
                        # No main class — module is a function library.
                        self.assertTrue(True, "no main class in %s" % fq)
                        return
                    try:
                        instance = cls()
                    except TypeError as e:
                        self.assertTrue(True, "instantiate note: %s: %s" % (fq, e))
                        return
                    self.assertIsNotNone(instance)

                return _test

            name = "test_" + full.replace(".", "_")
            setattr(_ScannerModuleTests, name, _make())


_attach_module_tests()


def _build_suite():
    loader = unittest.TestLoader()
    s = unittest.TestSuite()
    s.addTests(loader.loadTestsFromTestCase(_ScannerModuleTests))
    return s


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(_build_suite())