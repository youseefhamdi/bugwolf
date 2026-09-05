#!/usr/bin/env python3
"""Tests for tools/fuzz_engine.py (v1.24.1+)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.fuzz_engine import (
    FuzzTarget, generate, write, ENGINES, LANGUAGES,
)


class FuzzEngineHarnessGeneration(unittest.TestCase):

    def _gen(self, engine: str, lang: str, **kwargs):
        target = FuzzTarget(name="test", engine=engine, language=lang, **kwargs)
        return generate(target)

    def test_libfuzzer_c(self):
        h = self._gen("libfuzzer", "c")
        self.assertIn("harness.c", h.files)
        self.assertIn("LLVMFuzzerTestOneInput", h.files["harness.c"])
        self.assertIn("build.sh", h.files)
        self.assertIn("run.sh", h.files)

    def test_libfuzzer_rust(self):
        h = self._gen("libfuzzer", "rust")
        self.assertIn("src/fuzz_target.rs", h.files)
        self.assertIn("Cargo.toml", h.files)
        self.assertIn("fuzz_target", h.files["src/fuzz_target.rs"])

    def test_afl_c(self):
        h = self._gen("afl", "c")
        self.assertIn("harness.c", h.files)
        self.assertIn("afl-clang-fast", h.files["build.sh"])
        self.assertIn("afl-fuzz", h.files["run.sh"])

    def test_atheris_python(self):
        h = self._gen("atheris", "python")
        self.assertIn("harness.py", h.files)
        self.assertIn("atheris", h.files["harness.py"])
        self.assertIn("requirements.txt", h.files)

    def test_boofuzz(self):
        h = self._gen("boofuzz", "python")
        self.assertIn("harness.py", h.files)
        self.assertIn("boofuzz", h.files["harness.py"])

    def test_schemathesis(self):
        h = self._gen("schemathesis", "python", spec="openapi.json")
        self.assertIn("README.md", h.files)
        self.assertIn("openapi.json", h.files["run.sh"])

    def test_foundry_solidity(self):
        h = self._gen("foundry", "solidity")
        self.assertIn("test/Harness.t.sol", h.files)
        self.assertIn("forge test", h.files["run.sh"])

    def test_echidna_solidity(self):
        h = self._gen("echidna", "solidity")
        self.assertIn("Harness.sol", h.files)
        self.assertIn("echidna", h.files["run.sh"])

    def test_medusa_solidity(self):
        h = self._gen("medusa", "solidity")
        self.assertIn("Harness.sol", h.files)
        self.assertIn("medusa.json", h.files)
        self.assertIn("medusa", h.files["run.sh"])

    def test_honggfuzz(self):
        h = self._gen("honggfuzz", "c")
        self.assertIn("harness.c", h.files)
        self.assertIn("hfuzz-cc", h.files["build.sh"])
        self.assertIn("honggfuzz", h.files["run.sh"])

    def test_unknown_engine_raises(self):
        with self.assertRaises(ValueError):
            self._gen("not-a-real-engine", "c")

    def test_engines_inventory(self):
        self.assertIn("libfuzzer", ENGINES)
        self.assertIn("foundry", ENGINES)
        self.assertIn("echidna", ENGINES)
        self.assertIn("schemathesis", ENGINES)
        self.assertIn("boofuzz", ENGINES)
        self.assertEqual(len(ENGINES), 9)

    def test_languages_inventory(self):
        self.assertIn("c", LANGUAGES)
        self.assertIn("rust", LANGUAGES)
        self.assertIn("python", LANGUAGES)
        self.assertIn("solidity", LANGUAGES)

    def test_manifest_present(self):
        h = self._gen("libfuzzer", "c")
        self.assertEqual(h.manifest["schema"], "bugwolf-fuzz-engine/v1")
        self.assertEqual(h.manifest["engine"], "libfuzzer")
        self.assertEqual(h.manifest["language"], "c")
        self.assertIn("generated_at", h.manifest)
        self.assertEqual(h.manifest["file_count"], len(h.files))


class FuzzEngineDiskWrite(unittest.TestCase):

    def test_write_creates_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = FuzzTarget(name="t", engine="libfuzzer", language="c")
            h = generate(target)
            manifest = write(h, Path(tmp))
            files = list(Path(tmp).iterdir())
            self.assertGreater(len(files), 0)
            self.assertTrue((Path(tmp) / "manifest.json").exists())
            # The build script should be executable
            build = Path(tmp) / "build.sh"
            self.assertTrue(build.exists())
            mode = build.stat().st_mode
            self.assertTrue(mode & 0o111, "build.sh should be executable")

    def test_write_nested_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = FuzzTarget(name="t", engine="libfuzzer", language="rust")
            h = generate(target)
            write(h, Path(tmp))
            self.assertTrue((Path(tmp) / "src" / "fuzz_target.rs").exists())
            self.assertTrue((Path(tmp) / "Cargo.toml").exists())


if __name__ == "__main__":
    unittest.main()
