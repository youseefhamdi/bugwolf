#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.digest_canary import (
    canary_secret,
    check_output_leakage,
    dataset_digest,
    model_digest,
)


class TestDigestCanary(unittest.TestCase):
    def test_canary_secret_is_unique_and_labeled(self):
        secret = canary_secret("test")
        self.assertTrue(secret.startswith("BW-CANARY-"))
        self.assertNotEqual(secret, canary_secret("test"))

    def test_detects_canary_leakage_in_output(self):
        secret = "BW-CANARY-abc123"
        result = check_output_leakage("the secret is " + secret, [secret])
        self.assertTrue(result["leaked"])
        self.assertEqual(result["leaked_canaries"], [secret])

    def test_model_digest_is_stable(self):
        first = model_digest("model-name", "v1", adapter="openai")
        second = model_digest("model-name", "v1", adapter="openai")
        self.assertEqual(first, second)
        self.assertNotEqual(first, model_digest("model-name", "v2", adapter="openai"))

    def test_dataset_digest_tracks_provenance(self):
        digest = dataset_digest("corpus", ["a", "b"], version="2026-01")
        self.assertIn("corpus", digest)
        self.assertIn("2026-01", digest)


if __name__ == "__main__":
    unittest.main()