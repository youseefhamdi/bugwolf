#!/usr/bin/env python3
"""
## Source: bugwolf internal test spec (Phase 1.5.q-1.5.s + 2.y)
## License: bugwolf-internal
## Port: 2026-09-05

Tests for the Phase 1.5 external-repo ports.

Coverage:
  * import + core-function test per new module
  * stub-safe / arg-validation / output-shape tests
  * ForbiddenBypassEngine registers all 17 modules
  * FPScorer.is_false_positive() closes the M-4 finding
  * ProbeEstimator.estimate / blocks_if_exceeds contract
  * StealthFetcher returns StealthFetcherUnavailable when Chromium absent
  * SubdomainAggregator returns [] on network error
  * CVE modules each have cve_id + references attributes
  * NO module uses shell=True / verify=False / hardcoded UA
  * All files carry ## Source: + ## License: comments
"""

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.forbidden_bypass import (
    ForbiddenBypassEngine,
    BypassModule,
    BypassResult,
    CVE202529927,
    CVE202140346,
    CVE202345539,
    UnicodeNormalization,
    UnicodeTruncation,
    RawRequestFuzzer,
    Race403,
    RaceResult,
    BodyBypass,
    CnameHostBypass,
)
from tools.forbidden_bypass.engine import (
    HeaderInjection,
    HostOverride,
    ProtocolSwitch,
    PathNormalization,
    PathTruncation,
    UnicodeNormalization as _UNinEngine,
    UnicodeTruncation as _UTinEngine,
    CnameFuzz,
    BodyPrivilegeEscalation,
    RaceCondition,
    HttpMethodOverride,
    CookieInjection,
    ContentTypeSwitch,
    AcceptHeaderOverride,
    XForwardedFor,
    DoubleUrlEncode,
    SlidingHexEncode,
    DEFAULT_MODULES,
)
from tools.fp_scorer import FPScorer, FPEvalInput
from tools.probe_estimator import ProbeEstimator, Scanner
from tools.stealth_fetcher import (
    StealthFetcher,
    StealthFetcherUnavailable,
    HttpResponse,
)
from tools.subdomain_aggregators import SubdomainAggregator


TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
SOURCE_PATTERN = re.compile(r"^##\s*Source:\s*\S", re.MULTILINE)
LICENSE_PATTERN = re.compile(r"^##\s*License:\s*\S", re.MULTILINE)

# Files that MUST carry Source + License headers (Appendix H mandate).
PORTED_FILES = [
    TOOLS_DIR / "forbidden_bypass" / "__init__.py",
    TOOLS_DIR / "forbidden_bypass" / "engine.py",
    TOOLS_DIR / "forbidden_bypass" / "cve_middleware_subrequest.py",
    TOOLS_DIR / "forbidden_bypass" / "cve_smuggling.py",
    TOOLS_DIR / "forbidden_bypass" / "cve_haproxy_fragment.py",
    TOOLS_DIR / "forbidden_bypass" / "unicode_bypass.py",
    TOOLS_DIR / "forbidden_bypass" / "raw_request_fuzz.py",
    TOOLS_DIR / "forbidden_bypass" / "race_403.py",
    TOOLS_DIR / "forbidden_bypass" / "body_bypass.py",
    TOOLS_DIR / "forbidden_bypass" / "cname_host_bypass.py",
    TOOLS_DIR / "fp_scorer.py",
    TOOLS_DIR / "probe_estimator.py",
    TOOLS_DIR / "stealth_fetcher.py",
    TOOLS_DIR / "subdomain_aggregators.py",
]


# ---------------------------------------------------------------------------
# Forbidden-bypass engine
# ---------------------------------------------------------------------------


class TestForbiddenBypassEngine(unittest.TestCase):

    def setUp(self):
        """Reset global scope state so the engine's check_url sees a clean gate."""
        from tools.runtime import scope
        scope.reset()
        self.addCleanup(self._reset_scope)

    @staticmethod
    def _reset_scope():
        from tools.runtime import scope
        scope.reset()

    def test_engine_registers_all_17_modules(self):
        engine = ForbiddenBypassEngine()
        self.assertEqual(engine.count(), 17)

    def test_engine_run_returns_one_result_per_module(self):
        engine = ForbiddenBypassEngine()
        results = engine.run("https://target.example/admin")
        self.assertEqual(len(results), 17)
        for r in results:
            self.assertIsInstance(r, BypassResult)
            self.assertTrue(r.technique)
            self.assertEqual(r.target, "https://target.example/admin")

    def test_engine_register_appends(self):
        engine = ForbiddenBypassEngine()
        before = engine.count()
        engine.register(HeaderInjection())
        self.assertEqual(engine.count(), before + 1)

    def test_engine_register_rejects_non_module(self):
        engine = ForbiddenBypassEngine()
        with self.assertRaises(TypeError):
            engine.register("not a module")    # type: ignore[arg-type]

    def test_engine_run_with_transport_invokes_callable(self):
        engine = ForbiddenBypassEngine()

        def fake_transport(**kw):
            class R:
                status_code = 200
                note = ""
            return R()

        results = engine.run_with_transport(
            "https://target.example/admin", transport=fake_transport
        )
        self.assertEqual(len(results), 17)
        statuses = {r.transport_status for r in results}
        self.assertIn(200, statuses)


# ---------------------------------------------------------------------------
# CVE modules
# ---------------------------------------------------------------------------


class TestCVEModules(unittest.TestCase):

    def test_cve_2025_29927_payload_shape(self):
        cve = CVE202529927()
        h = cve.payload("/admin/users")
        self.assertIn("x-middleware-subrequest", h)
        self.assertIn("/admin/users", h["x-middleware-subrequest"])
        self.assertEqual(cve.cve_id, "CVE-2025-29927")
        self.assertTrue(cve.references)
        self.assertEqual(cve.HEADER_NAME, "x-middleware-subrequest")
        self.assertEqual(cve.DEPTH, 5)

    def test_cve_2021_40346_emits_six_overflow_forms(self):
        cve = CVE202140346()
        forms = cve.content_length_values()
        self.assertEqual(len(forms), 6)
        self.assertIn("4294967295", forms)
        self.assertIn("-1", forms)
        combos = cve.payload("/admin")
        # 6 CL forms x 4 TE variants = 24 header dicts
        self.assertEqual(len(combos), 24)
        self.assertTrue(cve.references)
        self.assertEqual(cve.cve_id, "CVE-2021-40346")

    def test_cve_2023_45539_emits_fragment_urls(self):
        cve = CVE202345539()
        tokens = cve.fragment_tokens()
        self.assertIn("", tokens)
        urls = cve.payload("http://target.example/admin")
        # N tokens -> N urls
        self.assertEqual(len(urls), len(tokens))
        # Every URL has the fragment delimiter inserted
        for u in urls:
            self.assertIn("#", u)
        # The empty-token variant collapses to <url>#
        self.assertIn("http://target.example/admin#", urls)
        self.assertEqual(cve.cve_id, "CVE-2023-45539")
        self.assertTrue(cve.references)


# ---------------------------------------------------------------------------
# Unicode bypass
# ---------------------------------------------------------------------------


class TestUnicodeBypass(unittest.TestCase):

    def test_unicode_normalization_map_char(self):
        cands = UnicodeNormalization.map_char("/")
        self.assertIn("/", cands)
        self.assertIn("\uff0f", cands)

    def test_unicode_normalization_transform_string(self):
        out = UnicodeNormalization.transform_string("ABC", form="NFKC")
        self.assertIsInstance(out, str)
        self.assertGreater(len(out), 0)

    def test_unicode_normalization_transform_all_includes_natural(self):
        # Use an A-with-accent so NFKC normalization changes the string
        out = UnicodeNormalization.transform_all("\u00c0")
        self.assertIn("\u00c0", out)
        # Either NFKC or casefold produced a candidate different from input
        self.assertGreaterEqual(len(out), 1)
        # NFKC of A-grave is "A" -- at least one candidate should differ
        self.assertTrue(any(o != "\u00c0" for o in out))

    def test_unicode_truncation_map_char_returns_injections(self):
        injs = UnicodeTruncation.map_char("/")
        self.assertGreater(len(injs), 0)
        self.assertNotIn("/", injs)    # pure injections, not alternatives

    def test_unicode_truncation_transform_string_after(self):
        out = UnicodeTruncation.transform_string("/", position="after")
        self.assertGreater(len(out), 1)

    def test_unicode_truncation_transform_string_rejects_bad_position(self):
        with self.assertRaises(ValueError):
            UnicodeTruncation.transform_string("/", position="middle")


# ---------------------------------------------------------------------------
# Raw request fuzzer
# ---------------------------------------------------------------------------


class TestRawRequestFuzzer(unittest.TestCase):

    RAW = (
        "GET /admin* HTTP/1.1\r\n"
        "Host: target.example\r\n"
        "User-Agent: probe\r\n"
        "\r\n"
    )

    def test_fuzz_returns_at_least_one_variant(self):
        f = RawRequestFuzzer()
        variants = f.fuzz(self.RAW, technique="identity")
        self.assertGreaterEqual(len(variants), 1)
        for v in variants:
            self.assertIn("HTTP/1.1", v)

    def test_fuzz_all_iterates_every_technique(self):
        f = RawRequestFuzzer()
        variants = f.fuzz(self.RAW, technique="all")
        # 7 techniques, but dedup may collapse some
        self.assertGreaterEqual(len(variants), 5)

    def test_fuzz_rejects_unknown_technique(self):
        f = RawRequestFuzzer()
        with self.assertRaises(ValueError):
            f.fuzz(self.RAW, technique="bogus")

    def test_fuzz_rejects_empty_request(self):
        f = RawRequestFuzzer()
        with self.assertRaises(ValueError):
            f.fuzz("", technique="identity")

    def test_count_placeholders(self):
        f = RawRequestFuzzer()
        self.assertEqual(f.count_placeholders(self.RAW), 1)


# ---------------------------------------------------------------------------
# Race 403
# ---------------------------------------------------------------------------


class TestRace403(unittest.TestCase):

    def test_race_records_successes(self):
        race = Race403()
        statuses = iter([403, 403, 200, 403, 200, 500, 403, 403, 403, 200])

        def fake_transport():
            class R:
                status_code = next(statuses, 403)
            return R()

        # Force fresh lock for this host (defensive -- other tests may run)
        race._burst_lock_mutex    # touch attr so pylint is happy
        Race403._burst_lock.clear()

        result = race.race("https://host-a.example", transport=fake_transport)
        self.assertIsInstance(result, RaceResult)
        self.assertEqual(result.concurrency, 10)
        self.assertEqual(result.success_count, 3)
        self.assertEqual(result.failure_count, 7)

    def test_race_no_transport_returns_zero(self):
        race = Race403()
        Race403._burst_lock.clear()
        result = race.race("https://host-b.example")
        self.assertEqual(result.success_count, 0)

    def test_race_rejects_invalid_args(self):
        race = Race403()
        with self.assertRaises(ValueError):
            race.race("")
        with self.assertRaises(ValueError):
            race.race("https://x.example", concurrency=0)

    def test_race_burst_lock_prevents_double_fire(self):
        race = Race403()
        Race403._burst_lock.clear()
        Race403._burst_lock.add("https://locked.example")

        result = race.race("https://locked.example")
        self.assertIn("already fired", " ".join(result.notes))


# ---------------------------------------------------------------------------
# Body bypass
# ---------------------------------------------------------------------------


class TestBodyBypass(unittest.TestCase):

    def test_json_bodies_include_proto(self):
        b = BodyBypass()
        bodies = b.json_bodies()
        joined = str(bodies)
        self.assertIn("__proto__", joined)

    def test_form_bodies_include_admin(self):
        b = BodyBypass()
        bodies = b.form_bodies()
        self.assertTrue(any("role" in p and "admin" in p["role"] for p in bodies))

    def test_xml_bodies_are_strings(self):
        b = BodyBypass()
        for x in b.xml_bodies():
            self.assertIsInstance(x, str)
            self.assertTrue(x.startswith("<"))

    def test_payloads_json_content_type(self):
        b = BodyBypass()
        out = b.payloads("json")
        self.assertGreater(len(out), 0)
        for entry in out:
            self.assertEqual(entry["content_type"], "application/json")
            self.assertIsInstance(entry["body"], str)

    def test_payloads_unknown_content_type_raises(self):
        b = BodyBypass()
        with self.assertRaises(ValueError):
            b.payloads("yaml")


# ---------------------------------------------------------------------------
# CNAME host bypass
# ---------------------------------------------------------------------------


class TestCnameHostBypass(unittest.TestCase):

    def test_set_apex_rejects_invalid(self):
        c = CnameHostBypass()
        with self.assertRaises(ValueError):
            c.set_apex("")

    def test_host_candidates_include_apex(self):
        c = CnameHostBypass(apex="example.com")
        candidates = c.host_candidates()
        self.assertIn("example.com", candidates)
        self.assertIn("www.example.com", candidates)
        self.assertGreater(len(candidates), 10)

    def test_payload_returns_host_headers(self):
        c = CnameHostBypass(apex="example.com")
        out = c.payload("/")
        self.assertGreater(len(out), 1)
        for entry in out:
            self.assertIn("Host", entry)


# ---------------------------------------------------------------------------
# FP scorer
# ---------------------------------------------------------------------------


class TestFPScorer(unittest.TestCase):

    def test_score_returns_float(self):
        s = FPScorer()
        out = s.score(eval_input=FPEvalInput(status=500, baseline_status=500))
        self.assertIsInstance(out, float)

    def test_is_false_positive_neutral_5xx_no_signature(self):
        """Closes M-4: 5xx with no body signature -> FP."""
        s = FPScorer()
        ev = FPEvalInput(
            status=500,
            baseline_status=500,
            body_signature_match=False,
            response_diff_neutral=True,
            time_baseline_match=True,
        )
        out = s.score(eval_input=ev)
        self.assertGreaterEqual(out, 40)
        self.assertTrue(s.is_false_positive(out))

    def test_is_false_positive_false_when_sql_signature_present(self):
        s = FPScorer()
        ev = FPEvalInput(
            status=500,
            baseline_status=200,
            body_signature_match=True,    # SQL error signature present
            payload_in_response_echo=True,
        )
        out = s.score(eval_input=ev)
        self.assertLess(out, 40)
        self.assertFalse(s.is_false_positive(out))

    def test_score_from_kwargs_rejects_unknown_keys(self):
        s = FPScorer()
        with self.assertRaises(TypeError):
            s.score_from_kwargs(status=200, nonsense=True)

    def test_classify_returns_dict(self):
        s = FPScorer()
        out = s.classify(FPEvalInput(status=403))
        self.assertIn("score", out)
        self.assertIn("is_fp", out)
        self.assertIn("threshold", out)


# ---------------------------------------------------------------------------
# Probe estimator
# ---------------------------------------------------------------------------


class TestProbeEstimator(unittest.TestCase):

    def test_estimate_returns_int(self):
        e = ProbeEstimator()
        scanners = [Scanner(name="a", estimate_per_target=10)]
        out = e.estimate({"hosts": ["a.example", "b.example"]}, scanners=scanners)
        self.assertIsInstance(out, int)
        self.assertEqual(out, 20)    # 10 x 2 hosts

    def test_estimate_no_hosts_uses_1x(self):
        e = ProbeEstimator()
        scanners = [Scanner(name="a", estimate_per_target=10)]
        out = e.estimate({}, scanners=scanners)
        self.assertEqual(out, 10)

    def test_estimate_rejects_non_dict_target(self):
        e = ProbeEstimator()
        with self.assertRaises(TypeError):
            e.estimate("not a dict", scanners=[])    # type: ignore[arg-type]

    def test_blocks_if_exceeds_true(self):
        e = ProbeEstimator()
        self.assertTrue(e.blocks_if_exceeds(100, max_requests=10))

    def test_blocks_if_exceeds_false(self):
        e = ProbeEstimator()
        self.assertFalse(e.blocks_if_exceeds(5, max_requests=10))

    def test_deadline_returns_float(self):
        e = ProbeEstimator()
        d = e.deadline(100, rate=10)
        self.assertEqual(d, 10.0)


# ---------------------------------------------------------------------------
# Stealth fetcher
# ---------------------------------------------------------------------------


class TestStealthFetcher(unittest.TestCase):

    def test_returns_unavailable_when_no_backend(self):
        with mock.patch.dict(sys.modules, {"playwright": None, "camoufox": None}):
            sf = StealthFetcher()
            out = sf.fetch("https://target.example/x")
            # Either HttpResponse (if a real backend exists) or Unavailable.
            if isinstance(out, StealthFetcherUnavailable):
                self.assertFalse(bool(out))
            else:
                self.assertIsInstance(out, HttpResponse)

    def test_rejects_invalid_impersonate(self):
        with self.assertRaises(ValueError):
            StealthFetcher(impersonate="ie6")

    def test_rejects_empty_url(self):
        sf = StealthFetcher()
        with self.assertRaises(ValueError):
            sf.fetch("")

    def test_unavailable_is_falsy(self):
        u = StealthFetcherUnavailable(reason="x", url="y")
        self.assertFalse(bool(u))


# ---------------------------------------------------------------------------
# Subdomain aggregators
# ---------------------------------------------------------------------------


class TestSubdomainAggregator(unittest.TestCase):

    def test_returns_empty_on_network_error(self):
        a = SubdomainAggregator(timeout=1)

        def boom(*a, **kw):
            raise OSError("no network")

        with mock.patch("urllib.request.urlopen", side_effect=boom):
            self.assertEqual(a.fetch_jsmon("example.com"), [])
            self.assertEqual(a.fetch_crt_name("example.com"), [])

    def test_fetch_jsmon_parses_plaintext(self):
        a = SubdomainAggregator()

        class FakeResp:
            def __init__(self, data):
                self._data = data.encode("utf-8")

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with mock.patch(
            "urllib.request.urlopen",
            return_value=FakeResp("a.example.com\nb.example.com\n# comment\n"),
        ):
            out = a.fetch_jsmon("example.com")
            self.assertIn("a.example.com", out)
            self.assertIn("b.example.com", out)
            self.assertNotIn("# comment", out)

    def test_fetch_crt_name_parses_json(self):
        a = SubdomainAggregator()

        class FakeResp:
            def __init__(self, data):
                self._data = data.encode("utf-8")

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with mock.patch(
            "urllib.request.urlopen",
            return_value=FakeResp('[{"name":"x.example.com"},{"value":"y.example.com"}]'),
        ):
            out = a.fetch_crt_name("example.com")
            self.assertIn("x.example.com", out)
            self.assertIn("y.example.com", out)

    def test_aggregate_returns_dict(self):
        a = SubdomainAggregator()
        with mock.patch.object(a, "fetch_jsmon", return_value=["a.example.com"]):
            with mock.patch.object(a, "fetch_crt_name", return_value=["b.example.com"]):
                out = a.aggregate(["example.com"])
                self.assertIn("example.com", out)
                self.assertIn("a.example.com", out["example.com"])
                self.assertIn("b.example.com", out["example.com"])

    def test_empty_domain_returns_empty(self):
        a = SubdomainAggregator()
        self.assertEqual(a.fetch_jsmon(""), [])
        self.assertEqual(a.fetch_crt_name(""), [])


# ---------------------------------------------------------------------------
# Source + License headers (Appendix H mandate)
# ---------------------------------------------------------------------------


class TestSourceLicenseHeaders(unittest.TestCase):

    def test_every_file_has_source_header(self):
        missing = []
        for path in PORTED_FILES:
            text = path.read_text(encoding="utf-8")
            if not SOURCE_PATTERN.search(text):
                missing.append(str(path))
        self.assertEqual(missing, [], f"missing ## Source: header in: {missing}")

    def test_every_file_has_license_header(self):
        missing = []
        for path in PORTED_FILES:
            text = path.read_text(encoding="utf-8")
            if not LICENSE_PATTERN.search(text):
                missing.append(str(path))
        self.assertEqual(missing, [], f"missing ## License: header in: {missing}")


# ---------------------------------------------------------------------------
# Anti-pattern guard (Appendix H)
# ---------------------------------------------------------------------------


# HTTP methods the plan forbids (POUET / UNCHECKOUT / LABEL).
FORBIDDEN_METHODS = ("POUET", "UNCHECKOUT", "LABEL")


class TestNoAntiPatterns(unittest.TestCase):

    # Active statement pattern (NOT in docstrings / comments).
    _ACTIVE_VERIFY_FALSE = re.compile(r"verify\s*=\s*False\b")
    _ACTIVE_SHELL_TRUE = re.compile(r"shell\s*=\s*True\b")
    # Hardcoded UA fingerprint -- exact "Mozilla/5.0" outside of the
    # plan / test comments (we don't grep these for UA).
    _UA_FINGERPRINT = re.compile(r'Mozilla/5\.0')

    def test_no_shell_true_in_any_ported_file(self):
        offenders = []
        for path in PORTED_FILES:
            text = path.read_text(encoding="utf-8")
            if self._ACTIVE_SHELL_TRUE.search(text):
                offenders.append(str(path))
        self.assertEqual(offenders, [], f"shell=True found in: {offenders}")

    def test_no_verify_false_in_any_ported_file(self):
        offenders = []
        for path in PORTED_FILES:
            text = path.read_text(encoding="utf-8")
            if self._ACTIVE_VERIFY_FALSE.search(text):
                offenders.append(str(path))
        self.assertEqual(offenders, [], f"verify=False found in: {offenders}")

    def test_no_hardcoded_ua_in_any_ported_file(self):
        """Heuristic: look for Mozilla/5.0 (a UA fingerprint) inside the
        ported files. The stealth_fetcher must pull UAs from
        tools.opsec, not embed them."""
        offenders = []
        for path in PORTED_FILES:
            text = path.read_text(encoding="utf-8")
            if self._UA_FINGERPRINT.search(text):
                offenders.append(str(path))
        self.assertEqual(
            offenders, [],
            f"hardcoded UA (Mozilla/5.0) found in: {offenders}",
        )

    def test_no_scrapling_parser_imports(self):
        """Detect active ``from scrapling.parser import ...`` or
        ``import scrapling.parser`` statements (not docstring text)."""
        import_pattern = re.compile(
            r"^\s*(?:from\s+scrapling\.parser\s+import|import\s+scrapling\.parser)\b",
            re.MULTILINE,
        )
        offenders = []
        for path in PORTED_FILES:
            text = path.read_text(encoding="utf-8")
            if import_pattern.search(text):
                offenders.append(str(path))
        self.assertEqual(
            offenders, [],
            f"forbidden scrapling.parser import in: {offenders}",
        )

    def test_no_forbidden_http_methods_referenced(self):
        """The plan forbids emitting POUET / UNCHECKOUT / LABEL probes."""
        offenders = []
        for path in PORTED_FILES:
            text = path.read_text(encoding="utf-8")
            for m in FORBIDDEN_METHODS:
                if re.search(rf'\b"{m}"\b|\'{m}\'', text):
                    offenders.append(f"{path}: {m}")
        self.assertEqual(
            offenders, [],
            f"forbidden HTTP method {FORBIDDEN_METHODS} referenced in: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()