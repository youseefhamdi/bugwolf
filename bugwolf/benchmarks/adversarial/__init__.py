# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-init-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Registry of adversarial benchmark apps.

The harness iterates ``BENCHMARK_APPS`` and launches each as a subprocess
on 127.0.0.1. Every entry is a ``(name, module_path)`` tuple where
``module_path`` is importable as ``python3 -m <module_path>``.
"""

SCHEMA = "bugwolf-benchmarks-adversarial-init-v1"

BENCHMARK_APPS = (
    ("sqli",        "bugwolf.benchmarks.adversarial.sqli_app"),
    ("xss",         "bugwolf.benchmarks.adversarial.xss_app"),
    ("ssrf",        "bugwolf.benchmarks.adversarial.ssrf_app"),
    ("idor",        "bugwolf.benchmarks.adversarial.idor_app"),
    ("jwt",         "bugwolf.benchmarks.adversarial.jwt_app"),
    ("race",        "bugwolf.benchmarks.adversarial.race_app"),
    ("deserialize", "bugwolf.benchmarks.adversarial.deserialize_app"),
    ("business",    "bugwolf.benchmarks.adversarial.business_logic_app"),
    ("llm",         "bugwolf.benchmarks.adversarial.llm_app"),
    ("graphql",     "bugwolf.benchmarks.adversarial.graphql_app"),
)


__all__ = ["BENCHMARK_APPS", "SCHEMA"]