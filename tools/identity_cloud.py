#!/usr/bin/env python3
"""Offline identity, cloud posture, and CVE triage for BugWolf.

This module analyzes supplied configuration, code, policy, and advisory text.
It never performs login attempts, MFA prompts, token replay, metadata access,
cloud API mutations, credential validation, or CVE exploitation.

Usage:
  python3 tools/identity_cloud.py --path infrastructure/ --plans --output-dir posture-review
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Sequence


@dataclass
class SecurityHypothesis:
    hypothesis_id: str
    category: str
    title: str
    source: str
    line_number: int
    severity: str
    rationale: str
    evidence_hash: str
    validation_questions: List[str] = field(default_factory=list)
    status: str = "offline_review_required"


@dataclass
class CveTriageRecord:
    cve_id: str
    source: str
    context: str
    validity: str = "unverified_reference"
    required_checks: List[str] = field(default_factory=lambda: [
        "Confirm the identifier and affected product against a trusted advisory.",
        "Confirm the installed version and program policy before testing.",
        "Use an isolated lab or vendor-safe check; do not run public exploit code on production.",
    ])
    status: str = "research_pending"
    # Optional enrichment fields populated by curated seed records.
    severity: str = ""
    cwe: str = ""
    product: str = ""
    fixed_in: str = ""
    summary: str = ""


@dataclass
class IdentityAuditPlan:
    plan_id: str
    category: str
    title: str
    offline_checks: List[str]
    authorized_validation: List[str]
    prohibited_actions: List[str]
    status: str = "plan_only"


_IDENTITY_RULES: Sequence[tuple[str, str, str, str, str, Sequence[str]]] = (
    (r"(?i)(legacy authentication|imap|pop3|smtp auth|basic authentication)", "legacy_auth", "Legacy authentication path may bypass modern policy", "high", "Legacy protocols or basic authentication can provide a path outside normal MFA/conditional-access policy.", ["Inventory the protocol and tenant policy offline.", "Validate only with a dedicated test account and provider-approved read-only check."]),
    (r"(?i)(mfa|2fa|multi.factor).{0,40}(false|disabled|optional|skip|bypass)", "mfa_policy_gap", "MFA policy gap requires review", "high", "Configuration or code appears to weaken MFA enforcement.", ["Compare policy requirements across all authentication paths.", "Use test accounts; never generate push floods or contact real users."]),
    (r"(?i)(enroll|register).{0,50}(factor|authenticator|phone|device)|factor.{0,50}(enroll|register)", "factor_enrollment", "MFA factor enrollment boundary", "high", "Factor enrollment or replacement requires strong reauthentication and ownership checks.", ["Review enrollment prerequisites and audit events offline.", "Validate with a disposable test tenant/account and one controlled factor."]),
    (r"(?i)(oauth|oidc).{0,100}(redirect_uri|redirect_uris).{0,30}(\*|任意|any|wildcard)", "oauth_redirect_policy", "OAuth redirect policy may be overly broad", "high", "Broad redirect handling can weaken code/token delivery boundaries.", ["Compare registered redirect URIs to exact-match policy.", "Use a provider sandbox; do not send phishing or consent links."]),
    (r"(?i)(oauth|consent).{0,80}(scope|permission).{0,80}(mail|drive|admin|wide|offline)", "oauth_consent_scope", "OAuth consent scope requires least-privilege review", "medium", "An application may request more persistent access than its function requires.", ["Review app registration and consent records.", "Do not grant permissions or access real user data during validation."]),
    (r"(?i)(saml|oidc|jwt).{0,100}(alg\s*[:=]\s*none|unsigned|signature.{0,10}(skip|disable)|aud|iss|amr|acr)", "federated_claim_validation", "Federated identity claim validation requires review", "high", "Signature, audience, issuer, or authentication-context handling is security-sensitive.", ["Inspect validation configuration and trusted issuer metadata.", "Use signed lab fixtures only; never forge production assertions."]),
    (r"(?i)(session|cookie|token).{0,80}(expiry|expire|invalidate|revok|reuse|device|binding)", "session_lifecycle", "Session or token lifecycle control requires review", "medium", "Session invalidation, binding, and expiry determine whether authentication state persists unexpectedly.", ["Review TTL, revocation, rotation, and logout semantics.", "Use test tokens and never replay captured user sessions."]),
    (r"(?i)(password|mfa).{0,60}(reset|helpdesk|recovery|support)", "recovery_assurance", "Account recovery assurance boundary", "high", "Recovery flows can become an alternate authentication path if identity proof is weak.", ["Review recovery policy and audit logging.", "Use documented helpdesk test procedures; no social engineering or real-user contact."]),
)

_CLOUD_RULES: Sequence[tuple[str, str, str, str, str, Sequence[str]]] = (
    (r'(?i)("Action"\s*:\s*"\*"|action:\s*\*|permissions:\s*\*|admin\s*[:=]\s*true)', "overbroad_identity", "Cloud identity grants broad capability", "high", "An identity policy appears to grant more actions than a bounded workload needs.", ["Review effective permissions and trust boundaries offline.", "Use read-only policy simulation in a dedicated account; do not create keys or alter policies."]),
    (r'(?i)("Resource"\s*:\s*"\*"|resource:\s*\*)', "overbroad_resource", "Cloud policy targets all resources", "high", "A wildcard resource may expand the blast radius of an otherwise narrow action.", ["Map action/resource pairs and owner-approved necessity.", "Do not assume or mutate roles during validation."]),
    (r"(?i)(0\.0\.0\.0/0|::/0).{0,80}(22|3389|3306|5432|6379|9200|database|ssh|rdp)", "public_network_boundary", "Sensitive service appears publicly reachable", "high", "A network rule may expose an administrative or data service to the public network.", ["Confirm the rule in IaC or an authorized read-only inventory.", "Do not connect to or authenticate against the service without explicit scope."]),
    (r"(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata service)", "metadata_boundary", "Cloud metadata boundary reference", "high", "Application or configuration references a cloud metadata endpoint.", ["Review SSRF defenses and workload identity configuration in a lab.", "Never request metadata credentials or access a production metadata service."]),
    (r"(?i)(public|anonymous).{0,50}(bucket|blob|storage|object|read|write|list)", "public_storage", "Cloud storage exposure hypothesis", "high", "Storage policy or documentation may permit public access.", ["Inspect policy and fixture objects without downloading sensitive data.", "Use provider policy analysis rather than object enumeration."]),
    (r"(?i)(sts:assumerole|assumerole|cross.account|principal).{0,100}(\*|root|external)", "cross_account_trust", "Cross-account trust requires review", "high", "A trust relationship may allow an unintended external principal or broad role assumption.", ["Review trust policy and account ownership.", "Do not assume the role or create credentials."]),
    (r"(?i)(process\.env|environment variables|AWS_SECRET|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS).{0,80}(error|debug|log|response|trace)", "secret_error_exposure", "Environment or credential material may reach diagnostics", "high", "Error/debug output appears related to environment or credential values.", ["Use synthetic secrets in a local fixture and inspect redaction controls.", "Never collect or validate real credentials."]),
    (r"(?i)(lambda|function|serverless|api gateway).{0,80}(public|anonymous|ANY|proxy|unauthenticated)", "serverless_exposure", "Serverless trigger may be broadly reachable", "medium", "A function or gateway route may lack an intended identity boundary.", ["Review route policy and invocation permissions offline.", "Use a sandbox test function only."]),
)


def _hypothesis(source: str, line_number: int, category: str, title: str,
                severity: str, rationale: str, line: str,
                questions: Sequence[str]) -> SecurityHypothesis:
    digest = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
    identifier = hashlib.sha256(f"{source}:{line_number}:{category}:{digest}".encode()).hexdigest()[:16]
    return SecurityHypothesis(identifier, category, title, source, line_number,
                              severity, rationale, digest, list(questions))


def analyze_text(text: str, source: str = "artifact") -> List[SecurityHypothesis]:
    results: List[SecurityHypothesis] = []
    rules = list(_IDENTITY_RULES) + list(_CLOUD_RULES)
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, category, title, severity, rationale, questions in rules:
            if re.search(pattern, line):
                results.append(_hypothesis(source, line_number, category, title,
                                           severity, rationale, line, questions))
    return results


def _extract_cve_references_legacy(text: str, source: str = "artifact") -> List[CveTriageRecord]:
    records: Dict[str, CveTriageRecord] = {}
    pattern = re.compile(r"(?<![A-Z0-9])CVE-[0-9]{4}-[0-9]{4,}(?![0-9])", re.IGNORECASE)
    for match in pattern.finditer(text):
        cve_id = match.group(0).upper()
        context = text[max(0, match.start() - 100):match.end() + 160].replace("\n", " ")[:300]
        records.setdefault(cve_id, CveTriageRecord(cve_id, source, context))
    return sorted(records.values(), key=lambda record: record.cve_id)


def extract_cve_references(text: str, source: str = "artifact") -> List[CveTriageRecord]:
    records: Dict[str, CveTriageRecord] = {}
    pattern = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,}(?!\d)", re.IGNORECASE)
    for match in pattern.finditer(text):
        cve_id = match.group(0).upper()
        context = text[max(0, match.start() - 100):match.end() + 160].replace("\n", " ")[:300]
        records.setdefault(cve_id, CveTriageRecord(cve_id, source, context))
    return sorted(records.values(), key=lambda record: record.cve_id)


# Field-annotated CVE references in nuclei templates: the ``id:`` line, the
# ``classification.cve-id``/``cve_id`` mapping, and ``reference`` URLs are the
# most reliable provenance. Everything is still treated as unverified.
_NUCLEI_CVE_FIELD_RE = re.compile(
    r"(?im)^\s*(?:id|cve[-_]?id|cve)\s*[:=-]\s*(CVE-\d{4}-\d{4,})\b|"
    r"\breference\s*:\s*.*?(CVE-\d{4}-\d{4,})\b"
)


def _template_reference_urls(text: str) -> List[str]:
    """URLs listed under a ``reference:`` block (list items ``- https://…``)."""
    urls: List[str] = []
    in_reference = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^reference\s*:", stripped):
            in_reference = True
            continue
        if in_reference:
            if stripped.startswith("- http"):
                urls.append(stripped.lstrip("-").strip())
            elif stripped and not stripped.startswith("-"):
                in_reference = False
    return urls


def parse_nuclei_template(text: str, source: str = "nuclei-template") -> List[CveTriageRecord]:
    """Extract CVE triage records from a nuclei template body (offline).

    Field-annotated references (``id:``, ``cve-id``, ``reference``) are
    preferred for context; any remaining CVE ID is captured as a fallback via
    :func:`extract_cve_references`. URLs under the template's ``reference:``
    block are appended to the record's context so the trusted-source links
    survive triage. No template is executed, downloaded, or run against a
    target — the output is triage metadata only.
    """
    records: Dict[str, CveTriageRecord] = {}
    for match in _NUCLEI_CVE_FIELD_RE.finditer(text):
        cve_id = (match.group(1) or match.group(2)).upper()
        context = text[max(0, match.start() - 80):match.end() + 140].replace("\n", " ")[:280]
        records.setdefault(cve_id, CveTriageRecord(cve_id, source, context))
    for record in extract_cve_references(text, source):
        records.setdefault(record.cve_id, record)
    reference_urls = _template_reference_urls(text)
    if reference_urls:
        for record in records.values():
            missing = [url for url in reference_urls if url not in record.context]
            if missing:
                record.context = (record.context + " | references: "
                                  + ", ".join(missing))[:400]
    return sorted(records.values(), key=lambda record: record.cve_id)


def analyze_nuclei_paths(paths: Iterable[Path]) -> List[CveTriageRecord]:
    """Parse CVE references from nuclei template files under the given paths."""
    cves: Dict[str, CveTriageRecord] = {}
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for record in parse_nuclei_template(text, str(path)):
            cves.setdefault(record.cve_id, record)
    return sorted(cves.values(), key=lambda record: record.cve_id)


# Curated reference CVE data, used only to enrich triage records when the
# user opts in via ``--seed``. Each entry is metadata only (no exploit code,
# no payload, no version probing). Reproductions stayed offline.
CVE_SEED_RECORDS: Sequence[Dict[str, Any]] = (
    {
        "cve_id": "CVE-2026-20266",
        "product": "Splunk AI Toolkit (btool Configuration Helper)",
        "cwe": "CWE-78",
        "severity": "critical",
        "cvss": 9.1,
        "fixed_in": "5.7.4",
        "advisory": "SVD-2026-0614",
        "summary": "OS command injection: btool helper builds command strings "
                    "from dynamic parameters; admin-role user can run "
                    "arbitrary commands on the Splunk host.",
    },
    {
        "cve_id": "CVE-2026-20296",
        "product": "Splunk Enterprise (Deployment Server)",
        "cwe": "CWE-352",
        "severity": "high",
        "cvss": 8.3,
        "fixed_in": "10.4.1, 10.2.5, 10.0.8 (+ earlier releases)",
        "advisory": "SVD-2026-0702",
        "summary": "Cross-site request forgery: a tricked capable user can be "
                    "made to run SPL as the system user.",
    },
    {
        "cve_id": "CVE-2026-20297",
        "product": "Splunk Enterprise (app installation)",
        "cwe": "CWE-22",
        "severity": "high",
        "cvss": 7.2,
        "fixed_in": "10.4.1, 10.2.5, 10.0.8 (+ earlier releases)",
        "advisory": "SVD-2026-0703",
        "summary": "Path traversal during app installation: a privileged role "
                    "can write files outside the app directory.",
    },
    {
        "cve_id": "CVE-2026-20298",
        "product": "Splunk Enterprise (storage/passwords endpoint)",
        "cwe": "CWE-200",
        "severity": "medium",
        "cvss": 5.3,
        "fixed_in": "10.4.1, 10.2.5, 10.0.8 (+ earlier releases)",
        "advisory": "SVD-2026-0704",
        "summary": "Information exposure: the storage/passwords endpoint "
                    "exposes stored credential hashes.",
    },
    {
        "cve_id": "CVE-2026-18051",
        "product": "W3 Total Cache (WordPress plugin, page cache key)",
        "cwe": "CWE-22",
        "severity": "critical",
        "cvss": 10.0,
        "fixed_in": "2.10.5",
        "advisory": "WPScan advisory (secondary source: Daily CyberSecurity report)",
        "summary": "Unauthenticated arbitrary directory/file write and .htaccess "
                    "overwrite via path traversal in the page cache key; "
                    "affects W3 Total Cache before 2.10.5 (CWE-22, CVSS 10.0).",
    },
    {
        "cve_id": "CVE-2026-73570",
        "product": "Zimbra Collaboration (optional zimbra-snmp package)",
        "cwe": "CWE-78",
        "severity": "high",
        "cvss": 8.9,
        "fixed_in": "10.1.20",
        "advisory": "Zimbra Security Advisories / CERT Polska (secondary source: Daily CyberSecurity report)",
        "summary": "Unauthenticated OS command injection in SNMP notification "
                    "handling (swatchdog service) as the zimbra user; requires "
                    "the optional zimbra-snmp package with SNMP notifications "
                    "enabled; reported exploited in the wild (CWE-78, CVSS 8.9).",
    },
    {
        "cve_id": "CVE-2026-70496",
        "product": "Red Hat Advanced Cluster Management (search-v2-operator ClusterRole)",
        "cwe": "CWE-250",
        "severity": "critical",
        "cvss": 9.9,
        "fixed_in": "See Red Hat ACM/Multicluster Engine advisories (August 2026)",
        "advisory": "Red Hat ACM security advisory (secondary source: Daily CyberSecurity report)",
        "summary": "Kubernetes privilege escalation to cluster-admin: the "
                    "search-v2-operator ClusterRole is cluster-admin equivalent "
                    "via impersonate, RBAC write, CSR approve, and ManifestWork "
                    "permissions; a low-privileged user can escalate (CWE-250, "
                    "CVSS 9.9). Not reported exploited in the wild.",
    },
    {
        "cve_id": "CVE-2026-66794",
        "product": "Red Hat Multicluster Engine (cluster-proxy-addon)",
        "cwe": "CWE-918",
        "severity": "high",
        "cvss": 9.3,
        "fixed_in": "See Red Hat Multicluster Engine advisories (August 2026)",
        "advisory": "Red Hat Multicluster Engine security advisory (secondary source: Daily CyberSecurity report)",
        "summary": "Server-side request forgery: the cluster-proxy-addon exposes a "
                    "user-facing route that skips authentication/authorization; "
                    "an unauthenticated attacker can bend URL path segments to "
                    "proxy requests to internal services (CWE-918, CVSS 9.3). "
                    "Not reported exploited in the wild.",
    },
    {
        "cve_id": "CVE-2026-71470",
        "product": "Red Hat Advanced Cluster Management (Search CR editor)",
        "cwe": "CWE-913",
        "severity": "high",
        "cvss": 9.1,
        "fixed_in": "See Red Hat ACM advisories (August 2026)",
        "advisory": "Red Hat ACM security advisory (secondary source: Daily CyberSecurity report)",
        "summary": "Improper control of a dynamically-identified resource: unvalidated "
                    "input in a Custom Resource editor lets an attacker swap the "
                    "container image or mount secrets, escalating to full cluster "
                    "compromise (CWE-913, CVSS 9.1). Not reported exploited in "
                    "the wild.",
    },
    {
        "cve_id": "CVE-2026-47301",
        "product": "Microsoft Configuration Manager (AdminService upload endpoints)",
        "cwe": "CWE-862",
        "severity": "high",
        "cvss": 8.8,
        "fixed_in": "5.0.9135.1031, 5.0.9141.1030, 5.0.9146.1021",
        "advisory": "Microsoft Configuration Manager advisory (secondary source: Daily CyberSecurity report)",
        "summary": "Elevation of privilege: the chunked-upload counterpart of the "
                    "extension-upload endpoint skips the permission check, so an "
                    "authenticated domain user can submit a malicious CAB that "
                    "hijacks SMS_EXECUTIVE via DLL proxying to run as SYSTEM. "
                    "Public PoC exists; first link of a four-link chain (CWE-862, "
                    "CVSS 8.8).",
    },
    {
        "cve_id": "CVE-2026-12394",
        "product": "WordPress MemberGlut plugin (< 1.1.5)",
        "cwe": "CWE-269",
        "severity": "critical",
        "cvss": 9.8,
        "fixed_in": "1.1.5",
        "advisory": "WPScan vulnerability 6b126a3e-30d5-4bed-ba47-33e589ec2852 / nuclei template CVE-2026-12394",
        "summary": "Unauthenticated privilege escalation: front-end registration lacks "
                    "role validation, so an unauthenticated user can register with "
                    "arbitrary roles including administrator (CWE-269, CVSS 9.8). "
                    "Template verified by its author; no in-the-wild exploitation "
                    "reported.",
    },
)


def seed_cve_records(source: str = "bugwolf-cve-seed") -> List[CveTriageRecord]:
    """Curated CVE intake records (offline-only, metadata only).

    These come from a vendor advisory digest the operator is expected to
    confirm against the vendor's official security bulletin before any
    testing. BugWolf does not validate the identifier against any database,
    download exploit code, attempt exploitation, or perform fingerprinting.
    """
    records: List[CveTriageRecord] = []
    for entry in CVE_SEED_RECORDS:
        checks = [
            f"Verify {entry['cve_id']} against {entry['advisory']} on the "
            f"vendor advisory page.",
            f"Confirm the installed {entry['product']} version against the "
            f"fixed-in cut-over ({entry['fixed_in']}).",
            "Use an isolated lab or a vendor-issued fixture; never run "
            "public exploit code on production.",
        ]
        records.append(CveTriageRecord(
            cve_id=entry["cve_id"],
            source=f"{source}:{entry['advisory']}",
            context=entry["summary"],
            severity=entry["severity"],
            cwe=entry["cwe"],
            product=entry["product"],
            fixed_in=entry["fixed_in"],
            summary=entry["summary"],
            required_checks=checks,
        ))
    return records


def identity_audit_plans() -> List[IdentityAuditPlan]:
    common = ["no phishing", "no MFA fatigue/push bombing", "no credential stuffing", "test accounts only"]
    return [
        IdentityAuditPlan("identity-legacy-auth", "legacy_auth", "Audit legacy authentication paths", ["Inventory enabled protocols and conditional-access exclusions.", "Compare each path with the intended MFA policy."], ["Run provider-approved read-only checks with a test account."], common),
        IdentityAuditPlan("identity-recovery", "recovery_assurance", "Audit recovery and factor replacement", ["Map recovery prerequisites, helpdesk verification, and audit events."], ["Use a documented test case with synthetic identity data."], common + ["no social engineering" ]),
        IdentityAuditPlan("identity-federation", "federated_claim_validation", "Audit OAuth/OIDC/SAML trust", ["Review issuer, audience, signature, redirect, and authentication-context configuration."], ["Use signed fixtures or a vendor sandbox."], common + ["no forged production assertions"]),
        IdentityAuditPlan("identity-session", "session_lifecycle", "Audit session and token lifecycle", ["Review TTL, revocation, rotation, logout, and device binding."], ["Use disposable test sessions and synthetic tokens."], common + ["no captured-session replay"]),
    ]


def analyze_paths(paths: Iterable[Path]) -> tuple[List[SecurityHypothesis], List[CveTriageRecord]]:
    hypotheses: List[SecurityHypothesis] = []
    cves: Dict[str, CveTriageRecord] = {}
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        hypotheses.extend(analyze_text(text, str(path)))
        for record in extract_cve_references(text, str(path)):
            cves[record.cve_id] = record
    return hypotheses, sorted(cves.values(), key=lambda record: record.cve_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf offline identity/cloud/CVE analysis")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--nuclei", action="append", default=[],
                        help="Nuclei template files to parse for CVE references")
    parser.add_argument("--seed", action="store_true",
                        help="Include curated CVE seed records (Splunk advisory batch).")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--plans", action="store_true")
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    hypotheses, cves = analyze_paths(Path(path) for path in args.path)
    nuclei_cves = analyze_nuclei_paths(Path(path) for path in args.nuclei)
    merged_cves: Dict[str, CveTriageRecord] = {r.cve_id: r for r in cves}
    for record in nuclei_cves:
        # Seed enrichment wins over generic text for product/cwe/fixed_in.
        existing = merged_cves.get(record.cve_id)
        if existing is not None and (existing.cwe or existing.severity):
            for key in ("cwe", "severity", "product", "fixed_in", "summary"):
                setattr(existing, key, getattr(existing, key) or getattr(record, key))
            merged_cves[record.cve_id] = existing
        else:
            merged_cves.setdefault(record.cve_id, record)
    for record in seed_cve_records() if args.seed else []:
        existing = merged_cves.get(record.cve_id)
        if existing is None:
            merged_cves[record.cve_id] = record
        elif not (existing.cwe and existing.severity and existing.product):
            for key in ("cwe", "severity", "product", "fixed_in", "summary"):
                setattr(existing, key, getattr(existing, key) or getattr(record, key))
            merged_cves[record.cve_id] = existing
    cves = sorted(merged_cves.values(), key=lambda record: record.cve_id)
    for filename, rows in (("security-hypotheses.jsonl", hypotheses), ("cve-triage.jsonl", cves)):
        with (output / filename).open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    if args.plans:
        with (output / "identity-audit-plans.jsonl").open("w", encoding="utf-8") as handle:
            for row in identity_audit_plans():
                handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    manifest = {"schema": "bugwolf-identity-cloud-v1", "hypotheses": len(hypotheses),
                "cve_references": len(cves),
                "cve_seed_included": bool(args.seed),
                "nuclei_templates": len(args.nuclei),
                "execution": "offline_artifacts_only"}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
