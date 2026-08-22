#!/usr/bin/env python3
"""Offline static analysis for high-impact application chains.

This module emits signals and validation/remediation plans only. It never
creates SQLi/OOB payloads, writes files, invokes shells, generates gadget
chains, or contacts external listeners.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


@dataclass
class StaticFinding:
    finding_id: str
    category: str
    title: str
    source: str
    line_number: int
    severity: str
    rationale: str
    evidence_hash: str
    status: str = "static_signal_human_review_required"


@dataclass
class ChainPlan:
    chain_id: str
    title: str
    stages: List[str]
    findings: List[str]
    preconditions: List[str]
    validation_questions: List[str]
    remediation: List[str]
    status: str = "offline_plan_only"


Rule = Tuple[str, str, str, str, str]

RULES: Sequence[Rule] = (
    (r"(?i)(execute|executemany|query)\s*\([^\n]*(\+|%|format\(|f[\"'])", "sqli_input", "SQL query may combine code and input", "high", "Review whether untrusted data reaches a query through concatenation or interpolation."),
    (r"(?i)(into\s+outfile|load_file\s*\(|xp_cmdshell|copy\s*\([^\n]*program)", "db_privileged_primitive", "Database exposes a file or command primitive", "critical", "Database capability can turn an injection or overprivileged account into filesystem or command impact."),
    (r"(?i)(upload(path|_path|dir|_dir)?|destination|parentPathName).{0,100}(request|body|params|query|form)", "path_input", "Client-controlled filesystem destination", "high", "A request-controlled destination needs canonicalization and a fixed-root check."),
    (r"(?i)(path\.join|os\.path\.join|resolve\(|normalize\(|writeFile|write_file|move\(|rename\().{0,160}(request|body|params|query|upload|filename|destination)", "filesystem_write", "Request data reaches a filesystem write path", "high", "A path sink may permit traversal or writes outside an upload root."),
    (r"(?i)(cron|crontab|systemd|scheduled.?task|job.?scheduler|postinstall|entrypoint).{0,120}(write|upload|file|path|content|command)", "file_consumer", "Privileged file-consuming component near a write path", "critical", "A file written into a service-consumed directory can become an execution or configuration boundary."),
    (r"(?i)(ObjectInputStream|readObject\s*\(|pickle\.loads|yaml\.load\s*\(|Marshal\.load|unserialize\s*\()", "deserialization_sink", "Untrusted deserialization sink", "critical", "Serialized input requires a strict type allowlist, integrity boundary, and safe parser configuration."),
    (r"(?i)(commons-collections|velocity-1\.[0-9]|ysoserial|gadget.?chain|ObjectInputFilter)", "deserialization_dependency", "Deserialization-related dependency or control", "high", "Dependency and filter posture must be verified against the actual runtime classpath and configuration."),
    (r"(?i)(setHeader|addHeader|header\s*\().{0,120}(request|query|params|user|input)|%0d%0a|\\r\\n", "header_injection", "Untrusted data may reach a response header", "medium", "Header construction should reject control characters and use structured APIs."),
    (r"(?i)(child_process|exec\s*\(|spawn\s*\(|os\.system|subprocess\.(run|Popen|call)|shell\s*=\s*true).{0,160}(request|body|params|query|user|input)", "command_sink", "Command execution sink near request input", "critical", "Command arguments must use fixed argv arrays and strict allowlists; shell interpretation must be avoided."),
    (r"(?i)(redirect|proxy|cache|location).{0,100}(header|request|input|user)", "header_chain_sink", "Header or redirect signal may reach a downstream trust boundary", "medium", "Assess whether the signal affects cache keys, redirects, proxy routing, or security headers."),
    (r"(?i)(DocumentBuilderFactory|SAXParserFactory|XMLReader|SAXParser|TransformerFactory|SchemaFactory|simplexml_load_string|loadXML|XmlDocument|fromstring|lxml|libxml_disable_entity_loader)", "xxe_sink", "XML parser may resolve external entities", "critical", "An XML parser that processes untrusted documents must disable external entity resolution and DTD processing."),
    (r"(?i)(external.?general.?entities|DOCTYPE|SYSTEM\s+[\"']|ENTITY\s+[\"']|setFeature|accessExternalDTD|resolveEntity|disallow-doctype)", "xxe_entity_config", "External-entity or DOCTYPE handling reference", "high", "External-entity/DTD configuration decides whether an XXE can read local files or reach internal resources."),
    (r"(?i)(config\.php|wp-config|db_credentials|DB_PASSWORD|database\.ini|connection.?string|\.env|credentials)", "credential_config", "Credential or configuration material reference", "high", "A file containing credentials or connection material is a high-value XXE/read target and must stay outside document reach."),
    (r"(?i)(webshell|persistence|scheduled|insert.*shell|write.*shell|backdoor)", "persistence_reference", "Persistence or shell reference near a write/execute boundary", "critical", "Persistence references near a file-write or credential boundary can complete an XXE-to-compromise chain."),
    # Cross-script database persistence (TaintRadar): an INSERT/UPDATE in one
    # script and a SELECT in another share only the database; standard CPGs
    # lose the taint chain at the persistence boundary.
    (r"(?i)(INSERT\s+INTO|UPDATE\s+\w+\s+SET)", "db_write", "Database write operation", "high", "A write that persists attacker-influenced data may resurface later in a different request or script."),
    (r"(?i)(SELECT\s+.+\s+FROM)", "db_read", "Database read operation", "info", "A read of persistent data can complete a stored attack chain if it renders unencoded values."),
    (r"(?i)(echo\s+|print\s+|<\?=|render|template|twig)", "output_render", "Output rendering sink", "high", "Unencoded rendering of persistent data is the sink that completes a stored XSS chain."),
    (r"(?i)(header\s*\(.*Location|redirect|wp_redirect)", "redirect_sink", "Redirect sink", "medium", "Persistent data reaching a redirect target can complete an open-redirect or header chain."),
    # Crypto-API misuse patterns (CauSec — 2608.18876): 57 crypto assumptions
    # catalogued across SAST tools; these are the most actionable subset.
    (r"(?i)(ECBMode|Cipher\.getInstance.*ECB|AES/ECB)", "crypto_ecb_mode", "ECB cipher mode detected", "critical", "ECB mode leaks plaintext structure; use GCM or CBC with authentication."),
    (r"(?i)(md5|sha1)\s*\(", "crypto_weak_hash", "Weak hash (MD5/SHA-1)", "high", "MD5 and SHA-1 are broken; use SHA-256 or SHA-3."),
    (r"(?i)(DES|3DES|RC4|RC2)\b", "crypto_weak_cipher", "Weak or deprecated cipher", "critical", "DES/3DES/RC4 are broken; use AES-256-GCM."),
    (r"(?i)(random\s*\(\)|Math\.random|rand\s*\(\)|mt_rand)", "crypto_weak_random", "Non-cryptographic RNG", "high", "Non-cryptographic RNG produces predictable values; use SecureRandom."),
    (r"(?i)(hardcoded.*key|key\s*=\s*\"[^\"]{8,}\"|secret\s*=\s*\"[^\"]{8,}\"|password\s*=\s*\"[^\"]{8,}\")", "crypto_hardcoded_key", "Hardcoded key or secret", "critical", "Hardcoded keys are extractable; use a key management service."),
    (r"(?i)(certificate.*verify.*false|verify_peer\s*=\s*false|verify\s*=\s*False|check_hostname\s*=\s*False)", "crypto_tls_bypass", "TLS verification disabled", "critical", "Disabling TLS verification enables MITM; always verify in production."),
    (r"(?i)(predictable.*IV|fixed.*IV|IV\s*=\s*0|IV\s*=\s*\"\")", "crypto_predictable_iv", "Predictable or fixed IV", "critical", "A fixed IV breaks authenticated encryption; generate fresh random IV per encryption."),
)


def _finding_id(source: str, line: int, category: str, text: str) -> tuple[str, str]:
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return hashlib.sha256(f"{source}:{line}:{category}:{digest}".encode()).hexdigest()[:16], digest


def analyze_text(text: str, source: str = "artifact") -> List[StaticFinding]:
    findings: List[StaticFinding] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, category, title, severity, rationale in RULES:
            if re.search(pattern, line):
                finding_id, digest = _finding_id(source, line_number, category, line)
                findings.append(StaticFinding(finding_id, category, title, source,
                                              line_number, severity, rationale, digest))
    return findings


def build_chain_plans(findings: Iterable[StaticFinding]) -> List[ChainPlan]:
    items = list(findings)
    by_category = {}
    for item in items:
        by_category.setdefault(item.category, []).append(item)
    plans: List[ChainPlan] = []

    if by_category.get("sqli_input") and by_category.get("db_privileged_primitive"):
        selected = by_category["sqli_input"] + by_category["db_privileged_primitive"]
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("sqli-db-os".encode()).hexdigest()[:12],
            "SQL input to database privilege boundary",
            ["untrusted input", "query construction", "database capability", "potential filesystem/command impact"],
            [item.finding_id for item in selected],
            ["Input is reachable from an authorized test fixture", "Database account has the flagged capability", "No safer sandbox proof is available"],
            ["Can the signal be reproduced without data extraction?", "Is the database account least-privileged?", "Are file-write/command features disabled or restricted?", "Can impact be bounded to a disposable lab?"],
            ["Use parameterized queries", "Remove FILE/command privileges from application accounts", "Restrict secure file paths and disable unused execution features", "Use separate database identities for read/write workloads"],
        ))

    if by_category.get("path_input") and by_category.get("filesystem_write"):
        selected = by_category["path_input"] + by_category["filesystem_write"]
        if by_category.get("file_consumer"):
            selected += by_category["file_consumer"]
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("upload-path-consumer".encode()).hexdigest()[:12],
            "Upload/path input to file-consuming component",
            ["request-controlled destination", "filesystem write", "service-consumed directory", "possible execution/configuration effect"],
            [item.finding_id for item in selected],
            ["Canonical path remains within a dedicated non-executable root", "Consumer is in scope and reproducible in a lab", "Only benign synthetic fixtures are used"],
            ["Is the canonical destination beneath the fixed upload root?", "Does the service consume the file by content or directory?", "Can the check be completed without writing to system paths?", "Is the service running with least privilege?"],
            ["Reject absolute paths, traversal, encoded separators, and symlink escapes", "Store uploads outside application/system consumer directories", "Run the service unprivileged", "Return uniform path errors and log details internally"],
        ))

    if by_category.get("deserialization_sink"):
        selected = by_category["deserialization_sink"] + by_category.get("deserialization_dependency", [])
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("deserialization".encode()).hexdigest()[:12],
            "Untrusted deserialization and runtime dependency boundary",
            ["untrusted serialized input", "deserialization sink", "runtime classpath/gadget risk", "possible code execution"],
            [item.finding_id for item in selected],
            ["Input origin and integrity are established", "Affected version and runtime dependencies are confirmed", "Testing occurs only in an isolated lab"],
            ["Can the sink be removed or replaced with a data-only format?", "Is an allowlist/filter enforced before object construction?", "Which dependencies are actually loaded?", "Is the process least-privileged?"],
            ["Use safe data-only formats", "Apply strict class/type allowlists", "Remove obsolete gadget-bearing dependencies", "Patch affected libraries and isolate the service"],
        ))

    if by_category.get("header_injection"):
        selected = by_category["header_injection"] + by_category.get("header_chain_sink", [])
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("header-chain".encode()).hexdigest()[:12],
            "Header input to downstream trust boundary",
            ["untrusted header value", "response/header construction", "redirect/cache/proxy consumer"],
            [item.finding_id for item in selected],
            ["Only harmless markers are used", "No cache poisoning or victim interaction is attempted"],
            ["Is control-character input rejected?", "Does the value affect routing, cache keys, redirects, or security policy?", "Can a test-only response prove impact without shared caches?"],
            ["Use structured header APIs", "Reject CR/LF and control characters", "Normalize and validate redirects and proxy destinations", "Separate security-sensitive headers from user data"],
        ))

    # Cross-script database persistence chain — TaintRadar technique.
    # When the same source has a db_write AND a db_read AND an output_render
    # signal, the code may have a stored XSS or 2nd-order injection chain that
    # standard single-script taint analyzers cannot detect.
    if by_category.get("db_write") and by_category.get("db_read") and by_category.get("output_render"):
        selected = (by_category["db_write"] + by_category["db_read"]
                    + by_category["output_render"])
        if by_category.get("redirect_sink"):
            selected += by_category["redirect_sink"]
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("db-persistence-render".encode()).hexdigest()[:12],
            "Database persistence to rendered output (stored XSS / 2nd-order injection)",
            ["user input", "database INSERT/UPDATE", "database SELECT",
             "output rendering without encoding", "stored attack delivered"],
            [item.finding_id for item in selected],
            ["Write and read paths share the same table and unsafe columns",
             "A benign-and-owned test fixture is available",
             "No production data is modified or exposed"],
            ["Do INSERT and SELECT share column(s) of unsafe type (VARCHAR/TEXT)?",
             "Is the rendered output encoded per context (HTML, JS, URL, attribute)?",
             "Can the same stored value reach an alternative render path (JSON, CSV, RSS)?",
             "Is there a CSP that would block inline script execution?"],
            ["Apply context-appropriate output encoding at every render point",
             "Use parameterized queries for all database access",
             "Add Content-Security-Policy headers restricting inline scripts",
             "Audit all render paths, not just the primary template"],
        ))

    # Crypto-API misuse chain (CauSec — 2608.18876)
    crypto_categories = {"crypto_ecb_mode", "crypto_weak_hash", "crypto_weak_cipher",
                         "crypto_weak_random", "crypto_hardcoded_key",
                         "crypto_tls_bypass", "crypto_predictable_iv"}
    if crypto_categories & set(by_category.keys()):
        selected = []
        for category in sorted(crypto_categories & set(by_category.keys())):
            selected += by_category[category]
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("crypto-misuse".encode()).hexdigest()[:12],
            "Crypto-API misuse chain",
            ["weak or misconfigured cryptographic primitive",
             "predictable or hardcoded key material",
             "disabled transport security",
             "potential credential extraction or data exposure"],
            [item.finding_id for item in selected],
            ["Source code or artifact is under authorized review",
             "No key material is extracted or tested",
             "Only benign synthetic fixtures are used"],
            ["Is the cryptographic primitive appropriate for the security requirement?",
             "Are keys managed through a KMS or hardware security module?",
             "Is TLS certificate and hostname verification enforced?",
             "Are IVs and salts freshly generated per operation?"],
            ["Upgrade to authenticated encryption (AES-256-GCM, ChaCha20-Poly1305)",
             "Use a key management service; never hardcode keys",
             "Enforce certificate verification and hostname checking",
             "Generate fresh random IVs and salts per operation"],
        ))

    if by_category.get("command_sink"):
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("command-sink".encode()).hexdigest()[:12],
            "Input to command execution boundary",
            ["untrusted input", "command sink", "process execution"],
            [item.finding_id for item in by_category["command_sink"]],
            ["Static reachability is confirmed", "A local fixture can demonstrate argument separation without execution"],
            ["Does input reach an argv element or shell parser?", "Can the code use a fixed executable and argument allowlist?", "Is command execution required for the feature?"],
            ["Avoid shell=True and string commands", "Use fixed argv arrays", "Allowlist operations and arguments", "Run workers with minimal filesystem/network permissions"],
        ))

    if by_category.get("xxe_sink"):
        selected = by_category["xxe_sink"]
        if by_category.get("xxe_entity_config"):
            selected += by_category["xxe_entity_config"]
        if by_category.get("credential_config"):
            selected += by_category["credential_config"]
        if by_category.get("persistence_reference"):
            selected += by_category["persistence_reference"]
        plans.append(ChainPlan(
            "chain-" + hashlib.sha256("xxe-read-cred-persist".encode()).hexdigest()[:12],
            "XXE file-read to credential and persistence boundary",
            ["unvalidated XML parser", "external entity / DTD resolution",
             "local file read (config/secrets)", "credential extraction",
             "database authentication / persistence"],
            [item.finding_id for item in selected],
            ["The parser is reachable from an authorized test fixture", "Only benign synthetic XML documents are used", "No real credentials or system files are read"],
            ["Can external entity and DTD processing be disabled in configuration?", "Are the referenced files outside the parser's reach or permissions?", "Does the read reach a documented secret/config path or only a synthetic fixture?", "Could the extracted material authenticate elsewhere (DB, admin, persistence)?"],
            ["Disable external entities and DTDs", "Use a hardened parser or data-only format", "Keep secrets outside document-reachable paths", "Separate read accounts from write/execution accounts"],
        ))
    return plans


def analyze_paths(paths: Iterable[Path]) -> tuple[List[StaticFinding], List[ChainPlan]]:
    findings: List[StaticFinding] = []
    for path in paths:
        if path.is_file():
            findings.extend(analyze_text(path.read_text(encoding="utf-8", errors="replace"), str(path)))
    return findings, build_chain_plans(findings)


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf offline application chain analyzer")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    findings, chains = analyze_paths(Path(path) for path in args.path)
    for name, rows in (("static-findings.jsonl", findings), ("chain-plans.jsonl", chains)):
        with (output / name).open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    manifest = {"schema": "bugwolf-chain-analyzer-v1", "findings": len(findings), "chains": len(chains), "execution": "offline_static_only"}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
