#!/usr/bin/env python3
"""Offline adapters derived from the supplied 2026 security papers.

This module turns transferable research ideas into bounded BugWolf artifacts:
skill-chain composition risk, temporal provenance bottlenecks, CTI-to-Sigma
plans, contamination-aware binary-RE tasks, endpoint-specific authentication
anomaly triage, failure-trace defense candidates, passive HTTPS metadata privacy
assessment, and Agent control-plane gap analysis.

It intentionally does not execute commands, contact targets, generate exploit
payloads, evade scanners, decode binaries, or mutate executable source. Every
output is a plan, signal, or quarantined candidate requiring the existing
scope, execution, evidence, and human-review gates.

Usage:
  python3 tools/paper_intel.py --output-dir research/T/paper-intelligence --json
  python3 tools/paper_intel.py --agent-control-plane-file .private/agent-inventory.json --map-output state/sessions/T/maps/paper-intelligence.md --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


SCHEMA = "bugwolf-paper-intelligence/v1"
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 20_000_000

PAPER_CATALOG: Dict[str, Dict[str, str]] = {
    "2608.19938": {
        "title": "From Noise to Signal: Improving Security Log Anomaly Detection Using LLMs with Endpoint-Specific Logs",
        "objective": "Detect normal, borderline, and anomalous authentication behavior using endpoint-specific context.",
        "techniques": "curated testbed, severity labels, instruction-based classification, borderline-case evaluation, structured-output validity, latency comparison",
        "bugwolf_fit": "endpoint-specific auth baselines and uncertainty-aware analyst triage",
        "limitation": "reported metrics are testbed/model dependent; use as a planning method, not a universal detector",
    },
    "2608.19750": {
        "title": "TGL-APT: Temporal Graph Learning with Graph Distillation for Efficient APT Investigation",
        "objective": "Investigate sparse multi-stage activity in large temporal provenance graphs.",
        "techniques": "information-bottleneck nodes, graph distillation, adaptive temporal relevance, cross-spatiotemporal fingerprint alignment, causal expansion, stage characterization",
        "bugwolf_fit": "target-local provenance compression and ranked chain continuation",
        "limitation": "DARPA-style provenance assumptions do not directly describe every web/API workflow",
    },
    "2608.19190": {
        "title": "SiNMULI: Novel Signed Network Approach for Malicious URL Identification",
        "objective": "Classify harmful URLs using signed backlink relationships and balance-theoretic inference.",
        "techniques": "signed URL graph, edge-sign propagation, majority inference, interpretable graph classification, obfuscation resilience",
        "bugwolf_fit": "passive URL relationship triage and external-link reputation hypotheses",
        "limitation": "graph labels and backlink quality can bias results; never treat a score as proof",
    },
    "2608.19011": {
        "title": "From Threat Intelligence to Detection: Knowledge-driven Enrichment and Template-based Rule Grounding for Automated Sigma Rule Generation",
        "objective": "Convert incomplete CTI into relevant, validated, environment-aware Sigma rule plans.",
        "techniques": "knowledge enrichment, template grounding, rule-repository matching, iterative judge/validation loop, ATT&CK coverage",
        "bugwolf_fit": "offline CTI enrichment and detection-rule planning from findings/research",
        "limitation": "generated rules still need environment validation and false-positive review",
    },
    "2608.19052": {
        "title": "Malformer: A Multi-Modal Malware Detector Using Transformers",
        "objective": "Improve malware classification by fusing text, image, graph, and audio representations.",
        "techniques": "quadrimodal representation, transformer encoders, vision/audio encoders, adaptive loss weighting, modality ablation",
        "bugwolf_fit": "multi-view binary-artifact evidence coverage and modality-gap reporting",
        "limitation": "classification performance does not establish exploitability or malware attribution",
    },
    "2608.18686": {
        "title": "Improving LLM-Based SSH Honeypots Through Prompting and Fine-Tuning",
        "objective": "Evaluate and improve local LLM shell-emulation fidelity without cloud-model dependence.",
        "techniques": "prompt structure, supervised adaptation, expanded log datasets, single/fresh-session unit tests, malformed-state checks",
        "bugwolf_fit": "safe lab-emulation test plans and evaluator criteria, never stealth improvement against real users",
        "limitation": "shell realism can be dual-use; BugWolf only plans isolated defensive testbeds",
    },
    "2608.15012": {
        "title": "SysEvolve: An AI-native, safe, autonomous adversarial attack-defense co-evolutionary system",
        "objective": "Create safe multi-host ranges and co-evolve bounded attack and defense agents.",
        "techniques": "range construction, efficient attack schemes, real-time interpretable defense, post-access bottleneck analysis, environmental-interference testing",
        "bugwolf_fit": "lab-only scenario queues, post-access continuation metrics, and defense feedback",
        "limitation": "reported autonomous attack success must not be transplanted into uncontrolled targets",
    },
    "2608.08468": {
        "title": "SkillsMetric: Mapping the Detection Boundary of Static Analysis for Malicious Agent Skills",
        "objective": "Measure static skill-analysis dimensions and identify blind spots.",
        "techniques": "pattern density, statistical anomaly, dataflow taint, import anomaly, capability mismatch, semantic-review boundary",
        "bugwolf_fit": "static skill-chain scanner and defense-in-depth gate",
        "limitation": "static analysis misses common destructive commands and much natural-language manipulation",
    },
    "2608.09732": {
        "title": "ColluSkill: Adversarial Cross-Skill Composition for Evading Agent Skill Scanners",
        "objective": "Study harmful workflows that emerge only from multiple locally plausible skills.",
        "techniques": "cross-skill dependencies, artifact flows, capability composition, execution handoffs, chain-level scanning",
        "bugwolf_fit": "context-aware installed-skill composition analysis",
        "limitation": "scanner findings are risk signals; semantic review and runtime isolation remain necessary",
    },
    "2608.11469": {
        "title": "The Next Challenge for Agentic Cybersecurity: A Realistic, Contamination-Free Reverse Engineering Benchmark",
        "objective": "Evaluate agentic reverse engineering on unseen, realistic, anti-analysis-protected binaries.",
        "techniques": "contamination control, realistic scale, anti-analysis variants, deterministic grading, static/dynamic task separation",
        "bugwolf_fit": "binary-analysis task planner with contamination and evidence controls",
        "limitation": "benchmark scores do not imply correctness on an arbitrary proprietary binary",
    },
    "2608.11802": {
        "title": "Towards Model-based Run-time Cybersecurity: On Control-Flow Anomaly Detection, Attack Identification, and Hardware Monitoring",
        "objective": "Improve attack diagnosis by corroborating software control-flow observations with independent hardware monitoring.",
        "techniques": "model-based runtime monitoring, attack trees, camouflage resistance, independent observation, diagnosis refinement",
        "bugwolf_fit": "multi-source evidence corroboration and attack-tree confidence updates",
        "limitation": "BugWolf cannot provide hardware telemetry; supplied artifacts remain analyst-reviewed evidence",
    },
    "2608.12977": {
        "title": "Beyond Handcrafted Security: Towards Self-Evolving Defense for LLM Agents",
        "objective": "Evolve runtime defense interventions from observed failure traces while preserving benign utility.",
        "techniques": "harness-level intervention taxonomy, failure-trace feedback, candidate evolution, utility/security evaluation",
        "bugwolf_fit": "quarantined defense candidates and regression-driven contract improvement",
        "limitation": "automatic artifact evolution can introduce unsafe changes; BugWolf requires review and never self-modifies source",
    },
    "2608.19568": {
        "title": "DraftFM: A FoundationModel for Day-Zero Drafting in Magic: The Gathering",
        "objective": "Rank unseen candidates before outcome data exists by using frozen public-record features and a sealed forecast.",
        "techniques": "cold-start discrete choice, identity-independent feature representation, withheld-set evaluation, cryptographic forecast provenance",
        "bugwolf_fit": "deterministic cold-start ranking of unseen vulnerability hypotheses and sealed prioritization manifests",
        "limitation": "forecast agreement is not proof; rankings require later evidence and outcome validation",
    },
    "2605.03138": {
        "title": "Zero Day Attacks: Novel Behaviour or Novel Vulnerability?",
        "objective": "Distinguish real vulnerability-centric zero-day claims from anomaly or novel-behavior detection claims.",
        "techniques": "incident-derived taxonomy, vulnerability-centric assessment, behavior-versus-vulnerability distinction, cautious ML claim interpretation",
        "bugwolf_fit": "zero-day claim triage that blocks behavior-only overclaiming and prioritizes vulnerability evidence",
        "limitation": "incident datasets and taxonomy coverage are incomplete; classification does not establish exploitability or novelty",
    },
    "star-website-fingerprinting": {
        "title": "STAR: Semantic-Traffic Alignment and Retrieval for Zero-Shot HTTPS Website Fingerprinting",
        "objective": "Retrieve a likely website profile from encrypted traffic metadata without requiring target traffic during profile enrollment.",
        "techniques": "semantic-traffic alignment, request/response/protocol anchors, open-world retrieval, unknown rejection, paired structural augmentation",
        "bugwolf_fit": "passive privacy-risk assessment over operator-supplied flow metadata and website logic profiles",
        "limitation": "the method is environment, browser, network, and traffic-condition dependent; BugWolf never captures or attributes unrelated user traffic",
    },
    "agent-memory-reasoning-survey": {
        "title": "AI Agent Memory, Reasoning, and Recursive Self-Improvement Survey",
        "objective": "Analyze memory control, harness reliability, verifier strength, and bounded self-improvement failure modes.",
        "techniques": "adaptive memory operations, temporal validity, failure taxonomy, verifier tiers, independent honesty channels, harness-as-environment evaluation",
        "bugwolf_fit": "time-aware memory provenance, failure-to-regression queues, independent evidence, and bounded defense evolution",
        "limitation": "survey and vendor reports do not establish a universal architecture or authorize autonomous self-modification",
    },
    "agent-control-plane-frameworks": {
        "title": "OWASP, Microsoft, ATR, and NIST Agent Security Control-Plane Synthesis",
        "objective": "Connect agent identity, data governance, runtime controls, detection, response, and policy feedback.",
        "techniques": "risk taxonomy, policy enforcement, zero-trust identity, sandboxing, threat rules, SOC linkage, governance functions",
        "bugwolf_fit": "vendor-neutral control-plane gap audit over supplied inventories and configurations",
        "limitation": "framework mappings are assessment aids, not proof of vendor deployment, compliance, or exploitability",
    },
    "2607.16456": {
        "title": "TaintRadar: Semantic-Aware Taint-Style Vulnerability Detection via Augmented Code Property Graphs",
        "objective": "Improve static taint analysis precision via three semantic CPG augmentation layers: vulnerability-typed sanitization, database-aware persistence propagation, and object-aware reaching definitions.",
        "techniques": "vulnerability-typed sanitization lattice, DB-schema-aware cross-script taint edges, object-field reaching-definition analysis, backward-traversal sink discovery, CVE-matching NLP",
        "bugwolf_fit": "per-vuln-class sanitization hypothesis tracking, cross-script DB-persistence chain rules, offline CVE-candidate matching",
        "limitation": "PHP-only prototype requires source code and DB schema access; CPG construction dependency limits direct portability; under review",
    },
    "2608.19680": {
        "title": "Frequency-Aware Continual Learning for Smart Contract Vulnerability Detection with LLMs",
        "objective": "Address catastrophic forgetting and adapter consolidation for sequentially arriving smart contract vulnerability categories using FA-LoRA, Forget-Aware Replay, and Anchor-Protected Progressive Merging.",
        "techniques": "FA-LoRA (Fourier-domain low-rank adaptation with per-frequency importance gates), Forget-Aware Replay (loss-dynamics forgetting-risk estimation), APPM (anchor-protected weighted merging with frequency-domain gate competition)",
        "bugwolf_fit": "smart contract vulnerability model adaptation strategy documentation; catalog-only (requires LLM access)",
        "limitation": "requires LLM fine-tuning access and continual-learning infrastructure; evaluated on DIVE dataset only",
    },
    "2608.19674": {
        "title": "Escaping the Quicksand: A Call to Arms",
        "objective": "Advocate incrementally co-developing executable-as-test-oracle partial specifications alongside prose descriptions, code, and tests to provide more discriminating feedback loops for both AI and human development.",
        "techniques": "executable partial specifications, property-based testing oracles, specification-testing continuum, semantics infrastructure co-development",
        "bugwolf_fit": "specification-first validation plans and executable-oracle invariant templates for methodology playbook",
        "limitation": "position paper without benchmarks; semantics infrastructure is not yet built for most languages",
    },
    "2608.19088": {
        "title": "Detecting Backdoors in Object Detection via Pre-NMS Prediction Distribution Shift (DistScan)",
        "objective": "Detect model backdoors by comparing pre-NMS class-prediction distribution against training class frequencies on clean inputs, requiring no weight access or trigger knowledge.",
        "techniques": "pre-NMS distribution shift, class-frequency baseline, zero-trigger detection, no model-access requirement",
        "bugwolf_fit": "output distribution integrity checks for LLM/agent outputs and model-supply-chain validation planning",
        "limitation": "CV-specific demonstration; LLM/agent output distribution shifts have not been validated with this method",
    },
    "2608.18976": {
        "title": "Catastrophic Learning: A New Attack Vector on Continual Learning Networks",
        "objective": "Identify learning blockers that attack plasticity in continual learning systems, plus 6 attack strategies combining attraction/repulsion and coincident/preceding variants.",
        "techniques": "learning blocker taxonomy, attraction/repulsion feature-space manipulation, coincident/preceding temporal attack variants, 4480-simulation evaluation",
        "bugwolf_fit": "adaptive-learning poisoning risk documentation and replay-data integrity validation planning",
        "limitation": "requires continual-learning architecture access; BugWolf's adaptive_learning.py is human-reviewed append-only, not a continual-learning system",
    },
    "2608.18876": {
        "title": "CauSec: Unboxing the Causal Drivers of Static Vulnerability Analysis Performance",
        "objective": "Formalize SAST tool assumptions as causal models and test whether design sacrifices actually produce expected performance gains.",
        "techniques": "causal assumption modeling, assumption-driven effect estimation, 57 crypto-API misuse assumptions catalogued, assumption validation framework",
        "bugwolf_fit": "crypto-API misuse detection rules in chain_analyzer.py and self-assumption audit methodology",
        "limitation": "evaluated only on crypto-API misuse SAST tools; generalization to broader vulnerability classes is untested",
    },
    "2608.18095": {
        "title": "Backdoor Learning in Language Models and Vision-Language Models",
        "objective": "Comprehensive PhD dissertation analyzing backdoor attack detection, design, and defense for NLP and VLM systems, plus efficient multimodal clinical representation.",
        "techniques": "backdoor taxonomy for NLP/VLMs, trigger detection, backdoor design space, defense evaluation",
        "bugwolf_fit": "LLM supply-chain backdoor signal patterns and agent trustworthiness checklist",
        "limitation": "PhD dissertation scope limits controlled evaluation to known backdoor types; production deployment may involve novel triggers",
    },
    "2608.16970": {
        "title": "Probing the Prefill: Detecting Code Vulnerabilities via Latent Activations",
        "objective": "Test whether frozen LLM internal activations (prefill token representations) carry vulnerability signals about arbitrary code without fine-tuning.",
        "techniques": "last-prefill-token activation probing, MLP probe training, cross-model and cross-benchmark evaluation, sub-0.2% parameter probes",
        "bugwolf_fit": "motivation for lightweight model-native code review signals; activated-probe planning only (BugWolf does not access LLM weights)",
        "limitation": "requires direct model-weight access; probes trail SOTA on harder benchmarks; BugWolf cannot probe activations",
    },
    "2608.16187": {
        "title": "Securing AI-Generated Code: A Just-in-Time Vulnerability Detection and Remediation Pipeline",
        "objective": "Multi-stage pipeline: generate code, scan with CodeQL+Bandit+LLM validator, enrich with MITRE ATT&CK/CWE/Python best practices, fix, and re-scan across 4 Claude models.",
        "techniques": "parallel static+LLM validation, ATT&CK/CWE enrichment, fix-verify loop, dual-pipeline comparison, verdict consistency tracking",
        "bugwolf_fit": "ATT&CK/CWE enrichment adapter for findings, fix-verify loop integration in post-finding trigger",
        "limitation": "Python-only evaluation with Claude models; remediation introduces new vulnerabilities in 15-22% of cases",
    },
    "2608.15184": {
        "title": "Pre-Model Representation Failures in GNN-Based Smart Contract Vulnerability Detection",
        "objective": "Identify four concrete representation-layer failures in GNN contract detectors: identical graphs for different contracts, hardcoded variable whitelist gaps, missing call-node isolation, and direct misclassification.",
        "techniques": "graph-deduplication test, variable-whitelist audit, C-node completeness check, controlled misclassification reproduction",
        "bugwolf_fit": "contract representation validation checklist and completeness audit for contract_discovery.py",
        "limitation": "evaluated on one GNN detector; prevalence in real-world contract populations is an open question",
    },
    "2608.15151": {
        "title": "SAEFUZZ: Smart Contract Vulnerability Detection through Statically Guided Evolutionary Fuzzing",
        "objective": "Combine EVM bytecode CFG extraction with coverage-guided evolutionary fuzzing and 5 dedicated runtime oracles for reentrancy, overflow, block-state, delegatecall, and frozen Ether.",
        "techniques": "bytecode CFG extraction, function-selector recovery, storage-dependency ordering, directed evolutionary seeding, 5 runtime vulnerability oracles",
        "bugwolf_fit": "5 contract vulnerability oracle templates and storage-dependency function ordering for contract_discovery.py",
        "limitation": "Ethereum-only; Solana/Move/TRON require different oracles; 81.82% recall leaves detection gaps",
    },
    "2608.14533": {
        "title": "Finding Vulnerabilities via LLM-Augmented Semantics-Aware Type-Checking (SETYPE)",
        "objective": "Use LLMs to derive a semantics-aware type system from variable/function name meanings, where type-checking failures indicate vulnerabilities; 87% precision, 15 potential zero-days, 9 confirmed.",
        "techniques": "semantic type inference from natural-language symbol meanings, LLM-powered type checking, Python web application evaluation, developer-confirmed zero-days",
        "bugwolf_fit": "semantic-name vulnerability inference and type-mismatch signal planning for code review",
        "limitation": "Python-only evaluation; LLM-based type inference may produce inconsistent results across models or naming conventions",
    },
}


@dataclass
class SkillProfile:
    skill_id: str
    path: str
    file_count: int
    byte_count: int
    file_hash: str
    capabilities: List[str]
    imports: List[str]
    taint_sources: List[str]
    taint_sinks: List[str]
    prompt_signals: List[str]
    anomalies: List[str]
    status: str = "static_analysis_review_required"


@dataclass
class SkillChainRisk:
    chain_id: str
    skills: List[str]
    capabilities: List[str]
    artifact_flow: List[str]
    rationale: str
    severity: str
    status: str = "chain_review_required"
    automatic_execution: bool = False


@dataclass
class ProvenanceNode:
    node_id: str
    label: str
    event_count: int
    in_degree: int
    out_degree: int
    temporal_span: str
    relevance_score: float
    suspicious: bool = False


@dataclass
class AuthAnomaly:
    anomaly_id: str
    endpoint: str
    identity: str
    observed_count: int
    baseline_count: int
    deviation: float
    categories: List[str]
    rationale: str
    status: str = "analyst_review_required"


@dataclass
class DefenseCandidate:
    candidate_id: str
    failure_class: str
    intervention: str
    evidence_hash: str
    regression_tests: List[str]
    status: str = "quarantined_candidate"
    auto_applied: bool = False


def _hash(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()


def _clean(value: Any, limit: int = 300) -> str:
    return " ".join(str(value or "").split())[:limit]


def _safe_id(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", _clean(value, 120)).strip("-") or "unknown"


def _severity(value: Any) -> str:
    value = str(value or "medium").lower()
    return value if value in {"critical", "high", "medium", "low", "info"} else "medium"


def _read_skill_file(path: Path) -> Tuple[str, str]:
    data = path.read_bytes()[:MAX_FILE_BYTES]
    return data.decode("utf-8", errors="replace"), hashlib.sha256(data).hexdigest()


_CAPABILITY_PATTERNS: Sequence[Tuple[str, str, str]] = (
    (r"(?i)(urllib|requests\.|httpx\.|fetch\(|curl\s|wget\s|socket\.)", "network", "network import or transport"),
    (r"(?i)(subprocess|os\.system|shell\s*=\s*true|exec\(|eval\()", "process", "process or interpreter capability"),
    (r"(?i)(open\([^\n]*(?:['\"]w|['\"]a)|write_text\(|write_bytes\(|unlink\(|rmtree\()", "filesystem_write", "filesystem mutation capability"),
    (r"(?i)(os\.environ|/etc/passwd|\.ssh/|secret|token|password|authorization:)", "secret_access", "credential or secret reference"),
    (r"(?i)(stdin|user_input|request\.body|conversation|retrieved|document|artifact\s+input)", "untrusted_input", "untrusted input source"),
    (r"(?i)(stdout|jsonl|artifact|write_text|handoff|output_file|result\.json)", "artifact_output", "artifact production or handoff"),
    (r"(?i)(ignore\s+(?:all\s+)?previous|system\s+message|developer\s+message|override\s+instructions|you\s+are\s+now)", "prompt_control", "instruction or context manipulation signal"),
    (r"(?i)(upload|POST\s|send\s+to|exfil|webhook|base64.{0,30}(?:http|send))", "external_transfer", "possible external data transfer"),
)


def _skill_units(root: Path) -> List[Path]:
    children = sorted(path for path in root.iterdir() if path.is_dir() and not path.name.startswith("."))
    return children or [root]


def scan_skill_chain(root: str | Path, *, max_files: int = 512) -> Dict[str, Any]:
    """Statically score a package and cross-package capability composition."""
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise ValueError(f"skill root is not a directory: {base}")
    profiles: List[SkillProfile] = []
    total_bytes = 0
    for unit in _skill_units(base):
        files = [path for path in sorted(unit.rglob("*"))
                 if path.is_file() and not path.is_symlink()][:max_files]
        capabilities: set[str] = set()
        imports: set[str] = set()
        taint_sources: set[str] = set()
        taint_sinks: set[str] = set()
        prompt_signals: set[str] = set()
        anomalies: set[str] = set()
        hashes: List[str] = []
        unit_bytes = 0
        for path in files:
            if total_bytes >= MAX_TOTAL_BYTES:
                anomalies.add("scan_total_byte_cap_reached")
                break
            text, digest = _read_skill_file(path)
            size = min(path.stat().st_size, MAX_FILE_BYTES)
            total_bytes += size
            unit_bytes += size
            hashes.append(digest)
            for pattern, capability, reason in _CAPABILITY_PATTERNS:
                if re.search(pattern, text):
                    capabilities.add(capability)
                    if capability == "untrusted_input":
                        taint_sources.add(f"{path.name}:{reason}")
                    elif capability in {"network", "process", "filesystem_write", "external_transfer"}:
                        taint_sinks.add(f"{path.name}:{capability}")
                    elif capability == "prompt_control":
                        prompt_signals.add(f"{path.name}:{reason}")
            if re.search(r"(?i)(import\s+[A-Za-z_][\w.]*|from\s+[A-Za-z_][\w.]*\s+import|require\(['\"])", text):
                imports.add(path.name)
            if re.search(r"(?i)(ignore\s+(?:all\s+)?previous|exfil|delete_database|rm\s+-rf|format\s+c:)", text):
                anomalies.add(f"high-risk-language:{path.name}")
        profile = SkillProfile(
            skill_id=_safe_id(unit.name),
            path=str(unit.relative_to(base)) if unit != base else ".",
            file_count=len(files), byte_count=unit_bytes,
            file_hash=_hash("|".join(hashes)), capabilities=sorted(capabilities),
            imports=sorted(imports), taint_sources=sorted(taint_sources),
            taint_sinks=sorted(taint_sinks), prompt_signals=sorted(prompt_signals),
            anomalies=sorted(anomalies),
        )
        profiles.append(profile)

    risks: List[SkillChainRisk] = []
    for left in profiles:
        for right in profiles:
            if left.skill_id >= right.skill_id:
                continue
            combined = set(left.capabilities) | set(right.capabilities)
            flows: List[str] = []
            rationale = ""
            severity = "medium"
            if {"untrusted_input", "external_transfer"} <= combined or \
                    ({"untrusted_input", "network", "artifact_output"} <= combined):
                flows.append("untrusted input -> artifact/context -> external transfer")
                rationale = "Capabilities are individually plausible but compose into an externally visible data path."
                severity = "high"
            if {"prompt_control", "process"} <= combined or \
                    {"prompt_control", "network"} <= combined:
                flows.append("instruction/context control -> downstream capability")
                rationale = (rationale + " " if rationale else "") + \
                    "Instruction-control signals can influence a downstream process or network capability."
                severity = "high"
            if {"artifact_output", "artifact_output", "filesystem_write", "process"} <= combined:
                flows.append("artifact handoff -> filesystem/process boundary")
                rationale = (rationale + " " if rationale else "") + \
                    "Artifacts may cross a boundary into a process-capable skill."
                severity = "high"
            if {"secret_access", "external_transfer"} <= combined:
                flows.append("secret source -> external transfer")
                rationale = (rationale + " " if rationale else "") + \
                    "A secret-reading capability and external-transfer capability coexist in the installed chain."
                severity = "critical"
            if not flows:
                continue
            risks.append(SkillChainRisk(
                chain_id="skill-chain-" + _hash(left.skill_id + "|" + right.skill_id)[:16],
                skills=sorted([left.skill_id, right.skill_id]),
                capabilities=sorted(combined), artifact_flow=flows,
                rationale=_clean(rationale), severity=severity,
            ))

    profiles.sort(key=lambda item: item.skill_id)
    risks.sort(key=lambda item: ({"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[item.severity], item.chain_id), reverse=True)
    return {
        "schema": SCHEMA,
        "source": "SkillsMetric + ColluSkill/ChainGuard methodology",
        "offline": True,
        "profiles": [asdict(item) for item in profiles],
        "chain_risks": [asdict(item) for item in risks],
        "dimensions": ["pattern_density", "statistical_anomaly", "dataflow_taint", "import_anomaly", "capability_mismatch", "cross_skill_composition"],
        "policy": "Static signals require semantic review and isolated runtime controls; no skill is executed by this analyzer.",
    }


def _event_time(record: Mapping[str, Any], index: int) -> float:
    value = record.get("timestamp", record.get("ts", record.get("time", index)))
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(index)


def _event_endpoint(record: Mapping[str, Any]) -> str:
    return _clean(record.get("endpoint") or record.get("url") or record.get("resource") or record.get("object") or "unknown", 240)


def _event_node(record: Mapping[str, Any], field_names: Sequence[str], fallback: str) -> str:
    for field_name in field_names:
        value = record.get(field_name)
        if value not in (None, ""):
            return _safe_id(value)
    return fallback


def investigate_provenance(records: Iterable[Mapping[str, Any]], *, max_events: int = 20_000,
                            max_chains: int = 64) -> Dict[str, Any]:
    """Compress supplied temporal events and rank causal bottleneck nodes."""
    rows = [dict(record) for record in records if isinstance(record, Mapping)][:max_events]
    rows.sort(key=lambda item: _event_time(item, 0))
    node_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    edges: Counter[Tuple[str, str, str]] = Counter()
    suspicious_nodes: set[str] = set()
    for index, record in enumerate(rows):
        source = _event_node(record, ("source", "src", "principal", "process", "actor"), f"event-source-{index}")
        target = _event_node(record, ("target", "dst", "resource", "object", "endpoint"), _event_endpoint(record))
        action = _safe_id(record.get("action") or record.get("event") or record.get("type") or "observed")
        node_events[source].append(record)
        node_events[target].append(record)
        if source != target:
            edges[(source, target, action)] += 1
        if str(record.get("severity", "")).lower() in {"critical", "high"} or \
                bool(record.get("suspicious") or record.get("anomaly")):
            suspicious_nodes.update({source, target})

    incoming: Counter[str] = Counter()
    outgoing: Counter[str] = Counter()
    for (source, target, _), count in edges.items():
        outgoing[source] += count
        incoming[target] += count
    nodes: List[ProvenanceNode] = []
    for node_id, events in node_events.items():
        times = [_event_time(event, index) for index, event in enumerate(events)]
        span = f"{min(times):g}..{max(times):g}" if times else ""
        distinct_actions = len({str(event.get("action") or event.get("event") or event.get("type") or "observed") for event in events})
        score = round(math.log1p(len(events)) * 2 + math.log1p(incoming[node_id] + outgoing[node_id]) * 3 + distinct_actions, 3)
        if node_id in suspicious_nodes:
            score += 5.0
        nodes.append(ProvenanceNode(
            node_id=node_id, label=node_id, event_count=len(events),
            in_degree=incoming[node_id], out_degree=outgoing[node_id],
            temporal_span=span, relevance_score=round(score, 3),
            suspicious=node_id in suspicious_nodes,
        ))
    nodes.sort(key=lambda item: (item.relevance_score, item.node_id), reverse=True)

    adjacency: Dict[str, List[str]] = defaultdict(list)
    for source, target, _ in edges:
        if target not in adjacency[source]:
            adjacency[source].append(target)
    chains: List[List[str]] = []
    for start in [node.node_id for node in nodes if node.suspicious][:max_chains]:
        queue: List[List[str]] = [[start]]
        while queue and len(chains) < max_chains:
            path = queue.pop(0)
            if len(path) > 1:
                chains.append(path)
            if len(path) >= 5:
                continue
            for nxt in sorted(adjacency.get(path[-1], [])):
                if nxt not in path:
                    queue.append(path + [nxt])
    fingerprints: Dict[str, List[str]] = defaultdict(list)
    for index, record in enumerate(rows):
        action = _safe_id(record.get("action") or record.get("event") or record.get("type") or "observed")
        endpoint = _event_endpoint(record)
        fingerprint = _hash(action + "|" + endpoint)[:16]
        fingerprints[fingerprint].append(_event_node(record, ("source", "src", "principal", "process", "actor"), f"event-source-{index}"))
    return {
        "schema": SCHEMA,
        "source": "TGL-APT + model-based runtime monitoring methodology",
        "offline": True,
        "events_seen": len(rows),
        "nodes": [asdict(node) for node in nodes],
        "edges": [{"source": source, "target": target, "action": action, "count": count}
                  for (source, target, action), count in sorted(edges.items())],
        "information_bottlenecks": [asdict(node) for node in nodes[:16]],
        "causal_chains": chains[:max_chains],
        "cross_spatiotemporal_fingerprints": [
            {"fingerprint": key, "entities": sorted(set(values))}
            for key, values in sorted(fingerprints.items())
            if len(set(values)) > 1
        ],
        "policy": "Graph relevance ranks investigation work; it does not establish attribution or authorize activity.",
    }


_AUTH_PATTERNS: Sequence[Tuple[str, str]] = (
    (r"(?i)(impossible\s+travel|new\s+country|new\s+geo|rare\s+source)", "geography_or_source_shift"),
    (r"(?i)(mfa\s*(?:failed|bypass|fatigue)|multi.factor|authentication\s+failure)", "authentication_or_mfa_anomaly"),
    (r"(?i)(role|privilege|admin|permission).*(?:changed|grant|elevat)", "privilege_transition"),
    (r"(?i)(session|cookie|token).*(?:new|reused|rotat|anomal)", "session_anomaly"),
    (r"(?i)(burst|spike|spray|brute|many\s+login)", "rate_or_volume_anomaly"),
)


def analyze_authentication_events(events: Iterable[Mapping[str, Any]],
                                  baselines: Mapping[str, Any] | None = None,
                                  *, max_events: int = 20_000) -> Dict[str, Any]:
    """Compare endpoint-specific auth observations to supplied baselines."""
    rows = [dict(row) for row in events if isinstance(row, Mapping)][:max_events]
    baseline = baselines or {}
    counts: Counter[Tuple[str, str]] = Counter()
    samples: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for row in rows:
        endpoint = _event_endpoint(row)
        identity = _clean(row.get("identity") or row.get("user") or row.get("principal") or "anonymous", 120)
        counts[(endpoint, identity)] += 1
        text = " ".join(str(value) for value in row.values())
        samples[(endpoint, identity)].append(text)
    anomalies: List[AuthAnomaly] = []
    for (endpoint, identity), observed in sorted(counts.items()):
        expected_value = baseline.get(endpoint, baseline.get(f"{endpoint}|{identity}", 0))
        try:
            expected = int(expected_value)
        except (TypeError, ValueError):
            expected = 0
        deviation = round((observed - expected) / max(1, expected), 3)
        categories: set[str] = set()
        for text in samples[(endpoint, identity)]:
            for pattern, category in _AUTH_PATTERNS:
                if re.search(pattern, text):
                    categories.add(category)
        if observed > expected * 2 + 2 or categories:
            anomaly_id = "auth-anomaly-" + _hash(endpoint + "|" + identity)[:16]
            rationale = f"Observed {observed} event(s) versus endpoint baseline {expected}; deviation={deviation}."
            if categories:
                rationale += " Context signals: " + ", ".join(sorted(categories)) + "."
            anomalies.append(AuthAnomaly(
                anomaly_id=anomaly_id, endpoint=endpoint, identity=identity,
                observed_count=observed, baseline_count=expected,
                deviation=deviation, categories=sorted(categories),
                rationale=rationale,
            ))
    anomalies.sort(key=lambda item: (max(item.deviation, 0), len(item.categories), item.anomaly_id), reverse=True)
    return {
        "schema": SCHEMA,
        "source": "endpoint-specific authentication anomaly methodology",
        "offline": True,
        "anomalies": [asdict(item) for item in anomalies],
        "ground_truth": "not available from telemetry alone; analyst review required",
        "policy": "Borderline anomalies remain reviewable and are never auto-blocked, challenged, reset, or reported.",
    }


_CTI_TECHNIQUES: Sequence[Tuple[str, str, str, str]] = (
    ("T1059", "command_and_scripting", "process_creation", "Command or scripting interpreter activity"),
    ("T1078", "valid_accounts", "authentication", "Use of valid accounts or unusual account context"),
    ("T1190", "exploit_public_facing_application", "web_server", "Public-facing application exploitation reference"),
    ("T1210", "exploitation_remote_services", "network_connection", "Remote-service exploitation reference"),
    ("T1566", "phishing", "email", "Phishing or social-delivery reference"),
    ("T1071", "application_layer_protocol", "network_traffic", "Application-layer network protocol reference"),
    ("T1021", "remote_services", "network_connection", "Remote-service access reference"),
)


def ground_cti_to_sigma(text: str, source: str = "cti-artifact") -> Dict[str, Any]:
    """Convert CTI text into static, template-grounded Sigma rule plans."""
    raw = str(text or "")
    technique_ids = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", raw, re.IGNORECASE)))
    cves = sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", raw, re.IGNORECASE)))
    lowered = raw.lower()
    plans: List[Dict[str, Any]] = []
    for attack_id, slug, logsource, label in _CTI_TECHNIQUES:
        if attack_id.lower() not in lowered and slug.replace("_", " ") not in lowered:
            continue
        rule_id = "cti-rule-" + _hash(source + "|" + attack_id)[:16]
        plans.append({
            "rule_id": rule_id,
            "title": f"CTI-grounded plan: {label}",
            "technique": attack_id,
            "logsource": {"category": logsource},
            "detection": {"selection": {"keywords": [slug, attack_id]}, "condition": "selection"},
            "references": {"source_sha256": _hash(raw), "cve_ids": cves},
            "false_positive_review": ["Validate fields against the actual telemetry schema.", "Test benign administrative and maintenance activity.", "Confirm the technique is present in the source context, not only a citation."],
            "status": "offline_plan_only",
            "execution": "never execute rule logic automatically",
        })
    if not plans and cves:
        plans.append({
            "rule_id": "cti-review-" + _hash(source + "|" + "|".join(cves))[:16],
            "title": "CVE-linked CTI requires environment-specific detection review",
            "technique": None,
            "logsource": {"category": "application"},
            "detection": {"selection": {"keywords": cves}, "condition": "selection"},
            "references": {"source_sha256": _hash(raw), "cve_ids": cves},
            "false_positive_review": ["Verify affected product/version before alerting.", "Ground fields in trusted telemetry."],
            "status": "offline_plan_only",
            "execution": "never execute rule logic automatically",
        })
    return {
        "schema": SCHEMA,
        "source": "AUTOSIGMA methodology",
        "offline": True,
        "source_sha256": _hash(raw),
        "technique_ids": technique_ids,
        "cve_ids": cves,
        "plans": plans,
        "validation_loop": ["knowledge_enrichment", "template_grounding", "schema_check", "false_positive_review", "analyst_approval"],
    }


def plan_binary_re_tasks(metadata: Mapping[str, Any], source: str = "binary-artifact") -> Dict[str, Any]:
    """Create a contamination-aware, deterministic binary-analysis task plan."""
    data = dict(metadata or {})
    imports = [str(item) for item in data.get("imports", [])][:500]
    sections = [str(item) for item in data.get("sections", [])][:100]
    strings = [str(item) for item in data.get("strings", [])][:500]
    known_hashes = {str(item).lower() for item in data.get("known_hashes", [])}
    artifact_hash = str(data.get("sha256") or data.get("hash") or "").lower()
    contamination = bool(artifact_hash and artifact_hash in known_hashes)
    has_cfg = bool(data.get("cfg") or data.get("control_flow_graph"))
    has_debug = bool(data.get("debug_symbols") or data.get("symbols"))
    has_anti_analysis = bool(data.get("anti_analysis") or re.search(r"(?i)(packed|obfuscat|anti.?debug|vm.?protect|opaque predicate)", " ".join(strings + sections)))
    task_specs = [
        ("metadata_triage", "Establish architecture, format, hash, signer, and provenance before interpretation.", ["format", "architecture", "sha256", "provenance"]),
        ("import_surface", "Classify imports and external calls without executing the binary.", ["imports", "libraries"]),
        ("string_semantics", "Cluster strings and references to identify candidate behaviors with source hashes only.", ["strings", "references"]),
        ("control_flow_recovery", "Recover and cross-check control-flow structure from the supplied artifact.", ["cfg_or_disassembly", "function_boundaries"]),
        ("hardening_review", "Record security hardening posture and missing metadata.", ["nx", "pie_or_aslr", "relro_or_cfg", "stack_protection"]),
        ("anti_analysis_review", "Identify anti-analysis signals and require an independent corroborating view.", ["anti_analysis_indicators", "second_view"]),
        ("cross_view_validation", "Compare at least two representations before asserting behavior.", ["static_view", "graph_or_metadata_view"]),
    ]
    tasks = []
    for name, objective, evidence in task_specs:
        tasks.append({
            "task_id": "re-task-" + _hash(source + "|" + name)[:16],
            "name": name,
            "objective": objective,
            "required_evidence": evidence,
            "status": "blocked_by_contamination" if contamination else "planned",
            "execution": "offline_or_isolated_lab_only",
            "automatic_execution": False,
        })
    return {
        "schema": SCHEMA,
        "source": "SRE-Bench + Malformer methodology",
        "offline": True,
        "artifact": {"source": source, "sha256": artifact_hash or _hash(json.dumps(data, sort_keys=True))},
        "contamination": {"known_hash_match": contamination, "requires_unseen_artifact": True, "source_fingerprint_required": True},
        "modalities": {
            "text": bool(strings or imports),
            "image": bool(data.get("section_image") or data.get("visual_representation")),
            "graph": has_cfg,
            "audio": bool(data.get("audio_representation")),
            "available_count": sum(bool(value) for value in (bool(strings or imports), bool(data.get("section_image") or data.get("visual_representation")), has_cfg, bool(data.get("audio_representation")))),
        },
        "signals": {"import_count": len(imports), "section_count": len(sections), "string_count": len(strings), "debug_symbols": has_debug, "anti_analysis": has_anti_analysis},
        "tasks": tasks,
        "grading": ["evidence completeness", "cross-view agreement", "reproducibility", "uncertainty calibration", "no contamination shortcut"],
        "policy": "Binary artifacts are not executed, patched, unpacked, or used to construct payloads by this planner.",
    }


def evolve_defenses(failure_traces: Iterable[Mapping[str, Any]], *, max_candidates: int = 64) -> Dict[str, Any]:
    """Turn failure traces into reviewed defense candidates without auto-applying them."""
    candidates: Dict[str, DefenseCandidate] = {}
    interventions = (
        ("prompt_injection", ("prompt_injection", "prompt injection"), "isolate untrusted instructions and re-run the decision with a typed task contract", ["benign task utility", "injection fixture", "instruction provenance"]),
        ("tool_authorization", ("tool_authorization", "tool authorization", "unauthorized tool"), "require a capability-specific authorization decision before tool dispatch", ["allowed tool matrix", "denied tool fixture", "audit record"]),
        ("memory_provenance", ("memory_provenance", "memory provenance", "memory write"), "bind memory writes to source provenance, tenant, expiry, and review state", ["cross-tenant negative test", "expiry test", "provenance record"]),
        ("malformed_output", ("malformed_output", "malformed output", "structured output"), "validate structured output against a schema and preserve the failure trace", ["invalid-output fixture", "retry bound", "trace integrity"]),
        ("state_inconsistency", ("state_inconsistency", "state inconsistency", "inconsistent state"), "reset only an isolated lab session and compare expected versus observed state", ["fresh-session test", "state snapshot", "recovery test"]),
        ("scope_confusion", ("scope_confusion", "scope confusion", "out of scope"), "re-check target, artifact, and capability scope at the handoff boundary", ["scope-negative test", "handoff provenance", "denied action record"]),
    )
    for index, trace in enumerate(failure_traces):
        if not isinstance(trace, Mapping):
            continue
        text = " ".join(str(value) for value in trace.values()).lower()
        matched = [(name, intervention, tests) for name, phrases, intervention, tests in interventions
                   if any(phrase in text for phrase in phrases)]
        if not matched:
            fallback = interventions[3]
            matched = [(fallback[0], fallback[2], fallback[3])]
        for name, intervention, tests in matched:
            digest = _hash(json.dumps(dict(trace), sort_keys=True))
            candidate_id = "defense-candidate-" + _hash(name + "|" + digest)[:16]
            candidates.setdefault(candidate_id, DefenseCandidate(
                candidate_id=candidate_id, failure_class=name,
                intervention=intervention, evidence_hash=digest,
                regression_tests=list(tests),
            ))
        if len(candidates) >= max_candidates:
            break
    return {
        "schema": SCHEMA,
        "source": "HARD + SSH-honeypot evaluation methodology",
        "offline": True,
        "candidates": [asdict(item) for item in sorted(candidates.values(), key=lambda item: item.candidate_id)][:max_candidates],
        "policy": "Candidates are quarantined until operator review; executable source and harness gates are never self-modified.",
    }


_COLD_START_FEATURES = (
    ("input_boundary", ("input", "request", "parameter", "artifact", "upload", "document"), 2.0),
    ("trust_boundary", ("trust", "header", "proxy", "identity", "tenant", "role", "auth"), 2.5),
    ("state_boundary", ("state", "workflow", "race", "transition", "cache", "sequence"), 2.0),
    ("impact_boundary", ("rce", "command", "write", "disclosure", "takeover", "funds", "privilege"), 3.0),
    ("cross_surface", ("graphql", "mobile", "web", "api", "cloud", "browser", "contract"), 1.0),
    ("evidence_signal", ("trace", "oracle", "baseline", "owned", "reproduced", "observed"), 2.0),
)


def _candidate_feature_text(candidate: Mapping[str, Any]) -> str:
    """Build features from public structure/content, excluding identity fields."""
    excluded = {"id", "candidate_id", "finding_id", "lead_id", "stable_id", "name"}
    values = []
    for key, value in sorted(candidate.items()):
        if key.lower() in excluded or key.lower().endswith("_id"):
            continue
        if isinstance(value, (str, int, float, bool)):
            values.append(str(value))
        elif isinstance(value, list):
            values.extend(str(item) for item in value[:32])
    return " ".join(values).lower()


def rank_cold_start_candidates(candidates: Iterable[Mapping[str, Any]],
                               context: Mapping[str, Any] | None = None,
                               *, top_k: int = 100,
                               model_version: str = "bugwolf-cold-start-v1") -> Dict[str, Any]:
    """Rank unseen hypotheses using deterministic identity-independent features.

    This is a planning analogue of DraftFM's cold-start idea: candidates are
    scored from their public feature content and current context, while IDs are
    carried only as opaque references in the output and never influence score.
    The result includes hashes so an operator can seal and later compare the
    exact forecast; it is not evidence of vulnerability.
    """
    if top_k < 1 or top_k > 1000:
        raise ValueError("top_k must be 1..1000")
    rows = [dict(item) for item in candidates if isinstance(item, Mapping)]
    ctx_text = _candidate_feature_text(dict(context or {}))
    scored: List[Dict[str, Any]] = []
    for index, candidate in enumerate(rows):
        text = _candidate_feature_text(candidate)
        feature_vector: Dict[str, float] = {}
        score = 0.0
        for feature, terms, weight in _COLD_START_FEATURES:
            candidate_hits = sum(1 for term in terms if term in text)
            context_hits = sum(1 for term in terms if term in ctx_text)
            value = min(1.0, candidate_hits / 2.0) + min(0.5, context_hits / 4.0)
            feature_vector[feature] = round(value, 4)
            score += value * weight
        severity = _severity(candidate.get("severity", "medium"))
        score += {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.25, "info": 0.0}[severity]
        reference = str(candidate.get("candidate_id") or candidate.get("finding_id") or candidate.get("id") or f"candidate-{index}")
        scored.append({
            "reference": _safe_id(reference),
            "score": round(score, 4),
            "severity": severity,
            "feature_vector": feature_vector,
            "evidence_state": str(candidate.get("evidence_state") or candidate.get("status") or "hypothesis"),
            "status": "cold_start_priority_only",
        })
    scored.sort(key=lambda item: (-item["score"], -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[item["severity"]], item["reference"]))
    scored = scored[:top_k]
    candidate_set_sha256 = _hash(json.dumps(rows, sort_keys=True, separators=(",", ":")))
    ranking_sha256 = _hash(json.dumps(scored, sort_keys=True, separators=(",", ":")))
    return {
        "schema": SCHEMA,
        "source": "DraftFM cold-start ranking methodology",
        "offline": True,
        "model_version": model_version,
        "candidate_set_sha256": candidate_set_sha256,
        "ranking_sha256": ranking_sha256,
        "feature_policy": "identity-independent public feature text and structured fields; no usage statistics or candidate identity in scoring",
        "ranking": scored,
        "sealed_provenance": {
            "candidate_set_sha256": candidate_set_sha256,
            "ranking_sha256": ranking_sha256,
            "model_version": model_version,
            "sealed": True,
            "later_outcome_validation_required": True,
        },
        "policy": "A cold-start rank is a prioritization hypothesis, never a confirmed vulnerability or authorization decision.",
    }


_ZERO_DAY_TAXONOMY = {
    "memory_corruption": ("memory", "buffer", "overflow", "use-after-free", "uaf", "corruption", "out-of-bounds"),
    "input_validation": ("injection", "parser", "validation", "deserialization", "xxe", "traversal"),
    "authorization_logic": ("idor", "authz", "privilege", "role", "tenant", "authorization", "access control"),
    "state_logic": ("race", "workflow", "state", "cache", "business logic", "transition"),
    "defensive_mechanism": ("sandbox", "filter", "edr", "asr", "amsi", "mitigation", "defense"),
    "supply_chain": ("dependency", "package", "build", "artifact", "workflow", "update"),
}


def assess_zero_day_claims(candidates: Iterable[Mapping[str, Any]], *,
                           max_items: int = 500) -> Dict[str, Any]:
    """Separate vulnerability-centric claims from behavior-only novelty claims."""
    assessments: List[Dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping):
            continue
        text = _candidate_feature_text(candidate)
        evidence = " ".join(str(candidate.get(key, "")) for key in ("evidence", "description", "impact", "validation", "research"))
        evidence_lower = evidence.lower()
        taxonomy = [name for name, terms in _ZERO_DAY_TAXONOMY.items()
                    if any(term in text for term in terms)]
        vulnerability_signals = sum(1 for term in ("root cause", "vulnerability", "flaw", "sink", "reachability", "trigger", "impact", "cwe") if term in evidence_lower)
        behavior_signals = sum(1 for term in ("anomaly", "novel behavior", "unusual", "ttp", "sequence", "traffic pattern") if term in text or term in evidence_lower)
        has_trigger = bool(candidate.get("trigger") or candidate.get("trigger_evidence") or "trigger" in evidence_lower or "reproduced" in evidence_lower)
        has_impact = bool(candidate.get("impact") or candidate.get("impact_evidence") or "impact" in evidence_lower or "victim" in evidence_lower)
        if vulnerability_signals >= 2 and (taxonomy or has_trigger):
            claim_type = "vulnerability_centric_candidate"
            status = "requires_novelty_and_human_review"
        elif behavior_signals and vulnerability_signals == 0:
            claim_type = "behavior_only_not_zero_day_proof"
            status = "do_not_label_zero_day"
        else:
            claim_type = "insufficient_vulnerability_evidence"
            status = "blocked_pending_evidence"
        assessments.append({
            "reference": _safe_id(candidate.get("candidate_id") or candidate.get("finding_id") or candidate.get("id") or f"candidate-{index}"),
            "claim_type": claim_type,
            "taxonomy": taxonomy,
            "trigger_evidence": has_trigger,
            "impact_evidence": has_impact,
            "vulnerability_signal_count": vulnerability_signals,
            "behavior_signal_count": behavior_signals,
            "status": status,
            "required_next_evidence": [
                "root-cause or invariant evidence",
                "bounded trigger reproduction on an authorized fixture",
                "concrete impact evidence",
                "novelty/dedup review",
                "human approval",
            ],
        })
    assessments = assessments[:max_items]
    vulnerability_count = sum(item["claim_type"] == "vulnerability_centric_candidate" for item in assessments)
    return {
        "schema": SCHEMA,
        "source": "Zero Day Attacks: Novel Behaviour or Novel Vulnerability? methodology",
        "offline": True,
        "assessments": assessments,
        "stats": {
            "total": len(assessments),
            "vulnerability_centric_candidates": vulnerability_count,
            "behavior_only": sum(item["claim_type"] == "behavior_only_not_zero_day_proof" for item in assessments),
            "blocked": sum(item["claim_type"] == "insufficient_vulnerability_evidence" for item in assessments),
        },
        "policy": "Novel behavior or anomaly is not zero-day proof; BugWolf requires vulnerability evidence, bounded validation, novelty review, and human approval.",
    }


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _pearson(left: Sequence[float], right: Sequence[float]) -> float | None:
    pairs = [(a, b) for a, b in zip(left, right) if math.isfinite(a) and math.isfinite(b)]
    if len(pairs) < 2:
        return None
    left_values = [pair[0] for pair in pairs]
    right_values = [pair[1] for pair in pairs]
    left_mean = sum(left_values) / len(left_values)
    right_mean = sum(right_values) / len(right_values)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in pairs)
    left_norm = math.sqrt(sum((a - left_mean) ** 2 for a in left_values))
    right_norm = math.sqrt(sum((b - right_mean) ** 2 for b in right_values))
    if left_norm == 0 or right_norm == 0:
        return None
    return round(numerator / (left_norm * right_norm), 4)


def _bucket_length(value: float) -> int:
    return int(max(0, value) // 32 * 32)


def _direction(value: Any) -> int:
    text = str(value or "").lower()
    if text in {"out", "up", "uplink", "client", "request", "-1"}:
        return -1
    return 1


def analyze_https_fingerprint(
    traffic_records: Iterable[Mapping[str, Any]],
    logic_profiles: Iterable[Mapping[str, Any]] = (),
    *,
    unknown_threshold: float = 0.35,
    max_records: int = 50_000,
) -> Dict[str, Any]:
    """Assess STAR-style semantic/traffic alignment from supplied metadata.

    This is intentionally a passive artifact analyzer. It accepts packet/flow
    metadata and separately supplied resource-logic profiles; it never captures
    traffic, decrypts content, crawls a site, identifies an unrelated user, or
    contacts a target. Matching is a retrieval hypothesis and unknown rejection
    remains the default when the score is below the supplied threshold.
    """
    if not 0.0 <= unknown_threshold <= 1.0:
        raise ValueError("unknown_threshold must be between 0 and 1")
    rows = [dict(row) for row in traffic_records if isinstance(row, Mapping)][:max_records]
    profiles = [dict(row) for row in logic_profiles if isinstance(row, Mapping)][:10_000]
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for index, row in enumerate(rows):
        key = _safe_id(row.get("session_id") or row.get("flow_id") or row.get("trace_id") or "trace-" + str(index))
        packet_length = _as_float(row.get("packet_length", row.get("length", row.get("size"))))
        if packet_length is None or packet_length < 0:
            continue
        copy = dict(row)
        copy["_packet_length"] = packet_length
        grouped[key].append(copy)

    traces: List[Dict[str, Any]] = []
    for trace_id, packets in sorted(grouped.items()):
        total = sum(packet["_packet_length"] for packet in packets)
        uplink = sum(packet["_packet_length"] for packet in packets if _direction(packet.get("direction")) < 0)
        downlink = total - uplink
        udp = sum(1 for packet in packets if str(packet.get("transport", packet.get("protocol", ""))).lower() in {"udp", "quic", "http3"})
        http3 = sum(1 for packet in packets if str(packet.get("http_version", "")).lower() in {"h3", "http/3", "http3"})
        sequence = [{"direction": _direction(packet.get("direction")), "length_bucket": _bucket_length(packet["_packet_length"])} for packet in packets[:200]]
        traces.append({
            "trace_id": trace_id,
            "packet_count": len(packets),
            "total_bytes": round(total, 3),
            "uplink_bytes": round(uplink, 3),
            "downlink_bytes": round(downlink, 3),
            "udp_ratio": round(udp / max(1, len(packets)), 4),
            "http3_ratio": round(http3 / max(1, len(packets)), 4),
            "direction_length_sequence": sequence,
            "status": "traffic_metadata_only",
        })

    anchor_specs = (
        ("request_anchor", ("uri_length", "request_uri_length"), ("request_packet_length", "request_length"), "URI length versus request packet length"),
        ("response_anchor", ("resource_size", "response_size"), ("response_bytes", "response_length"), "resource size versus response bytes"),
        ("protocol_anchor", ("http3_ratio", "http3"), ("udp_ratio", "udp"), "HTTP/3 usage versus UDP ratio"),
    )
    alignments = []
    for name, logic_keys, traffic_keys, explanation in anchor_specs:
        left: List[float] = []
        right: List[float] = []
        for row in rows:
            logic_value = next((_as_float(row.get(key)) for key in logic_keys if _as_float(row.get(key)) is not None), None)
            traffic_value = next((_as_float(row.get(key)) for key in traffic_keys if _as_float(row.get(key)) is not None), None)
            if logic_value is not None and traffic_value is not None:
                left.append(logic_value)
                right.append(traffic_value)
        correlation = _pearson(left, right)
        alignments.append({
            "anchor": name,
            "explanation": explanation,
            "paired_samples": len(left),
            "pearson": correlation,
            "status": "supported_by_supplied_pairs" if correlation is not None else "not_enough_paired_metadata",
        })

    def profile_vector(profile: Mapping[str, Any]) -> List[float]:
        return [
            float(_as_float(profile.get("uri_length", profile.get("mean_uri_length"))) or 0),
            float(_as_float(profile.get("resource_size", profile.get("mean_resource_size"))) or 0),
            float(_as_float(profile.get("resource_count")) or 0),
            1.0 if str(profile.get("http_version", "")).lower() in {"h3", "http/3", "http3"} else 0.0,
        ]

    def trace_vector(trace: Mapping[str, Any]) -> List[float]:
        return [
            float(trace["uplink_bytes"] / max(1, trace["packet_count"])),
            float(trace["downlink_bytes"]),
            float(trace["packet_count"]),
            float(trace["http3_ratio"]),
        ]

    def cosine(left: Sequence[float], right: Sequence[float]) -> float:
        numerator = sum(a * b for a, b in zip(left, right))
        denominator = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
        return round(numerator / denominator, 4) if denominator else 0.0

    retrievals = []
    for trace in traces:
        ranked = []
        for profile in profiles:
            ranked.append({
                "profile": _safe_id(profile.get("site") or profile.get("profile_id") or profile.get("name") or "profile"),
                "score": cosine(trace_vector(trace), profile_vector(profile)),
            })
        ranked.sort(key=lambda item: (-item["score"], item["profile"]))
        best = ranked[0] if ranked else None
        retrievals.append({
            "trace_id": trace["trace_id"],
            "best_match": best,
            "candidates": ranked[:10],
            "decision": "unknown" if not best or best["score"] < unknown_threshold else "candidate_match",
            "status": "open_world_retrieval_only",
        })

    return {
        "schema": SCHEMA,
        "source": "STAR semantic-traffic alignment and retrieval methodology",
        "offline": True,
        "records_seen": len(rows),
        "traces": traces,
        "alignment_anchors": alignments,
        "retrievals": retrievals,
        "unknown_threshold": unknown_threshold,
        "augmentation_plan": {
            "method": "paired structural deletion by shared server or flow identity",
            "required_keys": ["server_ip", "flow_id", "resource_id"],
            "status": "offline_plan_only",
            "purpose": "preserve logic/traffic correspondence while modeling resource churn",
        },
        "privacy": "metadata only; no payload, decryption, user identity, or unrelated-site attribution",
        "policy": "A correlation or match is a hypothesis for an authorized assessment, not proof of site ownership, user activity, or compromise.",
    }


_AGENT_GAP_SPECS = (
    ("AG-01", "agent_identity", "Agent has no distinct, auditable identity or uses a shared human/service identity.", "high", "GOV", "Entra-style agent identity lifecycle"),
    ("AG-02", "input_provenance", "Untrusted user, document, web, or tool content lacks provenance and instruction/data separation.", "high", "MAP", "Prompt Shields-style input isolation"),
    ("AG-03", "tool_authorization", "Tool calls lack independent authorization, parameter validation, or exact approval binding.", "critical", "MAN", "Policy engine and least-privilege tool registry"),
    ("AG-04", "supply_chain", "Dependencies, skills, plugins, or tool metadata lack origin, integrity, or review evidence.", "high", "MAP", "Signed/artifact provenance and quarantined install path"),
    ("AG-05", "memory_integrity", "Persistent memory lacks tenant binding, source provenance, expiry, or review state.", "high", "MAN", "Memory write policy and ghost-memory timeline"),
    ("AG-06", "data_governance", "Sensitive data sources lack labels, DLP policy, or server-side access constraints.", "critical", "MAP", "Purview-style data inventory and information-flow policy"),
    ("AG-07", "resource_bounds", "Model, retrieval, or tool loops lack explicit token, time, request, or cost bounds.", "medium", "MEASURE", "Reliability budgets, timeout, retry, and circuit-breaker controls"),
    ("AG-08", "audit_telemetry", "Tool, data, identity, and model actions cannot be correlated into a tamper-evident audit trail.", "high", "MEASURE", "Defender/Sentinel-style entity timeline and event integrity"),
    ("AG-09", "runtime_grounding", "Output grounding, schema validation, or content-safety decisions are absent before action.", "high", "MEASURE", "Groundedness and deterministic output validation"),
    ("AG-10", "response_linkage", "AI risk signals have no incident sink, owner, playbook, or policy writeback path.", "medium", "MAN", "SOC incident, response, and policy feedback loop"),
)


def _as_records(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, Mapping):
        return [dict(value)]
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    return []


def assess_agent_control_plane(artifact: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Audit an Agent control plane from a supplied export/configuration.

    The result joins identity, data, model, tool, memory, telemetry, and SOC
    response evidence. It is deliberately vendor-neutral; vendor labels in the
    control records are mappings, not proof that a product is deployed.
    """
    root = dict(artifact) if isinstance(artifact, Mapping) else {"agents": list(artifact)}
    inventory_keys = ("agents", "agent_inventory", "systems")
    has_inventory = any(key in root for key in inventory_keys)
    agents = _as_records(next((root.get(key) for key in inventory_keys if key in root), None))
    if not agents and root and not has_inventory:
        agents = [root]
    gaps: List[Dict[str, Any]] = []
    coverage: Dict[str, int] = {spec[1]: 0 for spec in _AGENT_GAP_SPECS}
    for index, agent in enumerate(agents[:500]):
        agent_id = _safe_id(agent.get("id") or agent.get("name") or f"agent-{index}")
        identity = agent.get("identity") or agent.get("agent_identity") or {}
        identity_text = json.dumps(identity, sort_keys=True).lower() if isinstance(identity, (Mapping, list)) else str(identity).lower()
        tools = _as_records(agent.get("tools") or agent.get("tool_registry"))
        data_sources = _as_records(agent.get("data_sources") or agent.get("repositories") or agent.get("retrieval"))
        memory = agent.get("memory") or {}
        telemetry = agent.get("telemetry") or agent.get("logging") or {}
        response = agent.get("response") or agent.get("soc") or {}
        runtime = agent.get("runtime") or agent.get("controls") or {}
        if not isinstance(memory, Mapping):
            memory = {}
        if not isinstance(telemetry, Mapping):
            telemetry = {}
        if not isinstance(response, Mapping):
            response = {}
        if not isinstance(runtime, Mapping):
            runtime = {}
        checks = {
            "agent_identity": bool(identity) and not any(term in identity_text for term in ("shared", "human", "api_key", "generic")),
            "input_provenance": bool(agent.get("input_provenance") or runtime.get("input_provenance") or runtime.get("prompt_shields") or runtime.get("content_provenance")),
            "tool_authorization": bool(tools) and all(bool(tool.get("authorization") or tool.get("policy") or tool.get("approval")) for tool in tools),
            "supply_chain": bool(agent.get("skill_provenance") or agent.get("plugin_integrity") or agent.get("signed_artifacts")),
            "memory_integrity": not bool(memory) or all(bool(memory.get(key)) for key in ("tenant_binding", "source_provenance", "expiry")),
            "data_governance": not bool(data_sources) or all(bool(source.get("tenant_filter") or source.get("access_policy")) and bool(source.get("sensitivity") or source.get("labels")) for source in data_sources),
            "resource_bounds": bool(agent.get("budgets") or runtime.get("budgets") or runtime.get("timeout") or runtime.get("max_iterations")),
            "audit_telemetry": bool(telemetry) and all(bool(telemetry.get(key)) for key in ("actor", "action", "outcome")),
            "runtime_grounding": bool(runtime.get("groundedness") or runtime.get("output_validation") or runtime.get("schema_validation")),
            "response_linkage": bool(response) and any(bool(response.get(key)) for key in ("incident_sink", "owner", "playbook", "policy_writeback")),
        }
        for owasp_id, key, rationale, severity, nist, vendor_control in _AGENT_GAP_SPECS:
            if checks[key]:
                coverage[key] += 1
                continue
            gaps.append({
                "gap_id": "agent-gap-" + _hash(agent_id + "|" + key)[:16],
                "agent": agent_id,
                "owasp_agentic": owasp_id,
                "control": key,
                "severity": severity,
                "nist_function": nist,
                "vendor_neutral_mapping": vendor_control,
                "rationale": rationale,
                "status": "offline_plan_only",
                "validation": ["inspect the control owner and exact policy", "run a synthetic negative fixture", "preserve the decision and evidence hash"],
                "automatic_action": False,
            })
    gaps.sort(key=lambda item: ({"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[item["severity"]], item["agent"], item["control"]), reverse=True)
    total_checks = max(1, len(agents)) * len(_AGENT_GAP_SPECS)
    return {
        "schema": SCHEMA,
        "source": "Agent identity/data/model/response control-plane methodology",
        "offline": True,
        "agents_seen": len(agents),
        "control_gaps": gaps,
        "coverage": coverage,
        "coverage_ratio": round(1 - len(gaps) / total_checks, 4),
        "control_chain": ["identity", "data", "input", "model", "tools", "memory", "telemetry", "response", "policy_writeback"],
        "frameworks": {"owasp_agentic": "risk taxonomy only", "nist_ai_rmf": ["GOV", "MAP", "MEASURE", "MANAGE"], "enterprise_control_plane": ["identity", "data", "runtime", "detection", "response"]},
        "policy": "Static gaps require owner review and isolated validation; this adapter does not change permissions, call tools, or contact provider services.",
    }


# ---------------------------------------------------------------------------
# TaintRadar-derived taint-flow and sanitization analysis (offline only)
# ---------------------------------------------------------------------------

# Vulnerability-typed sanitizer classification: a single sanitizer (e.g.
# htmlentities) may neutralize XSS but leave SQLi completely open. This
# mirrors TaintRadar's per-vulnerability sanitization lattice rather than
# the binary "sanitized / not sanitized" model of prior tools.
_VULN_SANITIZERS: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "sqli": {
        "explicit": ("mysqli_real_escape_string", "pg_escape_string",
                     "sqlite_escape_string", "addslashes", "mysql_real_escape_string",
                     "PDO::quote", "quote", "escape", "prepared_statement"),
        "implicit": ("intval", "int", "floatval", "float", "is_numeric", "ctype_digit",
                    "filter_var.*INT", "filter_var.*FLOAT"),
    },
    "xss": {
        "explicit": ("htmlentities", "htmlspecialchars", "strip_tags",
                    "filter_var.*SANITIZE_STRING", "filter_var.*SANITIZE_FULL_SPECIAL_CHARS",
                    "xss_clean", "esc_html", "esc_attr", "h", "twig_escape"),
        "implicit": (),
    },
    "command_injection": {
        "explicit": ("escapeshellarg", "escapeshellcmd"),
        "implicit": ("intval", "basename", "realpath"),
    },
    "path_traversal": {
        "explicit": ("basename", "realpath"),
        "implicit": (),
    },
    "ssti": {
        "explicit": ("autoescape", "escape", "safe"),
        "implicit": (),
    },
}

# Known persistence-related data-flow signal patterns.
_DB_PERSISTENCE_INDICATORS: Sequence[Tuple[str, str, str, str]] = (
    (r"(?i)(INSERT\s+INTO|UPDATE\s+\w+\s+SET)", "db_write", "Database write operation", "high"),
    (r"(?i)(SELECT\s+.+\s+FROM)", "db_read", "Database read operation", "info"),
    (r"(?i)(echo\s+|print\s+|<\?=.*\?>|render|twig|template)", "output_render", "Output rendering sink", "high"),
    (r"(?i)(header\s*\(.*Location|redirect|wp_redirect)", "redirect_sink", "Redirect sink", "medium"),
)


def analyze_taint_flow(
    source_text: str,
    *,
    database_schema: Mapping[str, Any] | None = None,
    source_label: str = "artifact",
) -> Dict[str, Any]:
    """Offline taint-flow analysis inspired by TaintRadar's three-layer CPG augmentation.

    This does NOT build a CPG or parse PHP ASTs; BugWolf is a black-box engine.
    Instead, it (1) classifies sanitization by vulnerability class using known
    language-agnostic sanitizer patterns, (2) identifies database read/write
    boundaries and output sinks, and (3) produces cross-script persistence chain
    hypotheses when a write boundary and a read+render boundary share a common
    resource label.

    The output is an offline plan — never an executed payload or chain.
    """
    text = str(source_text or "")
    schema = database_schema or {}

    # 1. Per-vulnerability sanitization classification
    sanitization_status: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
    for vuln_class, layers in _VULN_SANITIZERS.items():
        sanitization_status[vuln_class] = {"explicit": [], "implicit": []}
        for kind in ("explicit", "implicit"):
            for pattern in layers[kind]:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    sanitization_status[vuln_class][kind].append({
                        "pattern": pattern,
                        "span": f"{match.start()}-{match.end()}",
                        "matched": _clean(match.group(), 120),
                    })

    # 2. Database boundary and output sink detection
    boundaries: List[Dict[str, Any]] = []
    for pattern, category, label, severity in _DB_PERSISTENCE_INDICATORS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            boundaries.append({
                "boundary_id": "taint-boundary-" + _hash(source_label + "|" + str(match.start()))[:16],
                "category": category,
                "label": label,
                "severity": severity,
                "span": f"{match.start()}-{match.end()}",
                "preview": _clean(match.group(), 200),
                "source": source_label,
            })

    # 3. Cross-script persistence chain hypotheses
    writes = [b for b in boundaries if b["category"] == "db_write"]
    reads = [b for b in boundaries if b["category"] == "db_read"]
    renders = [b for b in boundaries if b["category"] in ("output_render", "redirect_sink")]

    persistence_chains: List[Dict[str, Any]] = []
    if writes and reads and renders:
        chain_id = "persist-chain-" + _hash(source_label + "|" + str(len(writes)))[:16]
        persistence_chains.append({
            "chain_id": chain_id,
            "title": "Database persistence to rendered-output chain",
            "stages": ["user_input", "db_insert_or_update", "db_select", "output_render"],
            "write_boundaries": len(writes),
            "read_boundaries": len(reads),
            "render_sinks": len(renders),
            "risk_classes": ("stored_xss" if renders else ""),
            "taintrader_insight": (
                "TaintRadar: without DB-schema-aware edges, the write and read "
                "scripts appear disconnected; a taint chain that traverses "
                "persistent storage is invisible to standard CPG tools."
            ),
            "validation_questions": [
                "Do the INSERT and SELECT share a table and overlapping unsafe columns?",
                "Is the rendered output encoded per output context (HTML, JS, URL)?",
                "Can the same data reach a different render path (JSON API, CSV export)?",
            ],
            "status": "offline_hypothesis_only",
            "automatic_execution": False,
        })

    # 4. Schema-aware column safety (if schema supplied)
    schema_columns: List[Dict[str, Any]] = []
    for table_name, columns in schema.items():
        if not isinstance(columns, (Mapping, list)):
            continue
        column_map = dict(columns) if isinstance(columns, Mapping) else {
            str(item): "unknown" for item in columns}
        for col_name, col_type in column_map.items():
            type_str = str(col_type).upper()
            safe = any(keyword in type_str for keyword in (
                "INT", "FLOAT", "DOUBLE", "DECIMAL", "BOOL", "DATE",
                "TIME", "TIMESTAMP", "DATETIME", "ENUM", "SET"))
            unsafe = any(keyword in type_str for keyword in (
                "VARCHAR", "TEXT", "CHAR", "BLOB", "LONGTEXT", "MEDIUMTEXT"))
            schema_columns.append({
                "table": str(table_name),
                "column": str(col_name),
                "type": type_str,
                "safe_type": safe and not unsafe,
            })

    return {
        "schema": SCHEMA,
        "source": "TaintRadar sanitization + database-aware methodology",
        "offline": True,
        "source_label": source_label,
        "sanitization_per_vuln_class": {
            vuln: {
                "explicit_count": len(sanitization_status[vuln]["explicit"]),
                "implicit_count": len(sanitization_status[vuln]["implicit"]),
                "fully_sanitized": bool(
                    sanitization_status[vuln]["explicit"] or
                    sanitization_status[vuln]["implicit"]),
                "details": sanitization_status[vuln],
            }
            for vuln in sanitization_status
        },
        "db_boundaries": boundaries,
        "persistence_chains": persistence_chains,
        "schema_columns": schema_columns,
        "taintrader_note": (
            "TaintRadar's object-field reaching-definition layer is not applicable; "
            "BugWolf is a black-box engine and does not build CPGs. The sanitization "
            "and database-awareness layers are adapted as offline planning signals."
        ),
        "policy": "Signals are plans only; no payload, DB write, or output is executed by this adapter.",
    }


# ---------------------------------------------------------------------------
# CVE-candidate matching via NLP (TaintRadar CVE-matching methodology)
# ---------------------------------------------------------------------------

# CVE records this adapter can match against — populated from identity_cloud.py
# seed intake and operator-supplied CVE manifests.
_CVE_INDEX: Dict[str, Dict[str, Any]] = {}


def _load_cve_index(cve_dir: str | Path | None = None) -> Dict[str, Dict[str, Any]]:
    """Populate the in-memory CVE index from the canonical offline store."""
    global _CVE_INDEX
    if _CVE_INDEX:
        return _CVE_INDEX
    root = Path(cve_dir or "state/cve").expanduser()
    if not root.is_dir():
        return {}
    for path in sorted(root.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, Mapping):
            cve_id = str(data.get("cve_id") or data.get("id") or path.stem)
            _CVE_INDEX[cve_id] = dict(data)
    return _CVE_INDEX


def _cve_match_score(finding_text: str, cve_record: Mapping[str, Any]) -> Dict[str, Any]:
    """Compute a multi-signal match score between a finding and a CVE record.

    Layered matching, as in TaintRadar's NLP pipeline:
    1. Product/version substring matching
    2. Vulnerability class alignment
    3. Parameter/function substring matching with word-boundary detection
    4. File-name overlap (from CVE description)
    """
    text = str(finding_text or "").lower()
    cve_text = " ".join(str(v) for v in cve_record.values()).lower()
    score = 0.0
    signals: List[str] = []

    # 1. Vulnerability class match
    vuln_classes = ["sql injection", "sqli", "xss", "cross-site scripting",
                   "command injection", "rce", "path traversal", "idor",
                   "ssrf", "deserialization", "csrf", "xxe", "ssti"]
    for vc in vuln_classes:
        if vc in text and vc in cve_text:
            score += 3.0
            signals.append(f"vuln_class:{vc}")
            break

    # 2. Product/version match
    products = set(re.findall(r"\b([a-z][a-z0-9_.-]{2,30})\s+\d+\.\d+", cve_text))
    matched_products = [p for p in products if p in text or p.replace("-", "_") in text]
    if matched_products:
        score += len(matched_products) * 4.0
        signals.append(f"product:{','.join(matched_products[:3])}")

    # 3. Parameter/function match with word boundary
    params = set(re.findall(r"\$?([a-z_][a-z0-9_]{2,30})", cve_text))
    matched_params = []
    for p in params:
        if p in {"the", "and", "for", "from", "with", "that", "this", "into",
                   "attack", "attacker", "vulnerability", "version", "application"}:
            continue
        if re.search(r"\b" + re.escape(p) + r"\b", text):
            matched_params.append(p)
    if matched_params:
        score += len(matched_params) * 1.5
        signals.append(f"params:{','.join(matched_params[:5])}")

    # 4. File-name overlap
    files = set(re.findall(r"([a-z][a-z0-9_.-]{3,40}\.(?:php|py|js|java|rb|go|ts|cs))", cve_text))
    matched_files = [f for f in files if f in text]
    if matched_files:
        score += len(matched_files) * 2.0
        signals.append(f"files:{','.join(matched_files[:3])}")

    return {"score": round(score, 3), "signals": signals}


def match_cve_candidates(
    findings: Iterable[Mapping[str, Any]],
    *,
    cve_dir: str | Path | None = None,
    max_findings: int = 500,
) -> Dict[str, Any]:
    """Match BugWolf findings against offline CVE records using NLP.

    This is adapted from TaintRadar's final-stage CVE cross-referencing: after
    the backward traversal identifies vulnerable paths, the system uses
    multi-layered NLP (product, version, class, parameter, file-name matching)
    to separate known-CVE from potentially-novel findings.

    This adapter is deliberately offline and uses only locally loaded CVE data;
    it never contacts a remote CVE database or claims a finding is novel.
    """
    index = _load_cve_index(cve_dir)
    rows = [dict(item) for item in findings if isinstance(item, Mapping)][:max_findings]

    matches: List[Dict[str, Any]] = []
    for finding in rows:
        finding_id = str(finding.get("finding_id") or finding.get("id")
                        or _safe_id(finding.get("title", "")))
        finding_text = " ".join(str(v) for v in finding.values())
        best: Dict[str, Any] | None = None
        for cve_id, cve_record in index.items():
            result = _cve_match_score(finding_text, cve_record)
            if result["score"] <= 0:
                continue
            if best is None or result["score"] > best["score"]:
                best = {
                    "cve_id": cve_id,
                    "score": result["score"],
                    "signals": result["signals"],
                    "cve_description": _clean(cve_record.get("description", ""), 500),
                }
        match_status = "known_cve_candidate" if best and best["score"] >= 6.0 else (
            "potential_novelty" if best and best["score"] >= 3.0 else
            "no_significant_match")
        matches.append({
            "finding_id": finding_id,
            "status": match_status,
            "best_cve": best,
            "cve_index_size": len(index),
        })

    known = sum(1 for m in matches if m["status"] == "known_cve_candidate")
    potential = sum(1 for m in matches if m["status"] == "potential_novelty")
    unmatched = sum(1 for m in matches if m["status"] == "no_significant_match")

    return {
        "schema": SCHEMA,
        "source": "TaintRadar CVE-matching NLP methodology",
        "offline": True,
        "cve_index_size": len(index),
        "matches": matches,
        "stats": {
            "total": len(matches),
            "known_cve_candidates": known,
            "potential_novelty": potential,
            "no_significant_match": unmatched,
        },
        "taintrader_note": (
            "A match or a high score is a retrieval signal, not proof the finding "
            "is the CVE. Manual verification against the CVE's actual affected "
            "product, version, and trigger is mandatory before any claim."
        ),
        "policy": "Matches are planning signals only; novelty claims require root cause, trigger, impact, dedup, and human review.",
    }


# ---------------------------------------------------------------------------
# CauSec-derived crypto-API misuse analysis (2608.18876)
# ---------------------------------------------------------------------------

_CRYPTO_MISUSE_PATTERNS: Sequence[Tuple[str, str, str, str, str]] = (
    (r"(?i)(md5|sha1)\s*\(", "weak_hash", "Weak cryptographic hash (MD5/SHA-1)", "high",
     "MD5 and SHA-1 are broken; use SHA-256 or SHA-3."),
    (r"(?i)(DES|3DES|RC4|RC2|Blowfish)\b", "weak_cipher", "Weak or deprecated cipher", "critical",
     "DES/3DES/RC4 are cryptographically broken; use AES-256-GCM."),
    (r"(?i)(ECBMode|Cipher\.getInstance.*ECB|AES/ECB)", "ecb_mode", "ECB cipher mode", "critical",
     "ECB mode leaks plaintext structure; use GCM or CBC with authentication."),
    (r"(?i)(random\s*\(\)|Math\.random|rand\s*\(\)|mt_rand)", "weak_random", "Weak random number generator", "high",
     "Non-cryptographic RNG produces predictable values; use SecureRandom or os.urandom."),
    (r"(?i)(predictable.*IV|fixed.*IV|constant.*IV|IV\s*=\s*0|IV\s*=\s*\"\")", "predictable_iv", "Predictable or fixed IV", "critical",
     "A fixed or predictable IV breaks authenticated encryption; generate a fresh random IV per encryption."),
    (r"(?i)(hardcoded.*key|key\s*=\s*\"[^\"]{8,}\"|secret\s*=\s*\"[^\"]{8,}\"|password\s*=\s*\"[^\"]{8,}\")", "hardcoded_key", "Hardcoded cryptographic key or secret", "critical",
     "Hardcoded keys are extractable from binaries and source; use a key management service."),
    (r"(?i)(RSA.*512|RSA.*1024|EC.*small|P-192|secp192)", "weak_key_size", "Weak key size for asymmetric cryptography", "high",
     "RSA-1024 and P-192 are below current security margins; use RSA-2048+ or P-256+."),
    (r"(?i)(PKCS1Padding|PKCS5Padding|OAEPWithSHA-?1)", "weak_padding", "Weak or deprecated padding scheme", "high",
     "PKCS#1 v1.5 padding is vulnerable to padding oracle attacks; use OAEP with SHA-256."),
    (r"(?i)(certificate.*verify.*false|trust.*all.*certs|allow.*all.*hostnames|verify_peer\s*=\s*false|verify\s*=\s*False)", "tls_verification_disabled", "TLS certificate verification disabled", "critical",
     "Disabling certificate verification enables MITM attacks; always verify in production."),
    (r"(?i)(SSLSocketFactory\.ALLOW_ALL|HostnameVerifier.*true|ssl.*verify.*none|check_hostname\s*=\s*False)", "hostname_bypass", "TLS hostname verification bypassed", "critical",
     "Bypassing hostname verification enables server impersonation; always verify hostnames."),
    (r"(?i)(keystore.*password.*=.*[\"'][^\"']{3,}|truststore.*password)", "keystore_password", "Keystore password in source", "critical",
     "Keystore passwords in source are extractable; use environment-specific secure storage."),
    (r"(?i)(hashlib\.pbkdf2|bcrypt|scrypt|argon2)", "strong_kdf", "Strong key derivation function", "positive",
     "Confirmed use of a secure KDF — verify iteration count and salt uniqueness."),
)


def analyze_crypto_misuse(
    source_text: str,
    *,
    source_label: str = "artifact",
) -> Dict[str, Any]:
    """Offline crypto-API misuse analysis using CauSec's catalogued assumption patterns.

    CauSec identified 57 crypto-API misuse assumptions across SAST tools;
    this adapter detects the most actionable subset in supplied source text.
    Positive signals (strong KDF, etc.) are reported alongside negatives.
    """
    text = str(source_text or "")
    findings: List[Dict[str, Any]] = []
    for pattern, category, title, severity, rationale in _CRYPTO_MISUSE_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append({
                "finding_id": "crypto-misuse-" + _hash(source_label + "|" + str(match.start()))[:16],
                "category": category,
                "title": title,
                "severity": severity,
                "rationale": rationale,
                "span": f"{match.start()}-{match.end()}",
                "preview": _clean(match.group(), 200),
                "source": source_label,
                "status": "static_signal_human_review_required",
            })
    findings.sort(key=lambda item: (
        {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "positive": -1}[item["severity"]],
        item["title"],
    ), reverse=True)
    critical = sum(1 for item in findings if item["severity"] == "critical")
    return {
        "schema": SCHEMA,
        "source": "CauSec crypto-API misuse methodology (2608.18876)",
        "offline": True,
        "source_label": source_label,
        "findings": findings,
        "stats": {"total": len(findings), "critical": critical},
        "cauSec_note": (
            "CauSec catalogued 57 crypto-API misuse assumptions across SAST tools; "
            "this adapter covers the 11 most actionable pattern classes. Positive "
            "signals (strong KDF use) are included to avoid false-confidence."
        ),
        "policy": "Static signals require source inspection and key-management review; no key material is extracted or tested.",
    }


# ---------------------------------------------------------------------------
# ATT&CK / CWE enrichment adapter (2608.16187)
# ---------------------------------------------------------------------------

_ATTACK_CWE_MAP: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "attack_technique": "T1190",
        "attack_name": "Exploit Public-Facing Application",
        "cwe": "CWE-89",
        "cwe_description": "Improper Neutralization of Special Elements used in an SQL Command",
        "mitigation": "Use parameterized queries and stored procedures; never concatenate input into SQL.",
    },
    "xss-reflected": {
        "attack_technique": "T1189",
        "attack_name": "Drive-by Compromise",
        "cwe": "CWE-79",
        "cwe_description": "Improper Neutralization of Input During Web Page Generation",
        "mitigation": "Apply context-appropriate output encoding; use CSP headers; validate input.",
    },
    "xss-stored": {
        "attack_technique": "T1189",
        "attack_name": "Drive-by Compromise",
        "cwe": "CWE-79",
        "cwe_description": "Improper Neutralization of Input During Web Page Generation (Stored)",
        "mitigation": "Encode on output; validate and sanitize on input; CSP with nonce-based scripts.",
    },
    "command_injection": {
        "attack_technique": "T1059",
        "attack_name": "Command and Scripting Interpreter",
        "cwe": "CWE-78",
        "cwe_description": "Improper Neutralization of Special Elements used in an OS Command",
        "mitigation": "Use fixed argv arrays; never invoke a shell with user input; allowlist commands.",
    },
    "ssti": {
        "attack_technique": "T1059",
        "attack_name": "Command and Scripting Interpreter",
        "cwe": "CWE-94",
        "cwe_description": "Improper Control of Generation of Code",
        "mitigation": "Use logic-less templates; sandbox template evaluation; never expose eval-capable engines.",
    },
    "path-traversal": {
        "attack_technique": "T1005",
        "attack_name": "Data from Local System",
        "cwe": "CWE-22",
        "cwe_description": "Improper Limitation of a Pathname to a Restricted Directory",
        "mitigation": "Canonicalize and validate paths against a fixed root; reject traversal sequences.",
    },
    "rce": {
        "attack_technique": "T1059",
        "attack_name": "Command and Scripting Interpreter",
        "cwe": "CWE-78",
        "cwe_description": "Improper Neutralization of Special Elements used in an OS Command",
        "mitigation": "Avoid user-controlled command execution; sandbox interpreters; use allowlisted APIs.",
    },
    "idor": {
        "attack_technique": "T1078",
        "attack_name": "Valid Accounts",
        "cwe": "CWE-639",
        "cwe_description": "Authorization Bypass Through User-Controlled Key",
        "mitigation": "Authorize every resource access against the requesting identity; avoid guessable IDs.",
    },
    "ssrf": {
        "attack_technique": "T1190",
        "attack_name": "Exploit Public-Facing Application",
        "cwe": "CWE-918",
        "cwe_description": "Server-Side Request Forgery",
        "mitigation": "Validate and allowlist destination hosts; disable internal-network routing; use a proxy layer.",
    },
    "open-redirect": {
        "attack_technique": "T1204",
        "attack_name": "User Execution",
        "cwe": "CWE-601",
        "cwe_description": "URL Redirection to Untrusted Site",
        "mitigation": "Validate redirect targets against an allowlist; use relative redirects; warn on external navigation.",
    },
    "deserialization": {
        "attack_technique": "T1059",
        "attack_name": "Command and Scripting Interpreter",
        "cwe": "CWE-502",
        "cwe_description": "Deserialization of Untrusted Data",
        "mitigation": "Use data-only formats (JSON Schema); enforce strict class allowlists; never deserialize untrusted input.",
    },
    "xxe": {
        "attack_technique": "T1190",
        "attack_name": "Exploit Public-Facing Application",
        "cwe": "CWE-611",
        "cwe_description": "Improper Restriction of XML External Entity Reference",
        "mitigation": "Disable external entity resolution and DTD processing; use a hardened parser or JSON.",
    },
    "prototype-pollution": {
        "attack_technique": "T1059",
        "attack_name": "Command and Scripting Interpreter",
        "cwe": "CWE-1321",
        "cwe_description": "Improperly Controlled Modification of Object Prototype Attributes",
        "mitigation": "Freeze prototypes; use Map instead of plain objects; validate and sanitize merge operations.",
    },
    "cache-poisoning": {
        "attack_technique": "T1557",
        "attack_name": "Adversary-in-the-Middle",
        "cwe": "CWE-444",
        "cwe_description": "Inconsistent Interpretation of HTTP Requests",
        "mitigation": "Use consistent cache-key construction; normalize headers; separate cache per host/port/scheme.",
    },
    "request-smuggling": {
        "attack_technique": "T1190",
        "attack_name": "Exploit Public-Facing Application",
        "cwe": "CWE-444",
        "cwe_description": "Inconsistent Interpretation of HTTP Requests",
        "mitigation": "Use HTTP/2 end-to-end; disable connection reuse across trust boundaries; normalize delimiters.",
    },
    "jwt-bypass": {
        "attack_technique": "T1078",
        "attack_name": "Valid Accounts",
        "cwe": "CWE-287",
        "cwe_description": "Improper Authentication",
        "mitigation": "Validate algorithm against a whitelist; verify signature with the correct key; reject 'none' alg.",
    },
}


def enrich_finding_attack(
    finding: Mapping[str, Any],
    *,
    include_best_practices: bool = True,
) -> Dict[str, Any]:
    """Enrich a BugWolf finding with MITRE ATT&CK technique and CWE metadata.

    Adapted from the JIT pipeline in 2608.16187: after detection (static + LLM),
    findings are enriched with threat intelligence context before remediation.
    This adapter is offline and uses only the local ATT&CK/CWE mapping table.
    """
    data = dict(finding)
    bug_class = str(data.get("bug_class") or data.get("class") or "").lower()
    enrichment = _ATTACK_CWE_MAP.get(bug_class, {})

    result: Dict[str, Any] = {
        "finding_id": str(data.get("finding_id") or data.get("id") or _safe_id(data.get("title", ""))),
        "bug_class": bug_class,
        "enrichment": {
            "attack_technique": enrichment.get("attack_technique", "TBD"),
            "attack_name": enrichment.get("attack_name", "Unknown"),
            "cwe": enrichment.get("cwe", "TBD"),
            "cwe_description": enrichment.get("cwe_description", "Unknown vulnerability class"),
            "mitigation": enrichment.get("mitigation", "Manual review required."),
        },
        "fix_verify_loop": [
            "apply_mitigation",
            "re_scan_with_static_analyzer",
            "re_validate_with_oracle",
            "check_for_new_vulnerabilities",
            "update_verdict_consistency",
        ],
        "churn_warning": (
            "Pipeline-based remediation introduces new vulnerabilities in 15-22% of cases; "
            "always re-scan after applying a fix."
        ),
        "status": "enriched_offline_plan_only",
    }

    if include_best_practices and enrichment:
        result["best_practices"] = [
            f"OWASP: {enrichment.get('cwe_description', '')}",
            f"MITRE ATT&CK: {enrichment.get('attack_technique')} - {enrichment.get('attack_name')}",
            "Verify fix does not introduce regression or new vulnerability (15-22% churn rate).",
            "Ground enrichment in real application context, not only the vulnerability label.",
        ]

    return result


# ---------------------------------------------------------------------------
# SETYPE-derived semantic-name vulnerability inference (2608.14533)
# ---------------------------------------------------------------------------

_SEMANTIC_TYPE_HINTS: Sequence[Tuple[str, Sequence[str], str, str]] = (
    ("credential_operation", ("password", "secret", "token", "api_key", "private_key", "credential", "auth_key"),
     "high", "Variable/func name suggests credential handling — verify encryption, storage, and access control."),
    ("admin_operation", ("admin", "root", "superuser", "privileged", "sudo", "elevated"),
     "high", "Name suggests elevated privilege — verify authorization check before execution."),
    ("user_input_operation", ("input", "param", "query", "request", "body", "form", "payload", "user_", "arg"),
     "medium", "Name suggests user-controlled input — verify sanitization and validation."),
    ("database_operation", ("sql", "query", "execute", "fetch", "insert", "delete", "update", "select", "cursor", "db_"),
     "high", "Name suggests database operation — verify parameterization and least-privilege access."),
    ("file_operation", ("file", "path", "dir", "upload", "download", "read", "write", "open", "save", "load"),
     "medium", "Name suggests filesystem operation — verify path sanitization and permission boundaries."),
    ("network_operation", ("http", "url", "host", "connect", "socket", "fetch", "request", "response", "redirect"),
     "medium", "Name suggests network operation — verify scope, TLS, and destination allowlisting."),
    ("command_operation", ("exec", "cmd", "shell", "system", "popen", "subprocess", "spawn", "run"),
     "critical", "Name suggests command execution — verify argv isolation and argument allowlisting."),
    ("crypto_operation", ("encrypt", "decrypt", "hash", "sign", "verify", "cipher", "digest", "hmac", "rsa", "aes"),
     "high", "Name suggests cryptographic operation — verify algorithm choice and key management."),
    ("serialization_operation", ("serialize", "deserialize", "marshal", "unmarshal", "pickle", "json", "xml"),
     "medium", "Name suggests serialization — verify schema validation and safe parser configuration."),
    ("access_control_operation", ("auth", "login", "logout", "permission", "role", "access", "allow", "deny", "gate"),
     "high", "Name suggests access control — verify enforcement point and bypass testing."),
)


def infer_semantic_types(
    source_text: str,
    *,
    source_label: str = "artifact",
) -> Dict[str, Any]:
    """Infer vulnerability-relevant semantics from variable and function names.

    Adapted from SETYPE (2608.14533): the insight is that names encode
    developer intent — a variable named `password` or `admin_cmd` signals
    a security boundary that must be verified. LLM-augmented type-checking
    (SETYPE's core technique) requires model access; this offline adapter
    uses pattern-based semantic classification as a planning signal.
    """
    text = str(source_text or "")
    # Extract variable and function identifiers
    identifiers = set(re.findall(
        r"\b(?:var\s+|let\s+|const\s+|def\s+|function\s+|class\s+)?"
        r"([a-zA-Z_][a-zA-Z0-9_]{2,40})\b", text))

    signals: List[Dict[str, Any]] = []
    for category, hints, severity, rationale in _SEMANTIC_TYPE_HINTS:
        matched = [name for name in identifiers
                   if any(hint.lower() in name.lower() for hint in hints)]
        if matched:
            signals.append({
                "category": category,
                "matched_identifiers": sorted(matched)[:20],
                "count": len(matched),
                "severity": severity,
                "rationale": rationale,
                "setype_insight": (
                    "SETYPE: semantic names encode developer intent — a name "
                    "carrying security semantics signals a boundary that must "
                    "be verified. An LLM-powered type-checker would flag "
                    "type mismatches at these boundaries."
                ),
            })

    signals.sort(key=lambda item: (
        {"critical": 4, "high": 3, "medium": 2, "low": 1}[item["severity"]],
        -item["count"],
    ), reverse=True)

    return {
        "schema": SCHEMA,
        "source": "SETYPE semantic-name vulnerability inference methodology (2608.14533)",
        "offline": True,
        "source_label": source_label,
        "identifiers_found": len(identifiers),
        "semantic_signals": signals,
        "setype_note": (
            "SETYPE used LLMs to derive a full type system from names and "
            "check for type-mismatch vulnerabilities. This offline adapter "
            "provides pattern-based semantic classification only; the LLM "
            "type-checking step requires model access and is not included."
        ),
        "policy": "Name-based signals are hypotheses; manual source review is required for each boundary.",
    }


# ---------------------------------------------------------------------------
# DistScan-derived output distribution integrity check (2608.19088)
# ---------------------------------------------------------------------------


def check_output_distribution_integrity(
    outputs: Iterable[Mapping[str, Any]],
    *,
    baseline_frequencies: Mapping[str, float] | None = None,
    threshold: float = 0.25,
    max_outputs: int = 10_000,
) -> Dict[str, Any]:
    """Check whether a system's output class distribution has shifted from baseline.

    Inspired by DistScan (2608.19088): a backdoored model systematically shifts
    its internal prediction distribution away from training frequencies, even on
    clean inputs. This adapter generalizes the concept to any structured output
    stream (LLM tool calls, classification labels, action distributions) and
    flags significant deviations.

    Applicable to: LLM agent tool-call distributions, model output labels,
    scanner findings by severity, discovery scheduler mutation distribution.
    """
    rows = [dict(item) for item in outputs if isinstance(item, Mapping)][:max_outputs]
    if not rows:
        return {
            "schema": SCHEMA,
            "source": "DistScan output distribution integrity methodology (2608.19088)",
            "offline": True,
            "error": "no outputs to analyze",
        }

    # Determine the class-like field: first key named 'class', 'type', 'action', 'severity', 'category'
    class_field = next((key for key in ("class", "type", "action", "severity", "category", "label")
                        if any(key in row for row in rows)), None)
    if not class_field:
        class_field = next(iter(rows[0].keys()))

    observed: Counter[str] = Counter()
    for row in rows:
        value = str(row.get(class_field, "")).strip()
        if value:
            observed[value] += 1

    total = sum(observed.values())
    distribution = {k: round(v / total, 4) for k, v in observed.most_common()}

    shift_signals: List[Dict[str, Any]] = []
    if baseline_frequencies:
        for cls_name, baseline_freq in baseline_frequencies.items():
            observed_freq = distribution.get(cls_name, 0.0)
            delta = abs(observed_freq - baseline_freq)
            if delta > threshold:
                shift_signals.append({
                    "class": cls_name,
                    "baseline": round(baseline_freq, 4),
                    "observed": observed_freq,
                    "delta": round(delta, 4),
                    "severity": "high" if delta > threshold * 2 else "medium",
                })

    shift_detected = len(shift_signals) > 0
    shift_signals.sort(key=lambda item: -item["delta"])

    return {
        "schema": SCHEMA,
        "source": "DistScan output distribution integrity methodology (2608.19088)",
        "offline": True,
        "class_field": class_field,
        "total_outputs": len(rows),
        "unique_classes": len(distribution),
        "distribution": distribution,
        "baseline_supplied": baseline_frequencies is not None,
        "shift_detected": shift_detected,
        "shift_signals": shift_signals,
        "distscan_note": (
            "DistScan detects backdoors by comparing pre-NMS class distribution "
            "against training frequencies without trigger knowledge. This "
            "adapter applies the same principle to any structured output stream. "
            "A shift is a signal, not proof of compromise."
        ),
        "policy": "A distribution shift is a hypothesis requiring independent investigation; it does not establish backdoor presence or compromise.",
    }


def _load_json_value(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _load_json_records(path: Path) -> List[Dict[str, Any]]:
    value = _load_json_value(path)
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        return [dict(value)]
    records = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, Mapping):
                records.append(dict(value))
        except json.JSONDecodeError:
            continue
    return records


def render_paper_intelligence_map(result: Mapping[str, Any]) -> str:
    """Render a compact, non-sensitive markdown handoff for the five maps."""
    lines = [
        "# Paper Intelligence Handoff",
        "",
        "This map is generated from operator-supplied local artifacts. It is an",
        "offline planning handoff, not attribution, authorization, or a finding.",
        "",
        "| Adapter | Status | Summary |",
        "|---|---|---|",
    ]
    traffic = result.get("https_fingerprint")
    if isinstance(traffic, Mapping):
        unknown = sum(item.get("decision") == "unknown" for item in traffic.get("retrievals", []))
        lines.append(f"| HTTPS semantic-traffic | `open_world_retrieval_only` | {len(traffic.get('traces', []))} trace(s); {unknown} unknown decision(s); metadata-only |")
    agent = result.get("agent_control_plane")
    if isinstance(agent, Mapping):
        gaps = agent.get("control_gaps", [])
        critical = sum(item.get("severity") == "critical" for item in gaps if isinstance(item, Mapping))
        high = sum(item.get("severity") == "high" for item in gaps if isinstance(item, Mapping))
        lines.append(f"| Agent control plane | `offline_plan_only` | {agent.get('agents_seen', 0)} agent(s); {len(gaps)} gap(s); {critical} critical, {high} high |")
    if len(lines) == 7:
        lines.append("| None | `not_present` | No automatic HTTPS or Agent control-plane artifact was supplied. |")
    lines.extend([
        "",
        "## Required review",
        "",
        "- Keep traffic matches as privacy-risk hypotheses and preserve unknown results.",
        "- Validate Agent identity, data, tool, memory, telemetry, grounding, and response controls with owners and synthetic fixtures.",
        "- Do not use this handoff to monitor unrelated users, decrypt traffic, change permissions, or authorize active testing.",
        "",
    ])
    return "\n".join(lines)


def build_artifact_intelligence_report(
    *,
    https_traffic_file: str | Path | None = None,
    site_profiles_file: str | Path | None = None,
    agent_control_plane_file: str | Path | None = None,
    output_dir: str | Path | None = None,
    map_output: str | Path | None = None,
) -> Dict[str, Any]:
    """Build the automatic recon/maps handoff from supplied local artifacts.

    This narrow helper is shared by the staged controller and recon shell path.
    It does not discover files, fetch profiles, or execute any target-facing
    operation; callers must provide the already-authorized local artifact paths.
    """
    result: Dict[str, Any] = {"schema": SCHEMA, "offline": True, "papers": PAPER_CATALOG}
    if https_traffic_file:
        traffic_path = Path(https_traffic_file)
        profiles: List[Dict[str, Any]] = []
        if site_profiles_file:
            profile_path = Path(site_profiles_file)
            profile_value = _load_json_value(profile_path)
            profiles = profile_value if isinstance(profile_value, list) else _load_json_records(profile_path)
        result["https_fingerprint"] = analyze_https_fingerprint(
            _load_json_records(traffic_path), profiles,
        )
    if agent_control_plane_file:
        agent_path = Path(agent_control_plane_file)
        artifact = _load_json_value(agent_path)
        if artifact is None:
            artifact = _load_json_records(agent_path)
        result["agent_control_plane"] = assess_agent_control_plane(artifact)
    if output_dir is not None:
        output = Path(output_dir).expanduser().resolve()
        output.mkdir(parents=True, exist_ok=True)
        (output / "paper-intelligence.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + chr(10), encoding="utf-8",
        )
    if map_output is not None:
        map_path = Path(map_output).expanduser().resolve()
        map_path.parent.mkdir(parents=True, exist_ok=True)
        map_path.write_text(render_paper_intelligence_map(result), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf offline research-derived intelligence adapters")
    parser.add_argument("--skill-root")
    parser.add_argument("--provenance-file")
    parser.add_argument("--auth-events-file")
    parser.add_argument("--cti-file")
    parser.add_argument("--binary-metadata")
    parser.add_argument("--failure-traces")
    parser.add_argument("--https-traffic-file", help="JSON/JSONL passive packet/flow metadata for semantic-traffic analysis")
    parser.add_argument("--site-profiles-file", help="JSON/JSONL site logic profiles for passive retrieval hypotheses")
    parser.add_argument("--agent-control-plane-file", help="JSON export of agent identity/data/tool/memory/telemetry/response controls")
    parser.add_argument("--candidates-file", help="JSON/JSONL vulnerability candidates for ranking/claim assessment")
    parser.add_argument("--cold-start-context", help="JSON context for cold-start ranking")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--map-output", help="write a compact maps/paper-intelligence.md handoff")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    output = Path(args.output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    result: Dict[str, Any] = {"schema": SCHEMA, "offline": True, "papers": PAPER_CATALOG}
    if args.skill_root:
        result["skill_chain"] = scan_skill_chain(args.skill_root)
    if args.provenance_file:
        result["provenance"] = investigate_provenance(_load_json_records(Path(args.provenance_file)))
    if args.auth_events_file:
        result["authentication"] = analyze_authentication_events(_load_json_records(Path(args.auth_events_file)))
    if args.cti_file:
        path = Path(args.cti_file)
        result["cti_sigma"] = ground_cti_to_sigma(path.read_text(encoding="utf-8", errors="replace"), str(path))
    if args.binary_metadata:
        result["binary_re"] = plan_binary_re_tasks(json.loads(Path(args.binary_metadata).read_text(encoding="utf-8")))
    if args.failure_traces:
        result["defense_evolution"] = evolve_defenses(_load_json_records(Path(args.failure_traces)))
    if args.https_traffic_file:
        profiles = []
        if args.site_profiles_file:
            profile_value = _load_json_value(Path(args.site_profiles_file))
            profiles = profile_value if isinstance(profile_value, list) else _load_json_records(Path(args.site_profiles_file))
        result["https_fingerprint"] = analyze_https_fingerprint(
            _load_json_records(Path(args.https_traffic_file)), profiles,
        )
    if args.agent_control_plane_file:
        artifact = _load_json_value(Path(args.agent_control_plane_file))
        if artifact is None:
            artifact = _load_json_records(Path(args.agent_control_plane_file))
        result["agent_control_plane"] = assess_agent_control_plane(artifact)
    if args.candidates_file:
        candidates = _load_json_records(Path(args.candidates_file))
        context = {}
        if args.cold_start_context:
            context = json.loads(Path(args.cold_start_context).read_text(encoding="utf-8"))
        result["cold_start_ranking"] = rank_cold_start_candidates(candidates, context)
        result["zero_day_claims"] = assess_zero_day_claims(candidates)
    (output / "paper-intelligence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.map_output:
        map_path = Path(args.map_output).expanduser().resolve()
        map_path.parent.mkdir(parents=True, exist_ok=True)
        map_path.write_text(render_paper_intelligence_map(result), encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps({"schema": SCHEMA, "output": str(output / "paper-intelligence.json"), "sections": sorted(key for key in result if key not in {"schema", "offline", "papers"})}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
