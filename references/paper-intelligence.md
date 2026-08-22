# Research-Derived Paper Intelligence

BugWolf includes `tools/paper_intel.py`, an offline adapter for transferable
ideas from the supplied August 2026 papers and framework notes. It produces
planning signals, provenance summaries, detection plans, binary-analysis task
queues, privacy metadata assessments, Agent control-plane gaps, and quarantined
defense candidates. It does not execute commands, contact targets, run
binaries, generate exploit payloads, evade scanners, capture/decrypt traffic,
or self-modify source.

## Paper map

| Source | Main objective | Transferable technique | BugWolf integration |
|---|---|---|---|
| `2608.19938` | Endpoint-specific authentication anomaly detection | Curated normal/borderline/anomalous labels, structured classification, endpoint context | `analyze_authentication_events()` keeps borderline anomalies for analyst review |
| `2608.19750` | Efficient multi-stage APT investigation over provenance graphs | Information-bottleneck nodes, temporal relevance, causal expansion, stage characterization | `investigate_provenance()` ranks target-local bottlenecks, temporal chains, and cross-entity fingerprints |
| `2608.19190` | Malicious URL identification from signed link relationships | Signed URL graph, edge-sign propagation, interpretable majority inference | Passive URL-relationship hypothesis source; no reputation score is treated as proof |
| `2608.19011` | CTI-to-Sigma rule generation | Knowledge enrichment, template grounding, validation/judge loop, ATT&CK coverage | `ground_cti_to_sigma()` emits schema-aware, offline Sigma plans with false-positive review |
| `2608.19052` | Multimodal malware classification | Text/image/graph/audio representations and adaptive fusion | `plan_binary_re_tasks()` reports modality coverage; it does not classify or execute malware |
| `2608.18686` | Local LLM SSH honeypot fidelity | Prompt structure, supervised adaptation, fresh-session tests, malformed-state tests | Isolated-lab evaluator criteria only; no deception or stealth deployment is automated |
| `2608.15012` | Safe attack-defense co-evolution in realistic ranges | Range construction, bounded attack schemes, interpretable defense, post-access bottlenecks | Lab-only scenario queues and continuation metrics; live targets remain gated |
| `2608.08468` | Static-analysis boundaries for malicious agent skills | Pattern density, anomaly, taint, import anomaly, capability mismatch | `scan_skill_chain()` adds cross-skill composition analysis and semantic-review flags |
| `2608.09732` | Cross-skill composition that evades individual scanners | Dependency, artifact flow, capability composition, execution handoff analysis | `scan_skill_chain()` detects risks emerging only across installed skill units |
| `2608.11469` | Contamination-free realistic binary RE benchmarking | Unseen artifacts, anti-analysis variants, deterministic grading, cross-view validation | `plan_binary_re_tasks()` blocks known-hash shortcuts and requires independent evidence views |
| `2608.11802` | Model-based runtime attack identification | Independent observation, attack trees, control-flow corroboration | Provenance and detection artifacts preserve corroboration gaps instead of upgrading confidence automatically |
| `2608.12977` | Self-evolving runtime defense for LLM agents | Harness interventions, failure-trace feedback, utility/security regression | `evolve_defenses()` creates quarantined candidates with regression tests; source is never auto-mutated |
| `2608.19568` | Day-zero ranking before outcome data exists | Frozen identity-independent public features, withheld evaluation, cryptographic forecast sealing | `rank_cold_start_candidates()` prioritizes unseen hypotheses and seals the ranking; later evidence is mandatory |
| `2605.03138` | Distinguish novel behavior from novel vulnerability | Incident-derived taxonomy, vulnerability-centric assessment, cautious zero-day claims | `assess_zero_day_claims()` blocks behavior-only overclaiming and requires root cause, trigger, impact, novelty, and human review |
| `2607.16456` | Semantic-aware taint-style vulnerability detection via augmented CPGs | Vulnerability-typed sanitization lattice, DB-schema-aware cross-script taint edges, object-aware reaching definitions, CVE-matching NLP | `analyze_taint_flow()` provides per-vuln-class sanitization and DB persistence planning; `match_cve_candidates()` performs layered NLP CVE matching; `chain_analyzer.py` has DB-persistence chain rules |
| `2608.19680` | Continual learning for smart contract vulnerability detection with LLMs | FA-LoRA (Fourier-domain low-rank adaptation), Forget-Aware Replay, Anchor-Protected Progressive Merging | Catalog only (requires LLM access and continual-learning infrastructure) |
| `2608.19674` | Escaping the Quicksand: A Call to Arms | Executable partial specifications as test oracles, specification-testing continuum, incremental specification co-development | `build_specification_plans()` in `methodology_playbook.py` generates precondition/postcondition/invariant/boundary/failure-mode specification hypotheses |
| `2608.19088` | Backdoor detection via pre-NMS prediction distribution shift (DistScan) | Class-frequency baseline comparison, zero-trigger detection, no model-weight access required | `check_output_distribution_integrity()` in `paper_intel.py` detects distribution shifts in any structured output stream |
| `2608.18976` | Catastrophic Learning attack on continual learning networks | Learning blocker taxonomy, attraction/repulsion feature-space manipulation, coincident/preceding temporal variants | Catalog only (requires continual-learning architecture; BugWolf's adaptive_learning.py is append-only with human review) |
| `2608.18876` | Causal drivers of SAST performance (CauSec) | Causal assumption modeling, 57 crypto-API misuse assumptions catalogued, assumption validation framework | `analyze_crypto_misuse()` in `paper_intel.py` and crypto-API rules in `chain_analyzer.py` detect 11 most actionable misuse patterns |
| `2608.18095` | Backdoor learning in language models and vision-language models | Backdoor taxonomy for NLP/VLMs, trigger detection, defense evaluation | Catalog only (doctoral dissertation; BugWolf uses signal patterns for LLM supply-chain checklist) |
| `2608.16970` | Probing the Prefill: detecting code vulnerabilities via latent activations | Last-prefill-token activation probing, sub-0.2% parameter probe MLPs, cross-model frozen-LLM evaluation | Catalog only (requires direct LLM weight access; BugWolf cannot probe activations) |
| `2608.16187` | Securing AI-Generated Code JIT pipeline | CodeQL+Bandit+LLM parallel validation, ATT&CK/CWE enrichment, fix-verify loop, dual-pipeline comparison | `enrich_finding_attack()` in `paper_intel.py` adds MITRE ATT&CK + CWE metadata to findings with fix-verify loop planning |
| `2608.15184` | Pre-model representation failures in GNN smart contract detectors | Graph-deduplication test, variable-whitelist audit, C-node isolation check, controlled misclassification reproduction | Contract representation validation checklist for `contract_discovery.py` |
| `2608.15151` | SAEFUZZ: statically guided evolutionary fuzzing for smart contracts | Bytecode CFG extraction, function-selector recovery, storage-dependency ordering, 5 dedicated runtime oracles | 5 contract vulnerability oracle templates (reentrancy, overflow, block-state, delegatecall, frozen-Ether) for `contract_discovery.py` |
| `2608.14533` | SETYPE: LLM-augmented semantics-aware type-checking for vulnerability detection | Semantic type inference from variable/function name meanings, LLM-powered type checking, 9 developer-confirmed zero-days | `infer_semantic_types()` in `paper_intel.py` provides pattern-based semantic-name classification as vulnerability boundary signals |
| `STAR-INFOCOM-2026` | Zero-shot HTTPS website fingerprinting from encrypted traffic structure | Semantic-traffic alignment, URI/resource/protocol anchors, open-world retrieval, unknown rejection, paired augmentation | `analyze_https_fingerprint()` assesses only operator-supplied flow metadata and logic profiles; it never captures or attributes user traffic |
| `AGENT-SURVEY-2026` | Memory, reasoning, harness reliability, and bounded self-improvement | Adaptive memory control, temporal validity, verifier tiers, failure feedback, independent evidence channels | `evolve_defenses()` plus `assess_agent_control_plane()` preserve provenance, review, regression, and bounded evolution |
| `AGENT-CONTROL-PLANE-2026` | Connect agent identity, data, runtime, detection, response, and governance | Risk taxonomy, policy enforcement, least privilege, sandboxing, threat rules, SOC linkage | `assess_agent_control_plane()` emits vendor-neutral control gaps and a remediation handoff |Paper `2608.16187` demonstrates that AI-generated code remediation introduces
new vulnerabilities in 15-22% of cases; BugWolf's `enrich_finding_attack()`
carries this churn warning and includes the fix-verify loop as a mandatory
planning step, never an automatic application.

Paper `2608.14533` (SETYPE) reported 15 potential zero-day vulnerabilities
in Python web applications with 9 confirmed by developers, demonstrating that
LLM-augmented semantics-aware type-checking can find real-world vulnerabilities
missed by purely syntactic static analysis.

Paper `2607.16456` (TaintRadar) is under review as of July 2026 and reports
29 confirmed zero-days (26 SQLi, 3 stored XSS) across 6 real-world PHP
applications with assigned CVE IDs. Its three-layer CPG augmentation is the
first practical demonstration that DB-schema-aware persistence edges and
per-vulnerability sanitization lattices can find cross-script chains invisible
to all prior PHP static analysis tools. BugWolf adapts the sanitization and
database-awareness layers as planning signals and chain rules; the CPG-based
object-field analysis layer is not applicable to a black-box testing engine.

The last three entries identify the supplied article/framework summaries rather than
asserting that they are arXiv identifiers. Their vendor names and
framework labels are mappings, not evidence that a deployment uses a product.

## Example

```bash
python3 tools/paper_intel.py \
  --skill-root .agents/skills \
  --provenance-file state/provenance/events.jsonl \
  --auth-events-file state/auth/events.jsonl \
  --cti-file research/T/post-findings/report.txt \
  --binary-metadata recon/T/binary/metadata.json \
  --failure-traces state/failures.jsonl \
  --output-dir research/T/paper-intelligence \
  --json
```

For cold-start vulnerability research, add a JSON/JSONL candidate file:

```bash
python3 tools/paper_intel.py \
  --candidates-file state/sessions/T/findings.jsonl \
  --cold-start-context recon/T/discovery/surface.json \
  --output-dir research/T/paper-intelligence \
  --json
```

The ranking is deterministic and cryptographically sealed for later comparison,
but candidate identity, a high score, or a novel behavior does not establish a
zero-day. `zero_day_claims` separates vulnerability-centric candidates from
behavior-only anomalies and lists the evidence still required.

## Passive HTTPS metadata assessment

For a privacy assessment using an operator-provided trace export, add
`--https-traffic-file` and optionally `--site-profiles-file`:

```bash
python3 tools/paper_intel.py \
  --https-traffic-file research/T/flows.jsonl \
  --site-profiles-file research/T/site-profiles.json \
  --output-dir research/T/paper-intelligence \
  --json
```

The traffic adapter extracts direction, length buckets, HTTP version, UDP/QUIC
ratios, and three alignment-anchor summaries. It performs open-world retrieval
with an explicit unknown threshold and emits a paired augmentation plan; it
must not be used to monitor unrelated users, decrypt traffic, or make an
identity claim. The adapter expects metadata already supplied by the operator;
it does not sniff interfaces, fetch site profiles, or infer a person.

## Agent control-plane assessment

For an Agent inventory/config export, add `--agent-control-plane-file`:

```bash
python3 tools/paper_intel.py \
  --agent-control-plane-file audit/agent-inventory.json \
  --output-dir research/T/paper-intelligence \
  --json
```

The control-plane audit checks distinct identity, input provenance, tool
authorization, skill/plugin integrity, memory expiry and tenant binding, data
labels and filters, resource budgets, tamper-evident telemetry, output
grounding, and incident/policy writeback. Missing controls become offline
review tasks, never automatic permission changes. The result is a control-gap
map, not compliance certification or proof of exploitability.

All inputs are treated as untrusted data. The output is an evidence and
planning handoff, not authorization. Active validation still requires the
existing scope file, execution controller, request/time budgets, separate
state-change confirmation, provenance, and human review.

## Interpretation limits

The papers report results under specific datasets, models, or testbeds. BugWolf
records those limitations in the machine-readable catalog and does not copy
paper accuracy numbers into finding confidence. A static signal is not a
finding; a chain plan is not an exploit; a binary task is not binary execution;
a traffic correlation is not user attribution; a control gap is not a confirmed
vulnerability; and a CTI-derived Sigma rule is not a validated detection. These
distinctions are part of the output contract.
