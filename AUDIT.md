# BugWolf — Repository Audit & File Map (generated)

> Generated on 2026-09-03T11:20:56+00:00 from `main@4801a20` by `scripts/generate_audit.py`. All counts are computed from the live tree; do not edit them by hand.

## 1. Scale

- Python modules under `tools/`: **161** (67438 lines) + **13** `__init__.py` package markers.
- CLI-capable modules (argparse/`__main__`): **111**
- Group sizes: core **8**, domains **14**, intelligence **3**, recon **1**, validation **3**

## 2. Test suite

- Test files: **121**
- Discovered tests: **1252**

## 3. References

- Reference docs: **53** (8 attack-vector catalogs, 22 hacking-agent guides)

## 4. Scripts & configs

- Shell scripts under `scripts/`: **5**
- readiness level: `L1-controlled-active-researcher`
- release status: `experimental-human-supervised`

## 5. Tool map (largest modules)

| Module | Lines | Purpose |
|---|---|---|
| `tools/runtime/mission_runner.py` | 2831 | BugWolf mission runner (orchestrator plan v2, Phase 4 exit criterion). |
| `tools/core/campaign_orchestrator.py` | 2177 | BugWolf Campaign Orchestrator — APT Commander (Stage 2 rebuild). |
| `tools/paper_intel.py` | 2096 | Offline adapters derived from the supplied 2026 security papers. |
| `tools/hunt.py` | 1467 | BugWolf Hunt Engine — Auth-aware vulnerability scanner. |
| `tools/core/research_loop.py` | 1445 | BugWolf Mandatory Deep-Research Loop v1.0.0 |
| `tools/zero_day.py` | 1398 | BugWolf potentially-novel vulnerability research orchestrator. |
| `tools/research_thread.py` | 1012 | BugWolf Research Thread System — self-driven research units. |
| `tools/campaign.py` | 964 | BugWolf Campaign State Engine — self-driven APT-level research persistence. |
| `tools/core/stage_controller.py` | 953 | Persistent no-skip workflow controller for BugWolf (APT Commander, Stage 2). |
| `tools/kill_chain.py` | 907 | BugWolf Autonomous Kill Chain Builder v1.0.0 |
| `tools/ledger.py` | 904 | BugWolf Ledger Verifier v1.0.0 |
| `tools/surface_model.py` | 869 | Structured Web/API attack-surface model for BugWolf's discovery core. |
| `tools/observation.py` | 861 | BugWolf Observation / Oracle Validation Layer v1.0.0 |
| `tools/core/live_executor.py` | 822 | BugWolf Live Execution Harness — real probes, real evidence. |
| `tools/patch_gap.py` | 806 | BugWolf Patch-Gap Exploitation Engine v1.0.0 |
| `tools/leads.py` | 796 | BugWolf Lead Ledger — persistent state-transition research objects for OPEN LEADs. |
| `tools/infra_deploy.py` | 763 | BugWolf Infrastructure Auto-Deploy v1.0.0 |
| `tools/carlini_loop.py` | 752 | BugWolf Carlini Loop Track — per-file brute-force vulnerability analysis. |
| `tools/capability_registry.py` | 733 | BugWolf Capability Registry v1.0.0 |
| `tools/trust_map.py` | 720 | BugWolf Trust Map Engine v1.0.0 |
| `tools/agent_isolation.py` | 711 | Agent Isolation Checker — verifies each BugWolf agent operates within |
| `tools/adversary_emulation.py` | 699 | BugWolf Adversary Emulation Framework v1.0.0 |
| `tools/header_trust.py` | 679 | Header-trust / proxy-trust analysis for BugWolf's discovery core. |
| `tools/validation/self_eval_harness.py` | 667 | BugWolf Self-Evaluation Harness — AutoPenBench-style milestone scoring. |
| `tools/threat_intel.py` | 659 | BugWolf Threat Intelligence Module v1.0.0 |
| `tools/art_selector.py` | 630 | Adaptive Random Testing (ART) selection for BugWolf's discovery core. |
| `tools/lab_lifecycle.py` | 605 | BugWolf private-lab lifecycle manager. |
| `tools/program_fit.py` | 604 | BugWolf Program-Fit Gate v1.0.0 |
| `tools/idor_research.py` | 603 | Offline IDOR/access-control research planning. |
| `tools/contract_discovery.py` | 588 | Smart-contract state-space exploration for BugWolf's discovery core. |
| `tools/chain_of_custody.py` | 585 | BugWolf Chain of Custody — Tamper-proof audit trail for every finding. |
| `tools/asset_discovery.py` | 584 | BugWolf Asset Discovery Engine — recursive multi-source enumeration. |
| `tools/js_ct_intel.py` | 573 | BugWolf passive CT and JavaScript intelligence pipeline. |
| `tools/exploit_gen.py` | 572 | BugWolf Exploit Generation Engine — produces weaponized PoCs from findings. |
| `tools/retest_scheduler.py` | 571 | BugWolf Autonomous Retest Scheduler v1.0.0 |
| `tools/opsec.py` | 571 | BugWolf OPSEC Module — Anti-attribution & operational security. |
| `tools/zero_day_tracks.py` | 571 | Deterministic discovery adapters for the five research surfaces. |
| `tools/runtime/contracts.py` | 570 | BugWolf Runtime Contracts - Phase 1 of the orchestrator plan. |
| `tools/chain_orchestrator.py` | 568 | BugWolf full-chain orchestrator. |
| `tools/domains/cloud/iam_privesc_graph.py` | 559 | BugWolf IAM Privilege-Escalation Graph — offline capability analysis (AWS). |

## 6. Verification notes

Run the reproducible verification locally:

```bash
python3 scripts/generate_audit.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m compileall -q tools tests lab
bash -n tools/recon_engine.sh
bash scripts/ci_bundle_check.sh
```

This document makes no claim about zero-day discovery probability; it is an engineering inventory.