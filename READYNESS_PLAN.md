# BugWolf Full-Power APT Readiness Plan

## Unrestricted-Depth APT Research — Operator-Authorized

**Status:** Approved implementation plan  
**Date:** 2026-08-26  
**Operator:** operator-declared (organization defaults to unknown; recorded per engagement)  
**Repository:** BugWolf / current `main` working tree  
**Audience:** security researchers, maintainers, fuzzing researchers, platform engineers

---

## 0. Operating principle

The plug-in must act as a **full APT research team**: all agents, all applicable
domains, chains, differential testing, state analysis, fuzzing, iterative
research, and escalation reasoning must remain **at full depth and full power**.

Research capability and depth are **never weakened by gates, boundaries, or
conservative defaults**. The project’s existing uncensored execution posture is
kept. “Full power” means maximum approved capability — deep, broad,
iterative, parallel, and adversarial — with the authorization context recorded
for accountability, never used to reduce research depth.

> **Rule 1 — Depth is unrestricted.** No scope check, safety gate, approval
> prompt, or default can reduce the research surface, number of agents,
> payload variety, chain depth, fuzzing coverage, or iterative rounds.
>
> **Rule 2 — Authorization is context, not a limiter.** The operator declares
> the authorization (organization, engagement, targets, environments), which
> defaults to unknown until recorded. Authorization never blocks a research
> idea or reduces depth; it is provenance for accountability.
>
> **Rule 3 — Evidence is the product.** Every hypothesis, probe, replay, and
> finding is captured with provenance so the operator can validate,
> reproduce, escalate, and report.
>
> **Rule 4 — Research is not weakened by reporting discipline.** Findings are
> gated for reporting quality, not for research capability. Execution stays
> full-power; reporting stays accurate.

---

## 1. Current baseline

### 1.1 Existing strengths

BugWolf already provides:

- staged full workflow and mandatory multi-checkpoint research loop;
- campaign orchestration with parallel research threads and pass@k variants;
- web/API, smart-contract, mobile, cloud/IaC, LLM/agentic, and recon domains;
- surface modeling, mutation planning, differential analysis, chain analysis,
  and novelty assessment;
- live HTTP execution, fuzz campaigns, WAF/bypass learning, and exploit replay;
- evidence, replay, state, ledger, chain-of-custody, PII, and learning stores;
- a deterministic lab fixture and an extensive test suite;
- bundle builds with content verification and self-evaluation.

### 1.2 What remains to make it a full-power, accountable research platform

1. **Capability truthfulness and maturity reporting.** A machine-readable
   manifest that states exactly what is supported, at what depth, and what is
   not — so the operator never over-relies on an unsupported surface.
2. **Execution context recording.** An audit record of operator authorization
   (operator-declared organization), engagement, target, environment, and
   operation class that never reduces depth but makes every action attributable.
3. **Research depth telemetry.** Metrics proving coverage, corpus quality,
   time-to-signal, reproduction rate, and precision so the team can steer
   research budgets.
4. **Strong validation.** Replay and impact checks that make findings
   trustworthy without limiting which probes can be run.
5. **Coverage-guided and state-aware research substrate.** Instrumented local
   targets, corpus management, minimization, and deduplication so novel-bug
   discovery probability rises.
6. **Secret-safe evidence.** Redaction and retention so evidence can be shared
   and reported without leaking credentials or third-party data.
7. **Supply-chain and release discipline.** Provenance, pinned dependencies,
   signed/verified bundles, and clean-install verification.
8. **Disclosure and retest workflow.** Coordinated disclosure, safe-harbor
   alignment, and patch-retest continuity.

None of these reduce research depth. They make full-power research
accountable, reproducible, and more effective.

---

## 2. Capability and readiness model

Maturity is measured on **depth and trustworthiness of the research output**,
not on the number of restrictions.

### Level 0 — Planning depth

- Full-depth planning and static analysis.
- No live validation; hypotheses only.

### Level 1 — Full-depth active research

- Full APT research depth on authorized targets.
- All agents, domains, chains, differentials, fuzzing, and escalation active.
- Evidence captured; findings marked as hypotheses until validated.

### Level 2 — Reproducible depth

- Every probe and replay is recorded with deterministic evidence.
- Baseline/control pairs and canary fixtures make validation trustworthy.
- Minimization and deduplication keep the research surface high-value.

### Level 3 — Continuously evaluated depth

- Coverage, corpus, crash, and precision metrics tracked per release.
- Benchmark corpus and seeded regression suite exist.
- CI validates bundles, dependencies, artifacts, and safety boundaries.

### Level 4 — Production-grade full-power platform

- Full-depth research with accountable execution context and provenance.
- Coverage-guided, state-aware, instrumented adapters across supported classes.
- Benchmark-gated releases with signed, provenance-verified bundles.
- Human review for reporting; disclosure and retest workflows operational.

Level 4 is the target. No level reduces research depth.

---

## 3. Target architecture — depth-first, accountability-included

```text
Operator Authorization Context (recorded, never a depth limiter)
        |
        v
Full-Depth Research Planner (all agents, all domains, chains, fuzzing)
        |
        +--> Coverage / Telemetry
        |
        +--> Evidence + Provenance
        |
        v
Validation (baseline/control, replay, canaries)
        |
        v
Triage + Review (reporting quality, not research depth)
        |
        v
Disclosure / Retest
```

### Non-negotiable requirements

- **Depth is never reduced by authorization, scope, approval, or default.**
- Every active operation is attributable to the recorded engagement.
- Evidence is content-addressed, redacted before persistence and egress, and
  replayable.
- Validation uses baselines, controls, canaries, and target-specific impact
  proof; it never limits which probes can be planned or run.
- Research memory is quarantined and provenance-bound; approved techniques are
  reusable at full depth.
- Web research informs hypotheses and prioritization; it is never treated as
  proof or permission.
- Reporting requires human review; research execution does not.

---

## 4. Phased implementation roadmap

## Phase 0 — Capability truth, depth guarantee, and release discipline

**Goal:** Make the platform’s capability and depth explicit, honest, and
machine-checkable, and lock in the “full APT depth, never weakened” rule.

### Work items

1. Define the **full-depth guarantee**:
   - all target classes are declared with status and depth;
   - research depth is recorded as `full_apt_team` and validated;
   - no default or gate may reduce depth;
   - unsupported surfaces fail with a clear capability result instead of
     silently degrading.
2. Define the evidence-state vocabulary:
   - `hypothesis`, `signal`, `candidate`, `reproduced`, `impact_verified`,
     `confirmed_finding`, `reportable`, `blocked`, `refuted`.
3. Add a machine-readable readiness manifest (`configs/readiness.json`)
   containing:
   - version and source revision;
   - supported target classes and depth;
   - execution profiles;
   - claims (including the full-depth guarantee and the no-weakness rule);
   - global control status;
   - requirements before production-grade label.
4. Add an offline readiness validator (`tools/readiness.py`) that:
   - validates the manifest;
   - rejects manifests that reduce depth below `full_apt_team`;
   - rejects false claims;
   - reports blockers and warnings without changing execution.
5. Ship the manifest and validator in both release bundles and verify them in
   CI.

### Acceptance criteria

- No document or CLI output claims guaranteed zero-day discovery.
- Every finding carries an explicit evidence state and confidence reason.
- The readiness report can be generated offline from repository state.
- A manifest that weakens research depth is rejected.
- Unsupported target classes fail with a clear capability result.
- The full-depth guarantee is part of the bundle contract.

---

## Phase 1 — Recorded execution context (accountability, not depth limits)

**Priority:** P1  
**Goal:** Attribute every active operation to the recorded engagement and
target without reducing research depth.

### Work items

1. Define a recorded authorization context:
   - operator/org: operator-declared (defaults to unknown);
   - engagement id;
   - target(s) and environment(s);
   - engagement window;
   - permitted operation classes;
   - excluded targets;
   - emergency contact.
2. Store the context as an immutable audit artifact.
3. Stamp operation records with the context reference, operator, engagement,
   target, timestamp, and operation class.
4. Add a dry-run context simulator that explains planned operations and their
   recorded authorization, without blocking anything.
5. Keep all research planning, payload generation, chain synthesis, fuzzing,
   and escalation **ungated**.

### Acceptance criteria

- Every active operation record carries the recorded engagement context.
- No context field reduces research depth.
- The simulator documents planned actions and their authorization basis.
- Missing context is surfaced as a warning, never as a research-depth gate.

---

## Phase 2 — Evidence, replay, and impact validation (trust, not limits)

**Priority:** P1  
**Goal:** Make findings trustworthy without reducing which probes can run.

### Work items

1. Define versioned evidence schemas for authorization context, target
   snapshot, experiment, execution result, coverage, crash, minimization,
   replay, impact, review, and disclosure.
2. Make artifact storage content-addressed and append-only with a hash-linked
   manifest.
3. Redact before persistence, hashing, logging, provider egress, and error
   reporting; protect raw evidence and enforce retention.
4. Strengthen replay:
   - transport reproduction (request/response recorded, status and block state
     match);
   - behavior reproduction (baseline/control pair, relevant behavior repeats);
   - authorization reproduction (Account A/B fixtures with canary records);
   - integrity reproduction (before/after invariant hashes);
   - confidentiality reproduction (unique canary records, controlled data);
   - availability reproduction (disposable lab only, bounded tests);
   - severity mapping (CWE/OWASP/MASVS/ASVS, CVSS v4.0 context).
5. Enforce the candidate state machine for reporting:

   ```text
   hypothesis -> signal -> candidate -> reproduced
   -> impact_verified -> human_confirmed -> reportable
   ```

   with exits to `refuted`, `blocked`, `duplicate`, `needs_more_evidence`.

### Acceptance criteria

- Confirmed findings have positive test, negative control, replay, impact
  artifact, and reviewer decision.
- Mismatched status, body, identity, or state invariant cannot be marked
  reproduced.
- Evidence is tamper-evident and secret-safe.
- No validation step reduces research depth.

---

## Phase 3 — Coverage-guided and state-aware research substrate

**Priority:** P1  
**Goal:** Raise novel-bug discovery probability through instrumentation,
corpus quality, and feedback — at full depth.

### Work items

1. Add adapters per target class:
   - web/API: authenticated state model, sequence-aware workflows, role/tenant
     matrix, canary oracles, differential versions;
   - source: CodeQL data-flow paths, custom query packs, dependency
     boundaries, static-to-dynamic handoff;
   - native parser/library: libFuzzer targets with sanitizers, corpus seeds,
     crash minimization, coverage telemetry;
   - AFL++: persistent mode, CmpLog/LAF-Intel, corpus sync, governance;
   - kernel/driver: syzkaller only in dedicated disposable VMs;
   - smart contract: invariant/sequence fuzzing, forked local chain,
     minimized transaction sequences;
   - mobile/binary: emulator/simulator, MASVS/MASTG mapping, IPC/deep-link
     state models;
   - LLM/agentic: isolated model/tool fixtures, policy oracles, retrieval
     poisoning canaries.
2. Implement corpus management: seed provenance, coverage novelty scoring,
   minimization, deduplication, mutation lineage, state-transition coverage,
   crash signature dedup, deterministic replay, human-reviewed promotion.
3. Implement research scheduling that optimizes expected information gain:
   differential pairs, negative controls, boundary flips, state/time/order
   permutations, role/ownership changes, parser disagreement, failure/recovery
   paths, cross-surface chains, cache/identity boundaries, capability-to-impact
   transitions.

### Acceptance criteria

- Each supported fuzzing adapter has at least one instrumented local target.
- Coverage, corpus, crash, and minimization artifacts appear in evidence.
- Seed promotion and crash deduplication are deterministic.
- Benchmarks show improvement against fixed-payload baselines at equal budget.
- No adapter reduces research depth.

---

## Phase 4 — Benchmark and regression laboratory

**Priority:** P2  
**Goal:** Measure whether changes improve discovery and precision.

### Work items

1. Build a versioned corpus: synthetic web/API apps, historical vulnerable
   revisions, native libraries, smart-contract fixtures, mobile fixtures,
   LLM/agentic fixtures, and a negative corpus.
2. Track per-release metrics: true/false positives, false negatives where
   ground truth exists, precision/recall/F-score, unique bugs and root causes,
   duplicate rate, time-to-first-signal, time-to-reproduced, time-to-impact,
   time-to-minimize, coverage, corpus quality, review time, secret-leakage
   incidents, blocked unsafe operations, evidence completeness.
3. Report discovery proxies honestly: new coverage, new state transitions,
   unique crash signatures, anomalous clusters, confirmed novel root causes,
   independently reproduced issues.

### Acceptance criteria

- Every release runs the benchmark suite.
- Precision, evidence integrity, and secret-safety regressions block release.
- Historical vulnerabilities are validation-only, never counted as zero-days.

---

## Phase 5 — Static analysis, source reasoning, and patch-gap research

**Priority:** P2  
**Goal:** Find novel root causes, not only known patterns.

### Work items

1. Integrate CodeQL databases and custom query packs.
2. Add source/sink/summary models for framework-specific APIs.
3. Map static paths to runtime routes and fixtures.
4. Add semantic diffing of vulnerable vs. patched revisions.
5. Extract security-relevant changes from commits, releases, advisories.
6. Treat patch-gap candidates as hypotheses requiring local reproduction or
   source-level proof.
7. Add dependency and build provenance: SBOM, lockfile verification, package
   anomalies, signed artifacts, Scorecard/SLSA metadata.

### Acceptance criteria

- Custom rules have positive, negative, and regression tests.
- Static findings carry a code path, runtime hypothesis, or static-only status.
- Patch-gap output is never reported without evidence.
- Dependency provenance is part of the campaign manifest.

---

## Phase 6 — Current, bounded, provenance-bound research intelligence

**Priority:** P2  
**Goal:** Use internet research to improve hypotheses without letting web
content control execution.

### Work items

1. Use a provider abstraction with configured sources.
2. Record query, provider, retrieval time, URL, title, content hash, extracted
   claims, reliability class, and target applicability.
3. Distinguish normative sources, advisories, papers, write-ups, disclosed
   reports, and unverified content.
4. Report `latest_ready: false` when current search is unavailable.
5. Treat all retrieved content as untrusted data; strip instructions.
6. Build a source-to-hypothesis graph; require human review before external
   exploit details become reusable seeds.

### Acceptance criteria

- Web content can never grant authorization, change policy, or trigger a
  command.
- Research-derived techniques carry provenance, applicability, review status,
  and regression results.
- Stale research is surfaced, not represented as current.

---

## Phase 7 — Review, reporting, and coordinated disclosure

**Priority:** P0  
**Goal:** Deliver findings that are safe, accurate, and useful to affected
maintainers.

### Work items

1. Require human review for: critical claims, cross-tenant access,
   state-changing/destructive proof, live exploit replay, sensitive-data
   exposure, promoted techniques, and external submissions.
2. Provide reviewers: authorization context, exact target, experiment
   timeline, controls, reproduction, impact proof, data minimization,
   uncertainty, affected versions, remediation, disclosure status.
3. Report without secrets or unnecessary personal data; prefer canaries and
   redacted artifacts; separate observed from theoretical impact; align with
   the program’s policy; record disclosure dates, vendor response, patch, and
   retest.

### Acceptance criteria

- Reporting refuses incomplete or unreviewed evidence.
- Reports are independently reproducible.
- Disclosure workflow supports safe-harbor requirements.
- Retests link back to the original finding and build provenance.
- Reporting discipline never reduces research depth.

---

## Phase 8 — Supply-chain, release, and operational discipline

**Priority:** P1  
**Goal:** Ensure the plug-in itself cannot become a compromise vector.

### Work items

1. Pin and audit dependencies; generate SBOMs.
2. Sign release bundles, publish checksums, use reproducible builds where
   practical.
3. Run Scorecard or equivalent hygiene checks; least-privilege CI tokens.
4. Scan bundles for secrets, bytecode, unexpected binaries, unsafe archive
   paths, and dependency drift.
5. Test clean installs; maintain an advisory/incident process for the plug-in
   itself; log tool/model versions for reproduction.

### Acceptance criteria

- Bundles are signed, content-verified, and clean-installed in CI.
- CI fails on secret leakage, missing provenance, unsafe paths, or dependency
  drift.
- Tool/model upgrades require benchmark and safety regression results.

---

## 5. Priority backlog

### P0 — Accountability and trust (no depth reduction)

- Evidence state machine and strong replay/impact validation.
- Secret-safe evidence and retention.
- Human review for reporting.
- Coordinated disclosure and retest workflows.
- Release provenance, signed bundles, clean-install verification.

### P1 — Depth expansion

- Recorded execution context (accountability, not limits).
- Coverage-guided fuzzing adapters with instrumented local targets.
- Corpus management, minimization, deduplication, deterministic replay.
- Benchmark corpus and seeded regression suite.
- CodeQL and patch-diff integration.
- Smart-contract fork/invariant harnesses; mobile emulator adapters;
  LLM/agentic disposable fixtures.
- Provenance-bound web research ingestion.

### P2 — Optimization and scale

- Distributed corpus sync and multi-target scheduling.
- Adaptive resource allocation based on measured coverage.
- Researcher feedback analytics; additional language/framework models.
- Automated minimization and report packaging.

---

## 6. Implementation order in this repository

1. Finish Phase 0 (this plan): capability manifest, full-depth guarantee,
   offline validator, bundle verification, and tests.
2. Add recorded execution context (engagement) and the dry-run
   simulator; no research-depth gates.
3. Strengthen evidence schemas and replay/impact validation.
4. Add sandboxed instrumented adapters for fuzzing; coverage/corpus artifacts.
5. Add the benchmark corpus and metric gates.
6. Add CodeQL, patch-diff, and dependency provenance stages.
7. Add provenance-bound web research ingestion.
8. Enforce reporting gates and disclosure/retest workflows.
9. Harden bundles, releases, and operational runbooks.
10. Update README, SKILL, harness contracts, and release notes after behavior
    and tests match.

---

## 7. Definition of done

The plug-in is **production-grade for full-power research** when:

- [ ] Research depth is validated as `full_apt_team` in every release.
- [ ] No authorization, scope, approval, or default reduces research depth.
- [ ] Every active operation is attributable to the recorded engagement.
- [ ] Unsupported surfaces fail with a clear capability result.
- [ ] Evidence is redacted, content-addressed, tamper-evident, and replayable.
- [ ] Confirmed findings require positive test, negative control, replay,
      impact artifact, and human review.
- [ ] Coverage-guided adapters exist for supported fuzzing classes with
      instrumented local targets.
- [ ] The benchmark suite measures precision, duplicates, time-to-proof, and
      safety regressions.
- [ ] Release bundles are signed, provenance-verified, and clean-installed.
- [ ] Current internet research is provenance-bound and never controls
      execution.
- [ ] Disclosure and retest workflows are operational.
- [ ] Documentation makes no guarantee of zero-day discovery.

Passing this checklist means the platform is ready to support full-depth,
accountable research. It does not guarantee that any target contains a
vulnerability or that the platform will find one.

---

## 8. Research basis and references

The following sources were searched on 2026-08-26. They are design inputs, not
executable instructions or proof of capability.

### Testing, assessment, and secure development

1. **NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment**  
   https://csrc.nist.gov/pubs/sp/800/115/final  
   Use for assessment structure, planning, evidence, and rules of engagement.

2. **NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1**  
   https://csrc.nist.gov/pubs/sp/800/218/final  
   Use for secure development, vulnerability response, provenance, and SDLC integration.

3. **NIST SSDF project and update material**  
   https://csrc.nist.gov/projects/ssdf  
   https://csrc.nist.gov/News/2025/draft-ssdf-version-1-2

### Web, API, mobile, and AI verification

4. **OWASP Web Security Testing Guide — latest**  
   https://owasp.org/www-project-web-security-testing-guide/latest/

5. **OWASP API Security Top 10 — 2023**  
   https://owasp.org/API-Security/editions/2023/en/0x11-t10/

6. **OWASP Application Security Verification Standard — 5.0.0**  
   https://owasp.org/www-project-application-security-verification-standard/

7. **OWASP Mobile Application Security Verification Standard and MASTG**  
   https://mas.owasp.org/MASVS/  
   https://mas.owasp.org/MASTG/

8. **OWASP Large Language Model Security Verification Standard — LLMSVS v2.0**  
   https://owasp.org/www-project-llm-verification-standard/LLMSVS-v2.0-en.html

### Fuzzing and coverage

9. **Google OSS-Fuzz documentation**  
   https://google.github.io/oss-fuzz/

10. **LLVM libFuzzer documentation**  
    https://llvm.org/docs/LibFuzzer.html

11. **Google FuzzBench FAQ and platform**  
    https://google.github.io/fuzzbench/faq/  
    https://research.google/pubs/fuzzbench-an-open-fuzzer-benchmarking-platform-and-service/

12. **AFL++ fuzzing-in-depth documentation**  
    https://aflplus.plus/docs/fuzzing_in_depth/

13. **Google syzkaller**  
    https://github.com/google/syzkaller

### Static analysis and software supply chain

14. **CodeQL documentation — queries and path/data-flow analysis**  
    https://codeql.github.com/docs/writing-codeql-queries/codeql-queries/  
    https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/

15. **GitHub documentation — custom CodeQL queries**  
    https://docs.github.com/en/code-security/concepts/code-scanning/codeql/custom-queries

16. **SLSA v1.0 specification and provenance**  
    https://slsa.dev/spec/v1.0/  
    https://slsa.dev/spec/v1.0/provenance

17. **OpenSSF Scorecard**  
    https://openssf.org/projects/scorecard/

### Scoring and disclosure

18. **FIRST CVSS v4.0 specification**  
    https://www.first.org/cvss/v4.0/specification-document  
    **CVSS v4.0 implementation guide:** https://www.first.org/cvss/v4.0/implementation-guide

19. **Google Project Zero disclosure policy — 2025 edition**  
    https://googleprojectzero.blogspot.com/2025/07/reporting-transparency.html

20. **CISA Vulnerability Disclosure Policy Template**  
    https://www.cisa.gov/vulnerability-disclosure-policy-template  
    **CISA Coordinated Vulnerability Disclosure Program:**  
    https://www.cisa.gov/resources-tools/programs/coordinated-vulnerability-disclosure-program

---

## 9. Final position

BugWolf is a capable full-power research orchestrator. The next step is to
make that power **accountable, reproducible, coverage-guided, and
secret-safe** — while keeping research depth unrestricted:

1. **full-depth APT research, never weakened;**
2. **recorded authorization context for accountability, never a limiter;**
3. **coverage- and state-guided depth;**
4. **strong validation without limiting probes;**
5. **benchmark-measured quality;**
6. **provenance-preserving evidence;**
7. **secret-safe reporting;**
8. **human review for reporting, not research;**
9. **honest about uncertainty.**

That combination maximizes the odds of finding novel vulnerabilities and
critical-impact chains while keeping the research capability at full APT-team
power. Zero-days are never guaranteed, and the product should not claim that
they are — but nothing in this plan reduces the depth of the search.
