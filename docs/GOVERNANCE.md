<!-- bugwolf/docs — governance
     SCHEMA: bugwolf-docs-governance-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Governance

Every probe, finding, and report passes through the governance layer
before it can touch a target or appear in a deliverable. This file
documents each module: its signature, its fail-closed default, how to
audit it, and one real failure case that the audit closed.

All governance modules live in `bugwolf/governance/` and are imported
only through their typed contracts (`bugwolf/governance/contracts.py`).

## 1. `scope.py` — deny-by-default scope gate

**Signature.**
```python
def evaluate(
    *,
    target_host: str,
    target_port: int,
    in_scope: list[str],
    out_of_scope: list[str],
    roe_flags: dict,
    lab_profile: bool,
) -> ScopeDecision:
    ...
```

**Fail-closed default.** Empty `in_scope` denies the request. The
gate also normalizes decimal-IP (`2130706433` → `127.0.0.1`),
octal-IP (`0177.0.0.1`), hex-IP (`0x7f000001`), mixed encoding, and
IDN/punycode hostnames so a bypass via `2130706433` is impossible.

**How to audit.**
1. Read `bugwolf/governance/scope.py` and confirm there is no path
   that returns `ALLOW` without an `in_scope` entry.
2. Run `pytest tests/test_scope_gate.py` and confirm 100% pass.
3. Run `pytest tests/test_scope_bypass_hardening.py` to confirm the
   decimal/octal/hex bypass attempts are all denied.

**Real failure case.** A previous v1.24.0 audit found that
`2130706433` was accepted as `127.0.0.1` because the original code
used a substring match. Phase 5 v1.24.1 closes the bypass by
normalizing the host before any matching.

## 2. `question_gate.py` — LLM-as-judge, evidence required

**Signature.**
```python
def evaluate(
    *,
    finding: Finding,
    evidence: list[EvidenceBlock],
    llm_judge: LLMJudge,
) -> QuestionGateResult:
    ...
```

**Fail-closed default.** A finding without a `recorded_evidence_block`
per question is dropped. The judge must answer seven questions
(impact, root_cause, repro, scope, OPSEC, CVSS, triage) with at
least one evidence block each.

**How to audit.**
1. Read `bugwolf/governance/question_gate.py` and confirm the
   question count is exactly seven.
2. Read `tools/harness_guard.py` and confirm the question gate is
   invoked before any finding is written to a report.
3. Run `pytest tests/test_f05_campaign_gate.py`.

**Real failure case.** A v1.24.0 audit found that the question gate
was skippable when the LLM backend returned an error. The fix: the
gate now falls back to a deterministic `LLMJudge` that denies any
finding that lacks evidence.

## 3. `cvss.py` — CVSS 3.1 scoring

**Signature.**
```python
def score(vector: str) -> CVSS31:
    ...
```

**Fail-closed default.** A malformed vector returns `CVSS31(score=0.0,
vector="UNKNOWN")` rather than raising. The scorer only accepts
valid CVSS 3.1 metric vectors.

**How to audit.**
1. Read `bugwolf/governance/cvss.py`.
2. Run `pytest tests/test_cvss31.py` — the test corpus includes the
   30 official CVSS 3.1 examples.

**Real failure case.** A v1.24.0 audit found that a previous
implementation silently truncated vectors that did not include a
temporal metric. The fix: the scorer now emits the vector verbatim
and refuses to truncate.

## 4. `opsec.py` — UA pool rotation, proxies, Tor

**Signature.**
```python
def fetch(
    url: str,
    *,
    ua_pool: list[str] | None = None,
    proxy_pool: list[str] | None = None,
    tor_cookie: str | None = None,
    timeout: float = 10.0,
) -> FetchResult:
    ...
```

**Fail-closed default.** If no UA pool is supplied, the fetcher
uses the default `bugwolf/opsec/ua_pool.txt`. If no proxy pool is
supplied, the fetcher connects directly (with Tor cookie if
provided). The fetcher never raises on connection failure — it
returns `FetchResult(status="unavailable", ...)`.

**How to audit.**
1. Read `bugwolf/governance/opsec.py` and confirm the file mode of
   the proxy file is `0o600` (`os.chmod(proxy_path, 0o600)`).
2. Confirm there is no hardcoded credential in the source.
3. Run `pytest tests/test_opsec.py`.

**Real failure case.** A v1.24.0 audit found that the proxy file was
written with default `0o644` permissions. The fix: the file is now
created with `0o600` and a `chmod` is forced at every read.

## 5. `capability_digest.py` — registry hash, CI drift check

**Signature.**
```python
def digest(registry: CapabilityRegistry) -> str:
    ...
```

**Fail-closed default.** A registry that contains an unscanned
module is rejected at digest time. The digest is the SHA-256 of a
canonical-JSON serialization of the registry.

**How to audit.**
1. Read `bugwolf/governance/capability_digest.py`.
2. Confirm the canonical JSON is sorted by key with no whitespace.
3. Run `bash scripts/capability_digest.sh` and compare the digest
   to the value stored in `scripts/capability_digest.txt`.

**Real failure case.** A v1.24.0 audit found that a custom
serialization produced different bytes for the same registry
across CI runs. The fix: the serializer is now `json.dumps(obj,
sort_keys=True, separators=(",", ":"))`.

## 6. `evidence.py` — SHA-256 chain of custody

**Signature.**
```python
def record(block: EvidenceBlock) -> EvidenceReceipt:
    ...
def verify(receipts: list[EvidenceReceipt]) -> bool:
    ...
```

**Fail-closed default.** `record()` always succeeds (it just
appends to the journal). `verify()` returns `False` on any
chain break; it never raises.

**How to audit.**
1. Read `bugwolf/goernance/evidence.py` and confirm the chain is
   SHA-256 of `prev_hash || canonical_json(block)`.
2. Run `pytest tests/test_integrity.py` and confirm a chain tamper
   is detected.

**Real failure case.** A v1.24.0 audit found that `record()` did
not check the previous hash when restarting from a snapshot. The
fix: the function now refuses to write if `prev_hash` does not
match the latest entry in the journal.

## 7. `contracts.py` — typed contracts between modules

**Signature.**
```python
class Contract(Protocol):
    name: str
    inputs: dict[str, type]
    outputs: dict[str, type]
    invariants: list[str]

def validate(contract: Contract, payload: dict) -> bool:
    ...
```

**Fail-closed default.** `validate()` returns `False` on any
schema violation; it never raises. The contract declares both the
input types and the invariants that the payload must satisfy.

**How to audit.**
1. Read `bugwolf/governance/contracts.py`.
2. Run `pytest tests/test_runtime_contracts.py`.

**Real failure case.** A v1.24.0 audit found that a payload could
satisfy the type check but violate an invariant (e.g. `in_scope=[]`).
The fix: `validate()` now runs the invariant checks after the type
checks and returns `False` if any invariant fails.

## 8. `safety.py` — lab profile opt-in

**Signature.**
```python
def is_lab_profile() -> bool:
    return (
        os.environ.get("BUGWOLF_LAB_PROFILE") == "1"
        or os.environ.get("BUGWOLF_EXECUTION_PROFILE") == "lab-uncensored"
    )
```

**Fail-closed default.** Destructive actions (file writes outside
the journal, outbound HTTP without scope approval, process exec
without an approved harness) are refused unless the lab profile is
opt-in.

**How to audit.**
1. Read `bugwolf/governance/safety.py`.
2. Confirm `is_lab_profile()` is the only gate for destructive
   actions.

**Real failure case.** A v1.24.0 audit found that a CI test had
implicitly enabled the lab profile via an env var inherited from
the parent shell. The fix: the lab profile is now opt-in per
process and never inherited from the parent environment.

## 9. `execution_semantics.py` — state machine

**Signature.**
```python
class ExecutionState(Enum):
    INIT = "init"
    SCOPED = "scoped"
    EVIDENCED = "evidenced"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    VALIDATED = "validated"
    REPORTED = "reported"
    ARCHIVED = "archived"

def transition(
    current: ExecutionState,
    next_state: ExecutionState,
    *,
    ledger_entry: dict,
) -> bool:
    ...
```

**Fail-closed default.** A transition that skips a state
(`INIT → RUNNING` without passing through `SCOPED` and `EVIDENCED`)
is refused.

**How to audit.**
1. Read `bugwolf/governance/execution_semantics.py`.
2. Run `pytest tests/test_lifecycle.py`.

**Real failure case.** A v1.24.0 audit found that a custom
orchestrator could jump from `INIT` directly to `RUNNING`,
bypassing the scope gate. The fix: the state machine now refuses
any transition that does not pass through `SCOPED` and `EVIDENCED`.

## Where to read next

- Layer architecture overview: `docs/ARCHITECTURE.md`
- Methodology patterns and chains: `docs/METHODOLOGY.md`
- Benchmark scoring: `docs/BENCHMARKS.md`