# Security Policy

## Scope of this document

BugWolf is offensive-security tooling for **authorized** engagements. This
policy covers (a) how to report vulnerabilities in BugWolf itself and
(b) the safety model operators should understand before running it.

## Reporting a vulnerability in BugWolf

**Do not open a public issue for security bugs.**

Report privately: open a [GitHub security advisory](https://github.com/youseefhamdi/bugwolf/security/advisories/new)
or contact the maintainer directly. Include a reproduction and affected
version. You will get an acknowledgment within 72 hours and a fix timeline
within 7 days for critical issues.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.16.x (latest minor)  | ✅ |
| older minors           | ❌ (upgrade — releases are signed; verify SHA256SUMS + minisig) |

## BugWolf's safety model (what enforces what)

BugWolf separates **workflow enforcement** from **execution enforcement**.
Understand this before running a mission:

| Control | Enforced by | Notes |
|---------|-------------|-------|
| Target boundary | `tools/runtime/scope.py` | **Deny-by-default**: the operator-declared mission target is authorized; everything else fails CLOSED and is recorded as a policy fact. `--exclude` carve-outs always beat wildcards. |
| Subprocess execution | `tools/runtime/sandbox.py` | Binary allowlist, scrubbed environment, output caps. Every spawn goes through it — including team subagents. |
| Emergency stop | `python3 -m tools.runtime.sandbox kill` | Halts all spawnable execution **fail-closed** (even with a corrupt marker file) and fails the release capability gate closed. Re-arm explicitly. |
| Evidence integrity | hash-chained artifacts + F0.5 gate | Findings below the evidence threshold are DEMOTED and quarantined, never reported. |
| Human review | report mode entry predicate | Report requires zero open leads and operator review; nothing is auto-submitted anywhere. |
| Harness-level contract | `tools/harness_guard.py` | Reloadable project contract so instruction drift is detectable after context compaction. |
| Release integrity | `tools/release_signing.py` | SHA-256 manifest + Ed25519 (minisign-style) detached signature; `harness_guard.py --verify-install` re-hashes the installed tree offline and fails closed on any mismatch, missing, or unlisted file. The session-start home-beacon (unsigned fetch of `VERSION` from a mutable branch on every session) was removed in v1.16.0 — update checks are opt-in via `--check-update` and read tagged releases only. |

### Operator responsibilities

- **Authorization is yours.** The scope gate enforces what you declared; it
  cannot authorize what you did not. Record a target spec
  (`tools/target_intake.py --record target-spec.json`) before any campaign.
- **Destructive validation is opt-in.** The default validation is
  non-destructive; `--confirm-destructive` is for approved environments only.
- **Secrets stay out.** Credentials come from the operator, are never logged,
  and evidence is redacted (`<REDACTED-…>`).

## Out of scope for the security policy

- Findings BugWolf produces against your targets — those belong to your
  engagement's disclosure process, not this repository.
- The hosted service at bugwolf.xyz — see that site's own policy.
