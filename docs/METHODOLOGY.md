<!-- bugwolf/docs — methodology
     SCHEMA: bugwolf-docs-methodology-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Methodology

The methodology layer is the "knowledge base" of BugWolf: 70 patterns
organized into 14 bug-class directories, 10 Markdown templates for
engagements, and 12 chain YAMLs for A→B→C attack synthesis. This file
documents the structure, the three public APIs (search, citation,
vector index), and how to add a new pattern or a new chain.

All methodology modules live in `bugwolf/methodology/`.

## 1. Directory layout

```
bugwolf/methodology/
    __init__.py             # public API: search / citation / vector_index
    search.py               # full-text + tag search
    citation.py             # citation formatter (HackerOne/Bugcrowd style)
    vector_index.py         # cosine similarity index over patterns
    chain_loader.py         # YAML loader for chains/*.yaml
    patterns/
        api/                # GraphQL, REST, gRPC, batching, ...
        auth/               # OAuth, JWT, SAML, session, ...
        business_logic/     # FIN matrix, state-machine bugs, ...
        ci_cd/              # GitHub Actions expression injection, ...
        cloud/              # AWS / GCP / Azure misconfig, ...
        deserialization/    # Python pickle, Java ObjectInputStream, ...
        idor/               # object-level access control, ...
        llm_ai/             # prompt injection, RAG poisoning, ...
        mobile/             # deep link, MASVS/MASWE, ...
        recon/              # subdomain enum, takeover, ...
        sqli/               # SQL injection variants, ...
        ssrf/               # SSRF + filter bypass, ...
        waf_bypass/         # 15 documented bypass techniques, ...
        xss/                # XSS variants + sinks, ...
    templates/
        api_assessment.md
        bug_bounty_triage.md
        cloud_assessment.md
        llm_assessment.md
        mobile_assessment.md
        osint_engagement.md
        pentest_kickoff.md
        redteam_kickoff.md
        smart_contract_assessment.md
    chains/
        01_oauth_to_ato.yaml
        02_ssrf_to_rce.yaml
        03_graphql_to_mass_leak.yaml
        04_cache_poison_xss.yaml
        05_http_smuggle_hijack.yaml
        06_credspray_to_admin.yaml
        07_subdomain_takeover.yaml
        08_idor_pii_leak.yaml
        09_race_double_spend.yaml
        10_jwt_to_admin.yaml
        11_supply_chain_rce.yaml
        12_cicd_secrets_leak.yaml
```

## 2. Public APIs

### 2.1 `methodology.search`

Full-text + tag search across patterns.

**Signature.**
```python
def search(
    query: str,
    *,
    tag: str | None = None,
    bug_class: str | None = None,
    limit: int = 10,
) -> list[Pattern]:
    ...
```

**Behavior.** Tokenizes the query, scores each pattern by BM25,
applies the optional tag and bug-class filters, returns the top
`limit` patterns sorted by score descending. The query is
case-insensitive; tags are matched exactly.

### 2.2 `methodology.citation`

Citation formatter for the H1/Bugcrowd/Intigriti/Immunefi report
templates.

**Signature.**
```python
def cite(
    pattern_id: str,
    *,
    style: str = "hackerone",
) -> Citation:
    ...
```

**Behavior.** Loads the pattern by `pattern_id`, formats the
"References" block in the requested style, and returns a
`Citation` object that the reporting layer can append to the
report.

### 2.3 `methodology.vector_index`

Cosine similarity index over the pattern corpus, used by the
chain builder to find candidate A→B steps.

**Signature.**
```python
class VectorIndex:
    def add(self, pattern_id: str, vector: list[float]) -> None: ...
    def query(
        self, vector: list[float], *, k: int = 5
    ) -> list[tuple[str, float]]: ...
```

**Behavior.** Uses stdlib only (`math.sqrt`, `sum`, generator
expressions). Vectors are L2-normalized at insert time. The query
returns the top-k patterns by cosine similarity.

## 3. Pattern schema

A pattern is a Markdown file with a YAML frontmatter block:

```yaml
---
id: xss.reflected.query
bug_class: xss
tags: [reflected, sink:html, severity:medium]
severity: medium
cwe: CWE-79
cvss_3_1: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
preconditions:
  - "parameter flows into HTML body"
  - "no output encoding detected"
steps:
  - "identify reflective sink"
  - "inject polyglot <svg/onload=alert(1)>"
  - "confirm browser execution"
evidence:
  - type: http_request
    method: GET
    url: "/search?q=<svg/onload=alert(1)>"
expected_status: 200
expected_body_contains: ["<svg"]
bypass_filters: ["<scRipt>"]
---

# Reflected XSS in Query Parameter

This pattern covers the canonical reflected-XSS case where a query
parameter flows unencoded into the HTML body of the response.
```

**Validation.** A pattern is validated at load time by
`methodology/__init__.py:validate_pattern`. The validation rules
are:
- `id` must be unique across all patterns.
- `bug_class` must be one of the 14 directories.
- `cvss_3_1` must parse cleanly via `cvss.score`.
- `evidence` must declare at least one `http_request` or
  `http_response` block.

## 4. How to add a new pattern

1. Pick the bug-class directory (`bugwolf/methodology/patterns/<class>/`).
2. Create a Markdown file with the schema above.
3. Run `python3 -m bugwolf.methodology --validate` to check the
   schema.
4. Run `pytest tests/test_methodology_playbook.py` to confirm the
   new pattern participates in the playbook tests.
5. (Optional) Run `python3 -m bugwolf.methodology --rebuild-index`
   to rebuild the vector index.

## 5. Chain YAML schema

A chain is a YAML file with the following structure:

```yaml
id: oauth_to_ato
title: "OAuth code interception → account takeover"
description: |
  Step-by-step attack chain from an OAuth misconfiguration to a
  full account takeover, citing five canonical patterns from the
  methodology corpus.
severity: high
preconditions:
  - "target exposes OAuth login"
  - "client_id / redirect_uri leaks via JS bundle"
steps:
  - id: discover_oauth_endpoint
    pattern: recon.subdomain_enum
    note: "find the OAuth authorization endpoint"
  - id: leak_client_id
    pattern: auth.oauth_flow
    note: "extract client_id from JS bundle"
  - id: register_redirect_uri
    pattern: auth.oauth_flow
    note: "register attacker-controlled redirect_uri"
  - id: exchange_code
    pattern: auth.oauth_flow
    note: "complete the OAuth dance as the victim"
  - id: takeover_account
    pattern: auth.ato_chain
    note: "log in as the victim"
validation:
  contract: chain_validity_v1
  must_close: true
citations:
  - pattern: auth.oauth_flow
  - pattern: auth.ato_chain
```

## 6. How to add a new chain (worked example)

Suppose you want to convert a 5-step methodology (an AWS Cognito
misconfiguration that escalates to IAM privilege escalation) into a
chain YAML:

```yaml
id: cognito_to_iam_privesc
title: "AWS Cognito misconfiguration → IAM privilege escalation"
description: |
  5-step chain: discover Cognito identity pool → enumerate
  unauthenticated roles → assume role via STS → escalate to
  admin via misconfigured trust policy → read S3 bucket.
severity: critical
preconditions:
  - "target hosts an AWS workload with Cognito identity pools"
  - "Cognito identity pool allows unauthenticated access"
steps:
  - id: discover_pool
    pattern: cloud.aws_recon
  - id: enumerate_roles
    pattern: cloud.iam_enum
  - id: assume_role
    pattern: cloud.sts_assume
  - id: escalate_via_trust
    pattern: cloud.trust_policy
  - id: read_s3
    pattern: cloud.s3_access
validation:
  contract: chain_validity_v1
  must_close: true
citations:
  - pattern: cloud.aws_recon
  - pattern: cloud.iam_enum
  - pattern: cloud.sts_assume
  - pattern: cloud.trust_policy
  - pattern: cloud.s3_access
```

After saving the YAML, run:
```bash
python3 -m bugwolf.methodology.chain_loader --validate \
    bugwolf/methodology/chains/13_cognito_to_iam_privesc.yaml
pytest tests/test_chain_orchestrator.py
```

The chain loader will:
1. Parse the YAML and confirm all required fields are present.
2. Look up each `pattern` reference in the methodology corpus and
   confirm it exists.
3. Build a chain object and feed it to `chain.validator` to
   confirm `chain_validity_v1` is satisfied (every step must
   reference a known pattern; the last step must produce an
   observable outcome).

## Where to read next

- Architecture overview: `docs/ARCHITECTURE.md`
- Governance contracts: `docs/GOVERNANCE.md`
- Benchmark scoring: `docs/BENCHMARKS.md`