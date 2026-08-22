# BugWolf Defensive and Asset Intelligence Tracks

The additional 2026 articles were converted into **offline analysis and planning** capabilities. They are not treated as authoritative vulnerability evidence, and article-provided CVE identifiers must be independently verified.

## Offline asset intelligence

`tools/asset_intel.py` creates provider query plans and normalizes operator-supplied exports from Amass, Shodan, Censys, FOFA, ZoomEye, or SpiderFoot. It does not contact those services and never accepts API keys from environment variables.

```bash
python3 tools/asset_intel.py \
  --target example.com \
  --scope-file scope.json \
  --input-file recon/example.com/subs.txt \
  --input-file recon/example.com/resolved.txt \
  --output-dir recon/example.com/asset-intel
```

Outputs include `assets.jsonl`, `asset-diff.jsonl`, `provider-plans.jsonl`, and `manifest.json`. Every asset is filtered against the explicit scope before it is retained.

### Shodan facet collection via `ipfinder`

The module also adapts [`rix4uni/ipfinder`](https://github.com/rix4uni/ipfinder), a local Go CLI that reads Shodan facet queries on stdin and prints matching IPs/domains (`query::value` lines with `--source`) from Shodan's public search facets. Offline by default, it emits the facet query plans and the exact command lines:

```bash
# Offline: facet query plans + commands (ssl / hostname / ssl.cert.subject.cn)
python3 tools/asset_intel.py --target example.com --scope-file scope.json \
  --shodan-facets --output-dir recon/example.com/asset-intel

# Offline: normalize a saved ipfinder --source run (scope-filtered)
python3 tools/asset_intel.py --target example.com --scope-file scope.json \
  --ipfinder-output recon/example.com/ipfinder-run.txt \
  --output-dir recon/example.com/asset-intel

# Gated live collection (active operation): requires the binary + confirmation
python3 tools/asset_intel.py --target example.com --scope-file scope.json \
  --collect-ipfinder --confirm-active --output-dir recon/example.com/asset-intel
```

Facet queries are built from the authorized target (operator-supplied `--org`/`--asn` facets are added only when declared). Bare IP results cannot match a domain scope, so they are retained only when the *query term itself* is in scope — the Shodan facet is constrained by that term, and out-of-scope cert/hostname matches never reach downstream tools. The live collector runs each query through `ipfinder --silent --source` with a per-query timeout and writes `shodan-facet-plans.jsonl`, `ipfinder-raw.txt`, and scope-filtered `ipfinder-assets.jsonl`.

## Defensive lateral-movement analysis

`tools/defensive_detection.py` analyzes supplied Windows, Sysmon, EDR, Zeek, NetFlow, OSQuery, or Velociraptor exports. It emits hypotheses for unusual logins, privilege changes, PowerShell, WMI, remote services, RDP, SMB, scheduled tasks, LOLBins, DNS anomalies, LDAP enumeration, peer traffic, process injection, and unusual outbound behavior.

It also emits **persistence (TA0003)**, **EDR-evasion**, and **in-memory
shellcode-runner** detection hypotheses:

- registry run-keys / `RunOnce` / startup-folder persistence;
- DLL/COM/IFEO (Image File Execution Options) hijack;
- Active Directory persistence (AdminSDHolder, DSRM, SIDHistory, DCShadow,
  golden ticket);
- Attack Surface Reduction (ASR) policy references;
- ETW, AMSI, and driver/syscall/BYOVD evasion signals;
- Sigma detection-rule artifacts (`logsource`, `attack.t*`, `detection`);
- in-memory execution signals from a shellcode-runner case review:
  private-memory allocation (`MEM_PRIVATE`), writable→executable transitions
  (`RW -> RX`), writes into executable memory, thread start outside a loaded
  module, high-entropy executable regions, mapped-file execution variants
  (`CreateFileMappingA`/`MapViewOfFile`), import-table execution signatures,
  dynamic resolution of execution primitives (`GetProcAddress` →
  `NtCreateThreadEx`), unsigned/untrusted-origin delivery, and
  obfuscated-at-rest payload bytes.

The in-memory taxonomy is deliberately **detection-side only**: it names what
an endpoint agent scores (the exact indicators a minimal runner triggers),
never how to build or mutate a runner. No evasion loop, artifact generator,
shellcode, or bypass primitive is constructed or executed.

```bash
python3 tools/defensive_detection.py \
  --path exported-security.log \
  --path zeek/conn.log \
  --rules \
  --output-dir defensive-review
```

These are **detection hypotheses only**: no persistence implant, evasion
primitive, driver, memory dump, or bypass technique is constructed or executed.
The analyzer stores line numbers and hashes rather than raw log lines and does
not collect telemetry, execute commands, dump memory, query AD, access
credentials, or move laterally.

## Identity and cloud posture

`tools/identity_cloud.py` performs static checks for:

- legacy authentication and MFA policy gaps;
- factor enrollment and account recovery boundaries;
- OAuth/OIDC/SAML redirect, signature, issuer, audience, and authentication-context controls;
- session expiry, revocation, rotation, and binding;
- wildcard cloud permissions and resources;
- public network/storage/serverless exposure;
- metadata and cross-account trust boundaries;
- environment-secret exposure in errors or debug output.

It also extracts CVE references as `unverified_reference` records requiring trusted advisory, product/version, policy, and lab checks. Nuclei templates can be ingested directly for triage:

```bash
python3 tools/identity_cloud.py \
  --path infrastructure/ \
  --path auth-config.json \
  --nuclei nuclei-templates/http/cves/2026/CVE-2026-40900.yaml \
  --plans \
  --output-dir posture-review
```

`parse_nuclei_template` reads `id:`, `cve-id`, and `reference` CVE references as
unverified triage records — it never executes or downloads the template.
`--seed` adds curated metadata-only records (including CVE-2026-18051 — W3
Total Cache unauthenticated file write — and CVE-2026-73570 — Zimbra SNMP RCE,
reported exploited in the wild) that still require trusted-source and
version confirmation before any testing.

No login attempts, MFA prompts, token replay, cloud mutations, metadata requests, credential validation, or exploit execution occur.

## Advanced IDOR planning

`tools/idor_research.py` expands object-reference analysis to direct IDs, UUIDs, encoded values, composite references, function-level actions, second-order references, files/exports, GraphQL, mobile APIs, and WebSockets — plus the common-vector surfaces: numeric path ids (`/users/42`), upload/download file names, client-supplied account headers (`X-Account-Id: 42`), id-bearing cookies (`userid=42; tenant=7`), GraphQL global node ids (`gid://` passed to `node(id:)` — the HackerOne #1618347 pattern, where composite ids like `gid://app/Type/group-id-program-id` leaked private program scope), JWT claim references (`"sub": 42`), and Android PendingIntent notification-hijack surfaces (`FLAG_IMMUTABLE` / explicit component checks). Chained mass-assignment escalation (the Buganizer-class chain: an accepted extra role/visibility field turning an IDOR into account/program takeover) is represented as planning notes on write operations.

Pass headers/cookies through the matrix planner as endpoint dict fields:

```python
plans = build_idor_matrix("example.com", [{
    "url": "https://example.com/api/orders", "method": "POST",
    "body": '{"target_user": 42}',
    "headers": "X-Account-Id: 42", "cookies": "tenant=7",
}], scope=scope)
```

The generated matrix requires:

- two cooperating authorized test accounts;
- disposable objects and synthetic data;
- response fingerprints instead of sensitive content;
- no sequential enumeration or bulk scraping;
- separate approval for reversible state changes.

The recon methodology output includes `idor-matrix.jsonl` alongside workflow and scanner validation plans.

## Execution boundary

The default for all tracks is `offline_only`. No provider, scanner, identity system, cloud API, endpoint, or host is contacted by these modules. Any later live validation must use the existing scope, environment preflight, execution controller, rate limits, test accounts, rollback plan, and human review gates.
