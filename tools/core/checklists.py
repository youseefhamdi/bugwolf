#!/usr/bin/env python3
"""BugWolf Canonical Checklist Registry (2026 corpus).

Single source of truth for the operator-approved test catalog, distilled
from the uploaded 76-document corpus (2FA/MFA bypass, ATO, IDOR/BAC,
smuggling/desync, SSRF/host-header, API/SQLi, recon/dorks, cloud, business
logic, RCE/upload, XML/SAML, platform misconfig) and merged with the
pre-existing 2026 web catalogs (The-XSS-Rat checklist, OWASP LLM/Agentic).

Design rules:
  * Canonical IDs only: ``<LANE>-<NN>``. Every ID carries a source tag so
    an agent can cite which corpus document a test came from.
  * ``canary_safe`` marks tests provable with operator-owned data
    (matching the mission safety ceiling). Tests that require victim-side
    signals are tagged ``attest`` and demand a human checkpoint before use.
  * The registry is frozen data: tests are never appended at runtime;
    new techniques enter through the technique ledger, not here.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

SCHEMA = "bugwolf.checklists/1.0"

SOURCES = {
    "2fa": "corpus:001/030/058 2FA-bypass checklists",
    "mfa2026": "corpus:062 MFA bypass (10 real techniques 2026)",
    "reset": "corpus:055/072 password-reset checklists",
    "ato": "corpus:002/040 account-takeover patterns + ato-chains-2026",
    "session": "corpus:071 cookie/session checklist",
    "jwt": "corpus:004 JWT hacking",
    "saml": "corpus:036 SAML vulnerabilities",
    "idor": "corpus:020/025/069/070 IDOR + access-control corpus",
    "authn": "corpus:040/074 authentication-bypass playbook",
    "smugg": "corpus:044/045/048/050/073 smuggling + desync corpus",
    "hdr": "corpus:031/032 header/host-header corpus",
    "ssrf": "corpus:042/054 SSRF playbook",
    "api": "corpus:016/052/075 API security corpus",
    "sqli": "corpus:027/035/041/061 SQL-injection corpus",
    "logic": "corpus:003/047/049 business-logic + financial corpus",
    "rce": "corpus:018/022/034/038/051 RCE corpus",
    "upload": "corpus:068 file-upload cheatsheet",
    "xml": "corpus:006/036 XML/SAML attacks",
    "recon": "corpus:013/014/017/019/037/039/060 recon corpus",
    "cloud": "corpus:063/067 attacking-AWS + cloud pentest",
    "plat": "corpus:005/009/010/057/070 platform misconfig corpus",
    "mob": "corpus:076 android pentest checklist",
    "jsdom": "corpus:066 JS/DOM checklist",
    "xss": "corpus:026 XSS fundamentals",
    "gh": "corpus:019 github dorks",
    "fin": "corpus:047 NCC financially-oriented web apps",
}


@dataclass(frozen=True)
class ChecklistItem:
    item_id: str
    lane: str
    title: str
    source: str
    canary_safe: bool = True  # False => human checkpoint (attest) required

    def to_dict(self) -> Dict[str, str]:
        d = asdict(self)
        d["canary_safe"] = str(bool(self.canary_safe)).lower()
        return d


def _i(item_id: str, lane: str, title: str, source: str,
       canary_safe: bool = True) -> ChecklistItem:
    return ChecklistItem(item_id=item_id, lane=lane, title=title,
                         source=source, canary_safe=canary_safe)


# ---------------------------------------------------------------------------
# The catalog. Ordered per lane: cheapest/highest-yield first. IDs are
# canonical forever — a removed technique leaves a tombstone comment, never
# a reused ID.
# ---------------------------------------------------------------------------

_ITEMS: Tuple[ChecklistItem, ...] = (
    # -- AUTH lane: 2FA/MFA --------------------------------------------------
    _i("AUTH-01", "auth", "2FA code integrity: use own valid code in victim "
       "second step (missing user binding)", "2fa"),
    _i("AUTH-02", "auth", "2FA second-step account cookie swap "
       "(step1 mine / step2 theirs)", "2fa"),
    _i("AUTH-03", "auth", "OTP brute-force without lockout (parallel code "
       "request + guess)", "2fa"),
    _i("AUTH-04", "auth", "OTP re-use and non-expiry after new request "
       "(incl. 24h window)", "2fa"),
    _i("AUTH-05", "auth", "Response/status manipulation on verify "
       "(false->true, 4xx->200) via match&replace", "2fa"),
    _i("AUTH-06", "auth", "OTP leaked in trigger response, referer, or JS "
       "bundle", "2fa"),
    _i("AUTH-07", "auth", "Direct navigation past 2FA + referer spoof of "
       "the 2FA page URL", "2fa"),
    _i("AUTH-08", "auth", "2FA disable page: clickjacking iframe + CSRF "
       "without re-auth", "2fa", canary_safe=False),
    _i("AUTH-09", "auth", "Enabling 2FA does not expire pre-existing "
       "sessions", "2fa"),
    _i("AUTH-10", "auth", "Password reset/email change silently disables "
       "MFA", "mfa2026"),
    _i("AUTH-11", "auth", "Backup-code flows inherit 2FA weaknesses "
       "(replay, no rate limit, reset path)", "2fa"),
    _i("AUTH-12", "auth", "Null/000000/wildcard OTP acceptance; type "
       "juggling on code compare", "mfa2026"),
    _i("AUTH-13", "auth", "Session double-spend: complete 2FA in my flow, "
       "continue in victim flow (shared boolean)", "2fa"),
    _i("AUTH-14", "auth", "2026 MFA ladder: push-bombing fatigue, "
       "helpdesk social reset, SIM-swap attest paths", "mfa2026",
       canary_safe=False),
    _i("AUTH-15", "auth", "Cross-account 2FA linking via user-id body "
       "params (verify-for-wrong-user)", "ato"),

    # -- AUTH lane: password reset / login -----------------------------------
    _i("AUTH-16", "auth", "Reset token accepted across accounts "
       "(my token, victim email)", "reset"),
    _i("AUTH-17", "auth", "Host-header poisoning of reset links "
       "(attacker.com, X-Forwarded-Host, HTML injection variants)", "reset"),
    _i("AUTH-18", "auth", "Reset token leakage: response body, referer "
       "header, email HTML injection img beacon", "reset"),
    _i("AUTH-19", "auth", "Reset token null/0000/array/massive-value "
       "bypasses and tokenless reset", "reset"),
    _i("AUTH-20", "auth", "Cross-domain reset token reuse on sibling "
       "properties sharing the mechanism", "reset"),
    _i("AUTH-21", "auth", "Reset endpoint: user enumeration, missing rate "
       "limit, SQLi, parameter pollution", "reset"),
    _i("AUTH-22", "auth", "Race on reset/consume (parallel token use)",
       "reset"),
    _i("AUTH-23", "auth", "Unicode/IDN homograph email spoofing at "
       "registration and reset", "reset"),
    _i("AUTH-24", "auth", "Login/2FA flow: swap user identifier between "
       "steps (server verifies wrong user)", "authn"),
    _i("AUTH-25", "auth", "Session scope theft chain: subdomain takeover "
       "plus domain=.parent cookie (Uber/Roblox/Ubiquiti pattern)", "ato",
       canary_safe=False),
    _i("AUTH-26", "auth", "Cookie attributes: missing HttpOnly/Secure/"
       "SameSite; session not expiring on logout/password change", "session"),
    _i("AUTH-27", "auth", "Cookie value attacks: parameter pollution, "
       "session puzzling, donation, deserialization", "session"),
    _i("AUTH-28", "auth", "JWT: alg none/HS-RS confusion, jku/kid "
       "injection, weak HMAC secret, claim tampering", "jwt"),
    _i("AUTH-29", "auth", "SAML: signature wrapping XSW1-8, XML comment "
       "confusion, replay, recipient confusion", "saml"),
    _i("AUTH-30", "auth", "OAuth: account fusion/linking abuse, PKCE "
       "downgrade on open client registration, state-less flows", "ato"),

    # -- ACCESS lane: IDOR/BOLA/BAC ------------------------------------------
    _i("ACC-01", "access", "Sequential-ID swap on every body param "
       "(GraphQL variables, JSON, legacy form fields — not just URLs)",
       "idor"),
    _i("ACC-02", "access", "GraphQL node-ID substitution (base64 gid "
       "decode/retarget, incremental gid decrement)", "idor"),
    _i("ACC-03", "access", "Session-object misbinding: server trusts body "
       "identifier over session (Mozilla account-destroy pattern)", "idor"),
    _i("ACC-04", "access", "Unauthorized writes: delete/update other "
       "users' objects (certs, campaigns, drafts)", "idor"),
    _i("ACC-05", "access", "GUID leak strategy: mobile fat responses, "
       "CSV/PDF export metadata, duplicate-email error ID leaks", "idor"),
    _i("ACC-06", "access", "Cross-tenant boundary: global-object mistake "
       "(labels/tags without tenant_id in query)", "idor"),
    _i("ACC-07", "access", "Blind IDOR side channels: timing deltas, "
       "state changes on victim objects", "idor"),
    _i("ACC-08", "access", "Wrap/typed bypasses: array wrap, object wrap, "
       "wildcard, param pollution, json dup keys", "idor"),
    _i("ACC-09", "access", "HTTP verb and content-type matrix on guarded "
       "endpoints (GET->POST/DELETE, xml<->json, .json/.bak suffixes)",
       "idor"),
    _i("ACC-10", "access", "Case/normalization FLA bypass (Admin/ADMIN/"
       "/aDmin), path traversal object swap", "idor"),
    _i("ACC-11", "access", "Outdated API version and shadow-path authz "
       "gaps (v1 vs v3, admin/internal prefixes)", "api"),
    _i("ACC-12", "access", "GraphQL mutation input-type override (admin "
       "userId param without privilege check — scope-bypass ATO)", "idor"),
    _i("ACC-13", "access", "Search/export endpoint bulk leaks (bugs.json, "
       "invoice download, transaction history)", "idor"),
    _i("ACC-14", "access", "Checkout/payment object swap (saved card, "
       "cart, invoice id)", "idor"),
    _i("ACC-15", "access", "BFLA: call admin functions as low-priv user; "
       "hide/remove-param responses", "authn"),

    # -- INFRA lane: smuggling/desync/host-header/SSRF -----------------------
    _i("INF-01", "infra", "CL.TE baseline probe with timing oracle",
       "smugg"),
    _i("INF-02", "infra", "TE.CL probe with partial-read oracle",
       "smugg"),
    _i("INF-03", "infra", "TE.TE obfuscation ladder (xchunked, space/"
       "tab, dup headers, transfer-encoding: x)", "smugg"),
    _i("INF-04", "infra", "Differential diagnosis: prefer parity errors "
       "and content-length deltas over blind timing", "smugg"),
    _i("INF-05", "infra", "Klein variants: Content-Length junk headers, "
       "'wait for it' partial body, HTTP/1.2 CRS bypass, text/plain CRS "
       "blind spot", "smugg"),
    _i("INF-06", "infra", "CRLF-powered desync: nginx $uri injection "
       "(/%20HTTP/1.1%0d%0a), request splitting, RQP inside CDNs",
       "smugg"),
    _i("INF-07", "infra", "Browser-powered desync (client-side): CL.0 "
       "and pause-based variants", "smugg"),
    _i("INF-08", "infra", "Response-queue poisoning safety: never steal "
       "victim requests — demonstrate with attacker-owned only", "smugg"),
    _i("INF-09", "infra", "Host-header routing: password-reset poisoning, "
       "cache key injection, SSRF via virtual-host confusion", "hdr"),
    _i("INF-10", "infra", "Override header trust: X-Original-URL, "
       "X-Rewrite-URL, X-Forwarded-Host, X-Forwarded-For ACL bypass", "hdr"),
    _i("INF-11", "infra", "Header injection upgraded to critical: git "
       "push-option / internal trust-header smuggling (X-Stat pattern)",
       "hdr"),
    _i("INF-12", "infra", "SSRF surface census: webhooks, importers, PDF/"
       "screenshot renderers, transcoders, OAuth callbacks, link previews",
       "ssrf"),
    _i("INF-13", "infra", "Cloud metadata escalation: GCP /v1beta1 no-"
       "flavor-header trick, AWS IMDSv1, ?alt=json SSH-key leak (canary: "
       "metadata version banner only)", "ssrf"),
    _i("INF-14", "infra", "Redirect-chain SSRF (303 to metadata), DNS "
       "rebinding, filter bypass encodings", "ssrf"),
    _i("INF-15", "infra", "Blind SSRF via integrations and OAST "
       "per-hypothesis subdomain callbacks", "ssrf"),

    # -- API lane -------------------------------------------------------------
    _i("API-01", "api", "REST action enumeration across CRUD verbs on "
       "guarded objects", "api"),
    _i("API-02", "api", "Mass assignment: role/premium fields in "
       "registration and profile updates", "api"),
    _i("API-03", "api", "Excessive data exposure: diff API response vs "
       "rendered UI (PII baseline diff)", "api"),
    _i("API-04", "api", "Content-type confusion: xml<->json, SOAP-style "
       "bodies on REST, $.params tricks", "api"),
    _i("API-05", "api", "Rate-limit and pagination abuse (limit/page "
       "DoS, L7 resource exhaustion — capped)", "api"),
    _i("API-06", "api", "API version sprawl: mobile vs web vs "
       "developer endpoints diverge", "api"),
    _i("API-07", "api", "SQLi in JSON bodies with boolean/time oracle "
       "ladder (AND 1=1 vs 1=2 vs sleep)", "sqli"),
    _i("API-08", "api", "NoSQL/XPath/LDAP auth bypass operator sets",
       "sqli"),
    _i("API-09", "api", "GraphQL: introspection off => field-suggestion "
       "mining and schema reconstruction", "api"),
    _i("API-10", "api", "GraphQL batching/alias DoS and depth abuse "
       "(capped)", "api"),

    # -- LOGIC lane: financial/business --------------------------------------
    _i("LOG-01", "logic", "Price/quantity tampering: negative, zero, "
       "decimal, overflow, exponential-notation values", "logic"),
    _i("LOG-02", "logic", "Currency arbitrage: pay/refund across "
       "currencies and rounding boundaries", "fin"),
    _i("LOG-03", "logic", "Coupon/voucher: reuse, race, mass-assign "
       "multiple codes, apply outside eligibility", "logic"),
    _i("LOG-04", "logic", "Premium feature gating: client-side booleans, "
       "cookie/localStorage entitlement flags, refund-keeps-feature", "logic"),
    _i("LOG-05", "logic", "Refund/cancellation races (parallel refund "
       "requests)", "logic"),
    _i("LOG-06", "logic", "Payment webhook logic: alternative event types "
       "(failed/chargeback) mis-handled; nested-key ambiguity in parser",
       "logic"),
    _i("LOG-07", "logic", "Webhook signature downgrade: replay, timestamp "
       "skew, raw-body vs parsed-body HMAC mismatch", "logic"),
    _i("LOG-08", "logic", "Replay of callback/encrypted parameters "
       "(capture-replay on state changes)", "fin"),
    _i("LOG-09", "logic", "TOCTOU matrices on money transfer and order "
       "state (simultaneous transfer/purchase)", "fin"),
    _i("LOG-10", "logic", "Delivery charge/shipping tamper; free-tier "
       "boundary abuse", "logic"),
    _i("LOG-11", "logic", "Review/rating abuse: unverified badges, out-"
       "of-scale values, impersonation, duplicate ratings", "logic"),

    # -- RCE lane --------------------------------------------------------------
    _i("RCE-01", "rce", "Upload extension ladder: php5/phtml/phar, double "
       "ext, null byte, capitalization, .htaccess", "upload"),
    _i("RCE-02", "rce", "Upload content tricks: GIF89a magic, polyglot "
       "PDF, SVG with embedded XXE/SSRF, content-length minimization",
       "upload"),
    _i("RCE-03", "rce", "Upload filename injections: traversal, SQLi, "
       "command injection, XSS via filename", "upload"),
    _i("RCE-04", "rce", "ImageMagick/ImageTragick and EXIF parser "
       "command injection (proof: canary id echo only)", "rce"),
    _i("RCE-05", "rce", "PDF/export engine LFI/SSRF (WeasyPrint-style "
       "renderer fingerprinting, iframe injection)", "rce"),
    _i("RCE-06", "rce", "SSTI probe ladder on error pages and template "
       "fields (jinja/twig/velocity canary math)", "rce"),
    _i("RCE-07", "rce", "Insecure deserialization probes per runtime "
       "(php/java/python gadget canaries)", "rce"),
    _i("RCE-08", "rce", "Dependency confusion pre-check: internal "
       "package-name census from JS/CI leakage (never publish — report "
       "only)", "rce"),
    _i("RCE-09", "rce", "Regex-anchor upload validation gap (missing $ "
       "anchor — LogiGlobal pattern)", "rce"),
    _i("RCE-10", "rce", "Jira/Confluence CVE ladder (2017-9506, 2019-"
       "8451, 2019-3396, 2020-14181, 2022-26135)", "plat"),

    # -- XML lane --------------------------------------------------------------
    _i("XML-01", "xml", "Classical XXE file-read via request/response "
       "bodies (file:// canary)", "xml"),
    _i("XML-02", "xml", "OOB XXE with per-hypothesis OAST subdomain",
       "xml"),
    _i("XML-03", "xml", "Blind XXE: local DTD triggers, error-based "
       "exfil", "xml"),
    _i("XML-04", "xml", "XXE via file formats: SVG, DOCX/XLSX/PPTX, "
       "PDF, SOAP, XMP, XMLRPC", "xml"),
    _i("XML-05", "xml", "XInclude and wrapper tricks (php:// expect:// "
       "filter chains)", "xml"),
    _i("XML-06", "xml", "SAML XML injection and signature wrapping "
       "toolkit (SAML Raider ladder)", "saml"),
    _i("XML-07", "xml", "Billion-laughs/quadratic blowup (DoS — "
       "operator-approval only, single doc)", "xml", canary_safe=False),
    _i("XML-08", "xml", "XSLT server-side injection probes (document() "
       "and script canaries)", "xml"),

    # -- RECON lane ------------------------------------------------------------
    _i("RCN-01", "recon", "CT-log census: wildcard expansion, ghost "
       "subdomains, SAN third-party correlations, reissuance timelines",
       "recon"),
    _i("RCN-02", "recon", "GitHub census: org/repo dork ladder, ghp_ "
       "token spray, CI/CD workflow exposure, git-history mining", "gh"),
    _i("RCN-03", "recon", "Shodan/Censys: favicon hash, ssl cert org, "
       "non-standard ports (8443/9090/3000), staging banners", "recon"),
    _i("RCN-04", "recon", "Staging census: crt.sh patterns (staging/dev/"
       "qa/uat/sandbox/preprod), AltDNS permutations, broken-link "
       "hijacking", "recon"),
    _i("RCN-05", "recon", "Scope-tiered recon: small=dir/tech/port/"
       "wayback; medium=+subenum/takeover/cloud; large=+ASN/subsidiaries/"
       "IP-space", "recon"),
    _i("RCN-06", "recon", "JS census: sourcemaps, buildManifest routes, "
       "webpack chunks, secret sweep (6-group regex), endpoint miners",
       "recon"),
    _i("RCN-07", "recon", "Mobile: APK unpack, hardcoded keys, shadow "
       "APIs, gRPC-web proto extraction, Firebase .json open reads", "mob"),
    _i("RCN-08", "recon", "Historical: gau/waymore diff of deprecated-"
       "but-live endpoints and dead params", "recon"),
    _i("RCN-09", "recon", "Cloud storage: S3/GCS/Azure naming patterns, "
       "bucket takeover candidates, public listing probes", "cloud"),
    _i("RCN-10", "recon", "Acquisition census: Crunchbase/Wikipedia "
       "subsidiaries, reverse whois, tracker/favicon fingerprint pivots",
       "recon"),

    # -- CLOUD lane --------------------------------------------------------------
    _i("CLD-01", "cloud", "IAM privesc graph: sts:AssumeRole chains, "
       "iam:PassRole, policy mutation edges", "cloud"),
    _i("CLD-02", "cloud", "Metadata service exposure (IMDSv1 vs v2, "
       "GCP beta path) — banner-only proof", "cloud"),
    _i("CLD-03", "cloud", "S3/lambda/snapshot misconfig census: open "
       "bucket policies, shared AMIs/EBS/RDS snapshots", "cloud"),
    _i("CLD-04", "cloud", "OIDC trust and pipeline injection: GitHub "
       "Actions token claims, self-hosted runner exposure", "cloud"),
    _i("CLD-05", "cloud", "Azure/O365: getuserrealm federation, tenant "
       "ID, context-file theft patterns (attest-only)", "cloud",
       canary_safe=False),

    # -- CLIENT lane -------------------------------------------------------------
    _i("CLI-01", "client", "DOM sink census: location.*, eval-family, "
       "srcdoc, jQuery ajax, FileReader, setRequestHeader", "jsdom"),
    _i("CLI-02", "client", "Reflected/stored XSS with ART payload "
       "families and context-aware encoding", "xss"),
    _i("CLI-03", "client", "PostMessage origin validation, prototype "
       "pollution, DOM clobbering", "jsdom"),
    _i("CLI-04", "client", "Cache-deception delimiter ladder against "
       "session-bearing endpoints (second-account proof)", "session"),

    # -- PLATFORM lane -----------------------------------------------------------
    _i("PLT-01", "platform", "Admin-panel bypass: default creds census, "
       "response manipulation, param removal, nodejs/php parser quirks",
       "plat"),
    _i("PLT-02", "platform", "AEM dispatcher bypass ladder (.css/.html/"
       ";%0a suffixes, servlet selectors, querybuilder dumps)", "plat"),
    _i("PLT-03", "platform", "JIRA exposure census: user/portal/filters "
       "dorks, mypermissions unauth checks", "plat"),
    _i("PLT-04", "platform", "Default-cred/service census: PeopleSoft, "
       "Jenkins, Grafana, swagger-ui on non-standard ports", "plat"),
    _i("PLT-05", "platform", "wc-db/.svn/source-disclosure probes",
       "plat"),
    _i("PLT-06", "platform", "PII over-exposure census: advertising/"
       "custom-audience inference, PII baseline diffs beyond one canary "
       "(attest-only)", "plat", canary_safe=False),
)

_CHECKLISTS: Dict[str, ChecklistItem] = {i.item_id: i for i in _ITEMS}

# Bug class -> applicable checklist IDs (drives dispatch slices).
_CLASS_MAP: Dict[str, Tuple[str, ...]] = {
    "mfa_bypass": ("AUTH-01", "AUTH-03", "AUTH-04", "AUTH-05", "AUTH-06",
                   "AUTH-09", "AUTH-10", "AUTH-11", "AUTH-12", "AUTH-13",
                   "AUTH-14", "AUTH-15"),
    "account_takeover": ("AUTH-15", "AUTH-16", "AUTH-17", "AUTH-24",
                         "AUTH-25", "AUTH-30", "ACC-03", "ACC-12"),
    "auth_bypass": ("AUTH-24", "AUTH-28", "AUTH-29", "AUTH-30", "ACC-10",
                    "ACC-15", "PLT-01"),
    "session_abuse": ("AUTH-09", "AUTH-13", "AUTH-25", "AUTH-26",
                      "AUTH-27"),
    "idor": ("ACC-01", "ACC-02", "ACC-03", "ACC-04", "ACC-05", "ACC-07",
             "ACC-08", "ACC-09", "ACC-12", "ACC-13", "ACC-14"),
    "bola": ("ACC-01", "ACC-02", "ACC-04", "ACC-06", "ACC-13", "ACC-14"),
    "bfla": ("ACC-10", "ACC-11", "ACC-15", "PLT-01"),
    "mass_assignment": ("ACC-08", "API-02", "LOG-03"),
    "request_smuggling": ("INF-01", "INF-02", "INF-03", "INF-04", "INF-05",
                          "INF-06", "INF-07", "INF-08"),
    "host_header": ("INF-09", "INF-10", "INF-11", "AUTH-17"),
    "ssrf": ("INF-12", "INF-13", "INF-14", "INF-15", "CLD-02"),
    "cache_deception": ("CLI-04",),
    "cache_poisoning": ("INF-09", "INF-10"),
    "sql_injection": ("API-07", "API-08", "ACC-08"),
    "nosql_injection": ("API-08",),
    "business_logic": ("LOG-01", "LOG-02", "LOG-03", "LOG-04", "LOG-05",
                       "LOG-06", "LOG-07", "LOG-08", "LOG-09", "LOG-10",
                       "LOG-11"),
    "race_condition": ("AUTH-22", "LOG-05", "LOG-09"),
    "rce": ("RCE-01", "RCE-02", "RCE-03", "RCE-04", "RCE-06", "RCE-07",
            "RCE-09", "RCE-10"),
    "command_injection": ("RCE-03", "RCE-04"),
    "file_upload": ("RCE-01", "RCE-02", "RCE-03", "RCE-09"),
    "lfi": ("RCE-05", "XML-01", "RCE-03"),
    "ssti": ("RCE-06",),
    "deserialization": ("RCE-07", "AUTH-27"),
    "dependency_confusion": ("RCE-08", "CLD-04"),
    "xxe": ("XML-01", "XML-02", "XML-03", "XML-04", "XML-05"),
    "saml": ("XML-06", "AUTH-29"),
    "recon": ("RCN-01", "RCN-02", "RCN-03", "RCN-04", "RCN-05", "RCN-06",
              "RCN-08", "RCN-10"),
    "js_secrets": ("RCN-02", "RCN-06"),
    "shadow_api": ("ACC-11", "API-06", "RCN-07"),
    "cloud_misconfig": ("CLD-01", "CLD-03", "RCN-09"),
    "iam_privesc": ("CLD-01",),
    "pipeline_injection": ("CLD-04",),
    "xss": ("CLI-01", "CLI-02", "CLI-03"),
    "dom_clobbering": ("CLI-01", "CLI-03"),
    "postmessage": ("CLI-03",),
    "mobile": ("RCN-07",),
    "platform_misconfig": ("PLT-01", "PLT-02", "PLT-03", "PLT-04",
                           "PLT-05"),
    "pii_exposure": ("API-03", "PLT-06", "ACC-13"),
    # -- corpus-v3 agent classes -------------------------------------------
    "otp_bypass": ("AUTH-03", "AUTH-04", "AUTH-05", "AUTH-06", "AUTH-12"),
    "two_factor_bypass": ("AUTH-01", "AUTH-02", "AUTH-07", "AUTH-08",
                          "AUTH-09", "AUTH-13", "AUTH-15"),
    "webhook_abuse": ("LOG-06", "LOG-07", "LOG-08", "LOG-09", "LOG-05"),
    "payment_logic": ("LOG-01", "LOG-02", "LOG-06", "LOG-07", "LOG-09"),
    "entitlement_bypass": ("LOG-03", "LOG-04", "LOG-11"),
    "replay_attack": ("LOG-08", "AUTH-22", "LOG-05"),
    "rounding_abuse": ("LOG-02", "LOG-01"),
    "surface_expansion": ("RCN-01", "RCN-03", "RCN-04", "RCN-05",
                          "RCN-08", "RCN-10"),
    "staging_exposure": ("RCN-04", "RCN-05"),
    "takeover_candidate": ("RCN-01", "RCN-03", "RCN-09", "AUTH-25"),
    "acquired_assets": ("RCN-10", "RCN-05"),
    "port_exposure": ("RCN-03", "PLT-04"),
    "aem_exposure": ("PLT-02",),
    "jira_exposure": ("PLT-03",),
    "default_credentials": ("PLT-01", "PLT-04"),
    "source_disclosure": ("PLT-05",),
    "xml_injection": ("XML-01", "XML-05", "XML-04"),
    "xslt_injection": ("XML-08",),
    "soap_attack": ("XML-04", "XML-06"),
    "image_parser_rce": ("RCE-04", "RCE-02"),
    "regex_validation_gap": ("RCE-09", "RCE-01"),
    "lfi_to_rce": ("RCE-05", "XML-01", "RCE-01"),
    "header_injection": ("INF-09", "INF-10", "INF-11", "AUTH-17"),
    "routing_confusion": ("INF-09", "INF-10"),
}


class ChecklistError(KeyError):
    """Unknown checklist ID."""


def get(item_id: str) -> ChecklistItem:
    key = str(item_id or "").strip().upper()
    if key not in _CHECKLISTS:
        raise ChecklistError(item_id)
    return _CHECKLISTS[key]


def slice_for_bug_class(bug_class: str) -> List[str]:
    """Canonical checklist IDs applicable to a bug class (ordered)."""
    return list(_CLASS_MAP.get(str(bug_class or "").strip().lower(), ()))


def slice_for_bug_classes(bug_classes: List[str]) -> List[str]:
    """Merged, canonical-ordered slice across classes.

    Output order follows the registry's canonical item order regardless of
    input order — same classes in any order yield the identical slice.
    """
    pos = {i.item_id: n for n, i in enumerate(_ITEMS)}
    seen = set()
    for bug in bug_classes or []:
        for item_id in slice_for_bug_class(bug):
            seen.add(item_id)
    return sorted(seen, key=lambda i: pos.get(i, len(pos)))


def lane(item_id: str) -> str:
    return get(item_id).lane


def attest_ids(ids: Optional[List[str]] = None) -> List[str]:
    """IDs requiring a human checkpoint before execution."""
    pool = ids if ids is not None else list(_CHECKLISTS)
    return [i for i in pool if i in _CHECKLISTS and
            not _CHECKLISTS[i].canary_safe]


def inventory() -> Dict[str, object]:
    lanes: Dict[str, int] = {}
    for item in _ITEMS:
        lanes[item.lane] = lanes.get(item.lane, 0) + 1
    return {
        "schema": SCHEMA,
        "total": len(_ITEMS),
        "lanes": dict(sorted(lanes.items())),
        "attest_count": len(attest_ids()),
        "sources": SOURCES,
    }


def all_ids() -> List[str]:
    return [i.item_id for i in _ITEMS]


def main() -> int:
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(description="BugWolf checklist registry")
    ap.add_argument("--inventory", action="store_true")
    ap.add_argument("--slice", default="",
                    help="comma-separated bug classes")
    ap.add_argument("--item", default="")
    args = ap.parse_args()
    if args.inventory:
        print(_json.dumps(inventory(), indent=2))
    elif args.slice:
        print(_json.dumps(slice_for_bug_classes(
            [s.strip() for s in args.slice.split(",") if s.strip()]),
            indent=2))
    elif args.item:
        print(_json.dumps(get(args.item).to_dict(), indent=2))
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
