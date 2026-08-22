# Local Tooling & Vulnerability Coverage

This standalone reference file documents the local CLI tooling and web/API vulnerability classes that BugWolf agents may use when Claude Code execution is enabled.

## Local CLI Tool Support

When Claude Code can execute locally, BugWolf can orchestrate available tools directly after an authorized scope is loaded. The **full categorized catalog** — one PRIMARY tool per phase, install commands, and API-key notes — lives in `references/recon-tooling.md`. The recon engine (`tools/recon_engine.sh [--fast|--deep] --scope-file scope.json --confirm-active`) runs the PRIMARY of every phase with graceful fallbacks.

**Core recon (minimum):** `curl`, `subfinder`, `assetfinder`, `dnsx`, `httpx`, `katana`, `nuclei`, `trufflehog`, `ffuf`, `nmap`

**Deep recon (add for `--deep`):** `bbot`, `alterx`, `puredns`, `naabu`, `gowitness`, `feroxbuster`, `jsluice`, `subjs`, `linkfinder`, `x8`, `subzy`

**Fuzzing / exploitation:** `sqlmap`, `ghauri`, `wfuzz`, `zap`, `burpsuite`, `commix`, `arjun`, `afrog`

Use these tools for discovery, fuzzing, payload generation, proof-of-concept validation, and evidence collection.

## Deepseek Claude CLI Setup

For temporary Deepseek Pro usage:

```bash
export ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic
export ANTHROPIC_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash
export CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash
export CLAUDE_CODE_EFFORT_LEVEL=max
export ANTHROPIC_AUTH_TOKEN="your-deepseek-pro-token"

deepseek export --project . --key "$ANTHROPIC_AUTH_TOKEN" --mode pro
```

For Windows PowerShell:

```powershell
$env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
$env:ANTHROPIC_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_EFFORT_LEVEL = "max"
$env:ANTHROPIC_AUTH_TOKEN = "your-deepseek-pro-token"

deepseek export --project . --key $env:ANTHROPIC_AUTH_TOKEN --mode pro
```

## Broader Web/API Vulnerability Coverage

BugWolf is designed to hunt across a wide range of attack classes with no fixed payload limit.

- open redirect
- CSV injection
- SQL injection
- XSS (reflected, stored, DOM)
- SSRF
- command injection
- template injection
- path traversal
- insecure deserialization
- prototype pollution
- request smuggling
- parameter pollution
- HTTP response splitting
- host header injection
- cache poisoning
- business logic abuse
- IDOR
- CSRF
- OAuth redirect abuse
- privilege escalation

Agents should reason about these classes and use local tooling when available to verify and expand findings.
