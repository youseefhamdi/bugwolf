# BugWolf Static Chain and AI Defense Analysis

The latest write-ups describe high-impact chains, but their exploit steps are not imported into BugWolf. The plugin instead identifies source/configuration signals and produces validation and remediation plans.

## Application chains

Run:

```bash
python3 tools/chain_analyzer.py \
  --path src/ \
  --path package-lock.json \
  --output-dir chain-review
```

The analyzer covers:

- SQL/query construction next to database file or command capabilities;
- request-controlled upload paths next to filesystem writes and cron/system consumers;
- Java/Python/PHP/Ruby deserialization sinks and dependency/filter signals;
- response-header construction next to redirect, cache, or proxy boundaries;
- request input next to command execution sinks;
- XML parser sinks next to external-entity/DOCTYPE configuration, credential/config
  references, and persistence references — synthesized into a
  file-read → credential → database-auth → persistence chain plan.

Outputs are `static-findings.jsonl`, `chain-plans.jsonl`, and `manifest.json`. Findings contain source locations and hashes, not raw secrets or payloads.

The analyzer does not generate SQLi, OOB, cron, shell, deserialization, gadget, callback, or RCE payloads. It does not write to host paths, contact OAST/Burp Collaborator, execute commands, or dump data.

## AI and MCP defense

Run:

```bash
python3 tools/ai_defense.py \
  --path src/agent.py \
  --path config/mcp.json \
  --output-dir ai-defense-review
```

Signals include:

- prompt/instruction concatenation;
- indirect instructions from documents, email, web, retrieval, or tool output;
- keyword-only injection filters;
- model-selected tools and output-to-action flows;
- high-risk tools, persistent memory, and RAG tenant boundaries;
- MCP OAuth URLs, token passthrough, local process spawning, and broad scopes.

Plans apply defense in depth: structured prompts, data marking/spotlighting, quarantined inference, information-flow labels, deterministic tool authorization, plan-drift checks, short-lived least-privilege scopes, human approval, exact redirect validation, token audience validation, SSRF-safe URL handling, and local MCP sandboxing.

The analyzer does not call a model, send prompts, connect to MCP, open OAuth URLs, replay tokens, execute tools, or test jailbreaks against a live service.

## CVE and chain claims

Article-provided CVE identifiers, versions, CVSS scores, and exploitability claims remain unverified references until checked against trusted vendor/advisory sources and the actual affected version. A static chain is a hypothesis, not proof of reachability or impact.
