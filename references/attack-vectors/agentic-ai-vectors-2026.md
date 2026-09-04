# Agentic AI Attack Vectors — 2026 Edition

Distilled from live research (Sept 2026): OWASP Top 10 for Agentic
Applications 2026, OWASP LLM Top 10 2025/2026, MCP security corpus
(Invariant Labs tool-poisoning advisory, CSA research notes, NSA CSI MCP
guidance, MCP stats: 97M+ monthly downloads, 82% vulnerable to path
traversal, 8.5% OAuth), Unit 42 in-the-wild web IDPI analysis (22
techniques), arXiv 2603.22489 MCP threat modeling.

## ASI-01..10 (OWASP Agentic Applications 2026)

| ID | Threat | BugWolf test pattern |
|---|---|---|
| ASI01 | **Agent Goal Hijack** (e.g. EchoLeak) | Feed agent-controlled content containing goal-override instructions; observe plan/tool divergence. Canary instructions only. |
| ASI02 | **Tool Misuse & Exploitation** (e.g. Amazon Q) | Enumerate agent tools; for each, attempt attacker-goal invocation via injected content (fetch attacker URL, send email, read cross-tenant doc). |
| ASI03 | **Agent Identity & Privilege Abuse** | Check whether agent runs with a human's full privileges; attempt privilege boundaries via tool calls the human could not make. |
| ASI04 | **Agentic Supply Chain Compromise** | Tool/plugin/skill registry poisoning; typosquatted MCP servers; rug-pull (benign at review, malicious after update). Diff tool descriptions over time. |
| ASI05 | **Unexpected Code Execution** | Agent-mediated execution paths: eval in generated code, shell out from tool args, template rendering of model output. |
| ASI06 | **Memory & Context Poisoning** | Persist canary instructions in memory/RAG/doc store consumed later; verify cross-session, cross-user propagation. |
| ASI07 | **Inter-Agent Communication Abuse** | Message spoofing between agents; trust-boundary traversal over agent buses; instructions in agent-to-agent payloads. |
| ASI08 | **Cascading Failures** | One compromised agent poisoning downstream agents' state; halt/interrupt abuse; resource loops. |
| ASI09 | **Human-Agent Trust Exploitation** | UI spoofing of agent approvals; misleading agent provenance; implicit-trust escalation ("the agent already checked"). |
| ASI10 | **Rogue Agents** | Agents that diverge from declared mission; hidden goals in system prompts; self-exfiltration behaviors. |

## MCP-specific vectors

1. **Tool poisoning** — malicious instructions embedded in tool
   descriptions/metadata (most prevalent client-side MCP attack; arXiv
   2603.22489). Test: dump all tool descriptions in context, scan for
   instruction-shaped content, canary-follow across tool boundaries.
2. **Rug pulls** — tool re-definition between approval and use. Test:
   snapshot descriptions, exercise repeatedly, diff.
3. **MCP server path traversal** — 82% of analyzed servers vulnerable.
   Test file-scoped tools with `../`, encoded, absolute-path inputs.
4. **Missing OAuth on servers** — 91.5% ship none. Test token storage,
   passthrough auth confusion, consent-screen omission.
5. **Client-side URL handling** — MCP servers triggering XSS/RCE via URL
   schemes (per modelcontextprotocol.io advisory 2026-07-28).
6. **Context poisoning** — shared state mutated by one server, consumed
   by another downstream.
7. **IDE auto-execution** — Cursor/VS Code-class IDEs auto-running MCP
   tool output; combined with tool poisoning = zero-click RCE.

## Web-based Indirect Prompt Injection (Unit 42 taxonomy)

### Delivery methods (how instructions hide in content)
- Zero-size font / opacity 0 / `visibility:none` / off-screen positioning
- HTML parser-ignored sections (comments, `<noscript>`, attribute values)
- Dynamic injection via post-load JavaScript
- URL fragment instructions (HashJack pattern: payload after `#`)
- Visible plaintext (relying on volume, not concealment)
- Layered redundancy: same payload via several methods (defeats partial
  sanitization)

### Jailbreak methods (how instructions evade filters)
- Invisible Unicode characters; multi-layer encoding
- Payload splitting across page sections
- Multilingual instructions (language-switch evasion)
- Syntax injection (role markers, fake system tags)

### Attacker intents (severity ladder — use for triage)
- **Low**: irrelevant output, anti-scraping, resource exhaustion
- **Medium**: decision-pipeline bias (recruitment/review manipulation),
  AI access restriction
- **High**: moderation bypass (first in-the-wild: AI ad-review evasion,
  Dec 2025), SEO poisoning, unauthorized transactions
- **Critical**: data destruction, sensitive info leakage, system-prompt
  leakage ("god mode" enabler), DoS/fork-bomb

## OWASP LLM Top 10 (2025/2026 alignment)

LLM01 Prompt Injection · LLM02 Insecure Output Handling · LLM03 Training
Data Poisoning · LLM04 Model DoS · LLM05 Supply Chain · LLM06 Sensitive
Information Disclosure · LLM07 Insecure Plugin Design · LLM08 Excessive
Agency · LLM09 Misinformation · LLM10 Unbounded Consumption.

## BugWolf operating rules for this surface

- Canary instructions only — never a payload that would damage a real
  pipeline (mirror the PII doctrine: one owned canary, then stop).
- The agent under test is a *target*: all BugWolf scope/sandbox/evidence
  rules apply to interactions with it.
- Any system-prompt leakage found is recorded (location + evidence), never
  weaponized into a full jailbreak chain without human approval.
