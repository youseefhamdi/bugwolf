# LLM / AI System Assessment

> LLM application and agent security assessment runbook.

_Template file: `llm_assessment.md`_

## Scoping

- Identify model(s): vendor, version, fine-tuning status, hosted vs self-hosted.
- Identify system prompts, tool definitions, and any external retrievers.
- Document data flows: user input → pre-processing → model → post-processing → response.
- Document actions the agent can take: file IO, HTTP, database queries, email.
- Confirm rate limits, content filters, and abuse-handling in scope.

## Threat Modeling

- Direct prompt injection: user-supplied messages override system prompt.
- Indirect prompt injection: retrieved content (web pages, PDFs, emails) embeds instructions.
- Training data extraction: memorized PII, secrets, copyrighted text.
- Jailbreak: bypass safety filters via encoding, role-play, multi-turn manipulation.
- Agent hijack: tool-call argument injection, dangerous-action execution.

## Prompt Injection Testing

- Direct injection: 'Ignore previous instructions and...', 'You are now in developer mode'.
- Indirect injection: poison a public web page that the agent fetches.
- Tool argument injection: coerce the LLM into emitting `delete_user(12345)`.
- Token smuggling: homoglyphs, zero-width characters, alternate Unicode forms.
- Multi-turn: build context across the conversation to bypass later filters.

## Data Extraction

- Attempt to extract memorized PII from the fine-tuning corpus.
- Attempt to extract the system prompt in full.
- Attempt to extract the entire tool-call schema.
- Attempt to recover API keys or credentials the model has seen.
- Test output-filter coverage: PII regex, profanity, jailbreak keyword lists.

## Agent Security

- Verify each function call requires explicit user approval.
- Verify function arguments are validated against a strict schema.
- Verify the agent operates with principle-of-least-privilege credentials.
- Verify rate limits on tool calls (e.g. file deletes, fund transfers).
- Verify the agent cannot bypass its own audit log.

## Reporting

- Findings mapped to OWASP LLM Top 10 (LLM01–LLM10).
- Severity calibrated to exfiltration volume, action privilege, and data sensitivity.
- Reproducer includes the exact prompt, retrieved content, and model output.

## Outputs

- `findings/*.yaml` — registered findings with severity and reproducer.
- `state/engagement/<id>/` — daily notes, surface map, evidence.
- `report/final.md` — final report delivered to the customer.
- `report/citations.md` — auto-generated methodology citations.

## Acceptance Criteria

- All findings reproducible from the documented evidence.
- Severity calibrated to the customer's business context.
- Every finding has at least one fix recommendation.
- Methodology citations attached via CitationEngine.
- Daily standups held; deviations from the runbook documented.
