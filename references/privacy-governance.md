# BugWolf Privacy and Data Governance Track

BugWolf now includes an offline privacy firewall for content that may be sent to LLMs, tools, logs, webhooks, or other downstream systems.

## PII firewall

```bash
python3 tools/pii_firewall.py \
  --text 'Patient Jane Doe, email jane@example.com, SSN 123-45-6789' \
  --request-id case-123 \
  --policy mask_and_warn
```

The firewall uses deterministic structured detectors and context rules for email, phone, SSN, payment cards, IBANs, IPs, dates, names, and addresses. It supports nested JSON and XML values. XML `DOCTYPE` and `ENTITY` declarations are rejected.

Masking uses request-bound tokens such as `[[EMAIL_1]]`. The original mapping remains only in an in-memory TTL vault and is never serialized to disk. Equivalent normalized values reuse the same token, so repeated names, dates, IDs, or contact values remain coherent to the downstream model.

`mask_and_warn` is the selected default: downstream code receives the masked value and warnings when possible residual PII remains. Integrators should log the warning without logging the original payload. `fail_closed` is available for stricter deployments.

The firewall is a preprocessing boundary, not a compliance certification. Production healthcare use requires authentication, access control, encrypted memory/process isolation, retention policy, key management, audit controls, language coverage, and legal/compliance review.

## Multilingual and Arabic planning

`multilingual_rule_plans()` emits implementation plans for Unicode/bidi normalization, Arabic-Indic digits, Arabic PERSON/ORG/LOCATION detection, transliteration, dialect fixtures, confidence consensus, and human review of low-confidence entities. No model download or external inference occurs.

## Kafka and schema governance

```bash
python3 tools/data_governance.py \
  --schema-file schemas/clinical-event.json \
  --topic clinical.events \
  --output-dir governance-review
```

The governance planner classifies schema fields into internal, confidential, or restricted-PII tiers and recommends:

- field-level encryption for restricted PII;
- TLS and broker-at-rest encryption;
- consumer and topic ACLs;
- schema annotation and compatibility enforcement;
- retention/deletion controls;
- field-level audit context including consumer, topic, schema version, field path, data-subject/request correlation, and timestamp.

It does not connect to Kafka, Schema Registry, KMS, consumers, or cloud APIs.

## Egress rule

Call the firewall before any LLM/tool/provider boundary. Never put the raw payload, token vault, original PHI, or reversible mapping into prompts, logs, evidence bundles, Kafka messages, or external API requests.
