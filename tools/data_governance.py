#!/usr/bin/env python3
"""Offline data-governance planning for Kafka and schema artifacts.

No brokers, schema registries, KMS services, or consumers are contacted. The
module produces classification and audit plans from local JSON/Avro/Proto-like
schema files and topic manifests.

Usage:
  python3 tools/data_governance.py --schema-file schemas/event.json --topic clinical.events --output-dir governance-review
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class FieldClassification:
    path: str
    field_type: str
    classification: str
    rationale: str
    encryption_tier: str
    audit_required: bool


@dataclass
class TopicGovernancePlan:
    topic: str
    classification: str
    encryption: str
    consumer_controls: List[str]
    retention_controls: List[str]
    audit_controls: List[str]
    status: str = "offline_plan_only"


PII_FIELD_RULES = (
    (re.compile(r"(?i)(email|phone|mobile|ssn|social.?security|passport|driver|national.?id|address|dob|birth|patient|medical|health|diagnos|biometric|card|iban|account)"), "restricted-pii", "Field name indicates personal, health, or financial data"),
    (re.compile(r"(?i)(name|location|ip|device|cookie|session|user.?id|customer.?id)"), "confidential", "Field may identify or correlate a person or session"),
)


def classify_field(path: str, field_type: str = "string") -> FieldClassification:
    for pattern, classification, rationale in PII_FIELD_RULES:
        if pattern.search(path):
            if classification == "restricted-pii":
                return FieldClassification(path, field_type, classification, rationale, "field-level-encryption", True)
            return FieldClassification(path, field_type, classification, rationale, "broker-at-rest-plus-ACL", True)
    return FieldClassification(path, field_type, "internal", "No restricted field hint detected; verify with data owner", "broker-at-rest-plus-TLS", False)


def classify_schema(value: Any, prefix: str = "") -> List[FieldClassification]:
    results: List[FieldClassification] = []
    if isinstance(value, dict):
        if "properties" in value and isinstance(value["properties"], dict):
            for name, child in value["properties"].items():
                path = f"{prefix}.{name}" if prefix else str(name)
                child_type = child.get("type", "object") if isinstance(child, dict) else "unknown"
                if isinstance(child, dict) and "properties" in child:
                    results.extend(classify_schema(child, path))
                if not isinstance(child, dict) or "properties" not in child:
                    results.append(classify_field(path, child_type))
        else:
            for name, child in value.items():
                if name in {"type", "title", "description", "$schema", "required", "items"}:
                    continue
                path = f"{prefix}.{name}" if prefix else str(name)
                if isinstance(child, dict):
                    results.extend(classify_schema(child, path))
                else:
                    results.append(classify_field(path, type(child).__name__))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            results.extend(classify_schema(child, f"{prefix}[{index}]"))
    return _dedupe(results)


def _dedupe(fields: Iterable[FieldClassification]) -> List[FieldClassification]:
    result: Dict[str, FieldClassification] = {}
    for field in fields:
        result[field.path] = field
    return sorted(result.values(), key=lambda field: field.path)


def topic_plan(topic: str, classification: str = "internal") -> TopicGovernancePlan:
    if classification == "restricted-pii":
        return TopicGovernancePlan(topic, classification, "field-level-encryption-with-per-field-keys",
            ["consumer ACLs scoped to fields/use cases", "deny consumers without key access", "schema annotation required"],
            ["restricted retention", "deletion/DSAR procedure", "no unrestricted replay"],
            ["field decryption audit", "consumer identity", "subject/trace correlation", "long-term protected retention"])
    if classification == "confidential":
        return TopicGovernancePlan(topic, classification, "TLS-plus-broker-at-rest-encryption",
            ["least-privilege topic ACLs", "consumer identity logging"],
            ["approved retention", "replay approval"],
            ["topic read audit", "schema change audit"])
    return TopicGovernancePlan(topic, classification, "TLS-plus-broker-at-rest-encryption",
        ["topic ACLs", "service identity"], ["documented retention"], ["topic read audit"])


def audit_requirements(fields: Iterable[FieldClassification]) -> Dict[str, Any]:
    restricted = [field.path for field in fields if field.classification == "restricted-pii"]
    return {
        "field_level_audit_required": bool(restricted),
        "restricted_fields": restricted,
        "required_context": ["consumer identity", "topic", "schema version", "field path", "data subject/request correlation", "timestamp"],
        "fail_closed_conditions": ["missing field classification", "schema compatibility violation", "consumer lacks field authorization"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf offline data governance planner")
    parser.add_argument("--schema-file", action="append", default=[])
    parser.add_argument("--topic", action="append", default=[])
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    fields: List[FieldClassification] = []
    for filename in args.schema_file:
        path = Path(filename)
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            fields.extend(classify_schema(value, path.stem))
        except json.JSONDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                match = re.search(r"(?:name|field)\s*[:=]\s*[\"']?([A-Za-z0-9_.-]+)", line, re.I)
                if match:
                    fields.append(classify_field(f"{path.stem}.{match.group(1)}"))
    fields = _dedupe(fields)
    topics = [topic_plan(topic, "restricted-pii" if any(field.classification == "restricted-pii" for field in fields) else "internal") for topic in args.topic]
    with (output / "field-classification.jsonl").open("w", encoding="utf-8") as handle:
        for row in fields:
            handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    with (output / "topic-governance.jsonl").open("w", encoding="utf-8") as handle:
        for row in topics:
            handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    manifest = {"schema": "bugwolf-data-governance-v1", "fields": len(fields), "topics": len(topics), "audit": audit_requirements(fields), "execution": "offline_schema_only"}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
