#!/usr/bin/env python3
"""Local deterministic PII masking for BugWolf AI/tool egress.

The firewall performs no model calls and persists no token mappings. It masks
known structured identifiers before an application sends content elsewhere.
Reversal is available only through the in-memory, request-bound TTL map.

Usage:
  python3 tools/pii_firewall.py --text 'Patient Jane Doe, email jane@example.com' --request-id case-123 --policy mask_and_warn
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import time
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


MAX_INPUT_CHARS = 2_000_000


@dataclass
class PIIEntity:
    entity_type: str
    start: int
    end: int
    value_hash: str
    normalized_key: str
    confidence: float
    detector: str


@dataclass
class MaskResult:
    masked_text: str
    entities: List[PIIEntity]
    warnings: List[str] = field(default_factory=list)
    request_id: str = ""
    residual_entities: List[PIIEntity] = field(default_factory=list)


@dataclass
class TokenEntry:
    token: str
    value: str
    entity_type: str
    normalized_key: str
    created_at: float
    expires_at: float
    request_id: str


@dataclass
class EgressDecision:
    allowed: bool
    masked_payload: Any
    warnings: List[str]
    entity_count: int
    residual_count: int
    policy: str = "mask_and_warn"


STRUCTURED_PATTERNS: Tuple[Tuple[str, re.Pattern[str], float], ...] = (
    ("email", re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b"), 0.99),
    ("ssn", re.compile(r"\b\d{3}[\- ]\d{2}[\- ]\d{4}\b"), 0.99),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .\-]?)?(?:\(?\d{2,4}\)?[ .\-]?)\d{3,4}[ .\-]\d{3,4}(?!\w)"), 0.86),
    ("credit_card", re.compile(r"\b(?:\d[ \-]?){13,19}\b"), 0.75),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE), 0.90),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.72),
    ("date", re.compile(r"\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\-\/]\d{1,2}[\-\/]\d{1,2})\b"), 0.78),
)

CONTEXT_PATTERNS: Tuple[Tuple[str, re.Pattern[str], float], ...] = (
    ("person", re.compile(r"(?i)\b(?:my|patient|client|customer|contact|name)\s*(?:name\s*)?(?:is|:)\s*([A-ZÀ-ÖØ-Ý][\wÀ-ÖØ-ÿ'\-]+(?:\s+[A-ZÀ-ÖØ-Ý][\wÀ-ÖØ-ÿ'\-]+){1,3}|[\u0600-\u06ff]+(?:\s+[\u0600-\u06ff]+){1,3})"), 0.80),
    ("address", re.compile(r"(?i)\b\d{1,6}\s+[A-Za-zÀ-ÿ0-9 .'-]+\s+(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|boulevard|blvd)\b"), 0.82),
)

FIELD_HINTS = {
    "email": "email", "e_mail": "email", "phone": "phone", "mobile": "phone",
    "ssn": "ssn", "social_security": "ssn", "credit_card": "credit_card",
    "card_number": "credit_card", "iban": "iban", "patient_name": "person",
    "full_name": "person", "address": "address", "date_of_birth": "date",
}


def normalize_for_detection(value: str) -> str:
    """Normalize Unicode and bidi controls without changing returned content."""
    value = unicodedata.normalize("NFKC", value)
    return "".join(ch for ch in value if unicodedata.category(ch) != "Cf")


def _normalized_key(entity_type: str, value: str) -> str:
    normalized = normalize_for_detection(value).casefold()
    if entity_type in {"phone", "ssn", "credit_card", "iban", "ipv4", "date"}:
        normalized = re.sub(r"[^0-9a-z]", "", normalized)
    else:
        normalized = re.sub(r"\s+", " ", normalized).strip()
    return entity_type + ":" + normalized


def _luhn(value: str) -> bool:
    digits = [int(ch) for ch in value if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect_entities(text: str, *, mask_person_names: bool = True) -> List[PIIEntity]:
    if len(text) > MAX_INPUT_CHARS:
        raise ValueError("input exceeds bounded PII analysis size")
    normalized_text = normalize_for_detection(text)
    entities: List[PIIEntity] = []
    for entity_type, pattern, confidence in STRUCTURED_PATTERNS:
        for match in pattern.finditer(normalized_text):
            value = match.group(0)
            if entity_type == "credit_card" and not _luhn(value):
                continue
            if entity_type == "ipv4":
                octets = [int(part) for part in value.split(".")]
                if any(part > 255 for part in octets):
                    continue
            entities.append(PIIEntity(entity_type, match.start(), match.end(),
                                      hashlib.sha256(value.encode()).hexdigest()[:16],
                                      _normalized_key(entity_type, value), confidence, "deterministic_regex"))
    if mask_person_names:
        for entity_type, pattern, confidence in CONTEXT_PATTERNS:
            for match in pattern.finditer(normalized_text):
                value = match.group(1) if match.lastindex else match.group(0)
                start = match.start(1) if match.lastindex else match.start()
                entities.append(PIIEntity(entity_type, start, start + len(value),
                                          hashlib.sha256(value.encode()).hexdigest()[:16],
                                          _normalized_key(entity_type, value), confidence, "context_regex"))
    return _dedupe_entities(entities)


def _dedupe_entities(entities: Iterable[PIIEntity]) -> List[PIIEntity]:
    ordered = sorted(entities, key=lambda item: (item.start, -(item.end - item.start), -item.confidence))
    kept: List[PIIEntity] = []
    for entity in ordered:
        if any(entity.start >= other.start and entity.end <= other.end for other in kept):
            continue
        kept = [other for other in kept if not (other.start >= entity.start and other.end <= entity.end)]
        kept.append(entity)
    return sorted(kept, key=lambda item: item.start)


class TokenVault:
    """Request-bound in-memory reversible mapping with TTL and no persistence."""

    def __init__(self, ttl_seconds: int = 300):
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise ValueError("ttl_seconds must be between 1 and 86400")
        self.ttl_seconds = ttl_seconds
        self._maps: Dict[str, Dict[str, TokenEntry]] = {}

    def _purge(self) -> None:
        now = time.time()
        for request_id in list(self._maps):
            self._maps[request_id] = {
                token: entry for token, entry in self._maps[request_id].items()
                if entry.expires_at > now
            }
            if not self._maps[request_id]:
                del self._maps[request_id]

    def token_for(self, request_id: str, entity_type: str, value: str, normalized_key: str) -> str:
        self._purge()
        mapping = self._maps.setdefault(request_id, {})
        for entry in mapping.values():
            if entry.normalized_key == normalized_key:
                return entry.token
        prefix = entity_type.upper()
        token = f"[[{prefix}_{len(mapping) + 1}]]"
        now = time.time()
        mapping[token] = TokenEntry(token, value, entity_type, normalized_key,
                                    now, now + self.ttl_seconds, request_id)
        return token

    def unmask(self, request_id: str, text: str) -> str:
        self._purge()
        mapping = self._maps.get(request_id, {})
        for token, entry in mapping.items():
            text = text.replace(token, entry.value)
        return text

    def clear(self, request_id: str) -> None:
        self._maps.pop(request_id, None)


class PIIFirewall:
    def __init__(self, *, ttl_seconds: int = 300, policy: str = "mask_and_warn"):
        if policy not in {"mask_and_warn", "fail_closed", "allow"}:
            raise ValueError("unsupported PII policy")
        self.vault = TokenVault(ttl_seconds)
        self.policy = policy

    def mask_text(self, text: str, request_id: str, *, mask_person_names: bool = True) -> MaskResult:
        normalized = normalize_for_detection(text)
        entities = detect_entities(normalized, mask_person_names=mask_person_names)
        replacements: List[Tuple[int, int, str]] = []
        for entity in entities:
            value = normalized[entity.start:entity.end]
            token = self.vault.token_for(request_id, entity.entity_type, value, entity.normalized_key)
            replacements.append((entity.start, entity.end, token))
        masked = normalized
        for start, end, token in sorted(replacements, reverse=True):
            masked = masked[:start] + token + masked[end:]
        residual = detect_entities(masked, mask_person_names=mask_person_names)
        warnings = []
        if residual:
            warnings.append(f"{len(residual)} possible residual PII span(s) remain after masking")
        return MaskResult(masked, entities, warnings, request_id, residual)

    def mask_json(self, payload: Any, request_id: str, *, mask_person_names: bool = True) -> Tuple[Any, MaskResult]:
        entities: List[PIIEntity] = []
        warnings: List[str] = []

        def walk(value: Any, field_name: str = "") -> Any:
            hint = FIELD_HINTS.get(field_name.casefold())
            if isinstance(value, str):
                if hint and value:
                    normalized = normalize_for_detection(value)
                    key = _normalized_key(hint, normalized)
                    token = self.vault.token_for(request_id, hint, normalized, key)
                    entities.append(PIIEntity(hint, 0, len(normalized), hashlib.sha256(normalized.encode()).hexdigest()[:16], key, 1.0, "field_name_rule"))
                    return token
                result = self.mask_text(value, request_id, mask_person_names=mask_person_names)
                entities.extend(result.entities)
                warnings.extend(result.warnings)
                return result.masked_text
            if isinstance(value, dict):
                return {key: walk(item, str(key)) for key, item in value.items()}
            if isinstance(value, list):
                return [walk(item, field_name) for item in value]
            return value

        masked = walk(copy.deepcopy(payload))
        return masked, MaskResult("", entities, sorted(set(warnings)), request_id)

    def mask_xml(self, xml_text: str, request_id: str, *, mask_person_names: bool = True) -> Tuple[str, MaskResult]:
        if re.search(r"<!DOCTYPE|<!ENTITY", xml_text, re.IGNORECASE):
            raise ValueError("DOCTYPE and ENTITY declarations are rejected")
        if len(xml_text) > MAX_INPUT_CHARS:
            raise ValueError("XML exceeds bounded PII analysis size")
        root = ET.fromstring(xml_text)
        entities: List[PIIEntity] = []
        warnings: List[str] = []
        def walk(element: ET.Element) -> None:
            if element.text:
                result = self.mask_text(element.text, request_id, mask_person_names=mask_person_names)
                element.text = result.masked_text
                entities.extend(result.entities)
                warnings.extend(result.warnings)
            for key, value in list(element.attrib.items()):
                result = self.mask_text(value, request_id, mask_person_names=mask_person_names)
                element.attrib[key] = result.masked_text
                entities.extend(result.entities)
                warnings.extend(result.warnings)
            for child in element:
                walk(child)
        walk(root)
        return ET.tostring(root, encoding="unicode"), MaskResult("", entities, sorted(set(warnings)), request_id)

    def prepare_egress(self, payload: Any, request_id: str, *, kind: str = "text", mask_person_names: bool = True) -> EgressDecision:
        if kind == "json":
            masked, result = self.mask_json(payload, request_id, mask_person_names=mask_person_names)
        elif kind == "xml":
            masked, result = self.mask_xml(str(payload), request_id, mask_person_names=mask_person_names)
        else:
            result = self.mask_text(str(payload), request_id, mask_person_names=mask_person_names)
            masked = result.masked_text
        if self.policy == "fail_closed" and result.residual_entities:
            allowed = False
        else:
            allowed = True
        return EgressDecision(allowed, masked, result.warnings, len(result.entities), len(result.residual_entities), self.policy)


def multilingual_rule_plans() -> List[Dict[str, Any]]:
    return [
        {"locale": "ar", "controls": ["NFKC and bidi-control normalization", "Arabic-Indic digit normalization", "Arabic PERSON/ORG/LOCATION detector review", "transliteration and dialect fixtures", "human review for low-confidence entities"], "status": "plan_only"},
        {"locale": "multilingual", "controls": ["structured regex detectors", "locale-specific phone/date/ID rules", "consensus merge by span and confidence", "golden fixtures per language", "fail-safe residual scan"], "status": "plan_only"},
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf local PII firewall")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text")
    group.add_argument("--json-file")
    group.add_argument("--xml-file")
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--ttl-seconds", type=int, default=300)
    parser.add_argument("--policy", choices=["mask_and_warn", "fail_closed", "allow"], default="mask_and_warn")
    parser.add_argument("--mask-person-names", action="store_true")
    args = parser.parse_args()
    firewall = PIIFirewall(ttl_seconds=args.ttl_seconds, policy=args.policy)
    if args.json_file:
        payload = json.loads(open(args.json_file, encoding="utf-8").read())
        decision = firewall.prepare_egress(payload, args.request_id, kind="json", mask_person_names=args.mask_person_names)
    elif args.xml_file:
        decision = firewall.prepare_egress(open(args.xml_file, encoding="utf-8").read(), args.request_id, kind="xml", mask_person_names=args.mask_person_names)
    else:
        decision = firewall.prepare_egress(args.text or "", args.request_id, mask_person_names=args.mask_person_names)
    print(json.dumps(asdict(decision), indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
