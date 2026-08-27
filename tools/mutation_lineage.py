#!/usr/bin/env python3
"""Stable mutation identifiers and lightweight coverage accounting."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

SCHEMA = "bugwolf/mutation-lineage/v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def mutation_id(*, surface: str, operation: str, variant: str,
                input_value: Any = "") -> str:
    raw = json.dumps({"surface": surface, "operation": operation,
                      "variant": variant, "input": input_value},
                     sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


@dataclass
class MutationRecord:
    mutation_id: str
    parent_id: str
    surface: str
    operation: str
    variant: str
    input_sha256: str
    outcome: str = "planned"
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"schema": SCHEMA, **asdict(self)}


class MutationLineage:
    def __init__(self, target: str = "", project_root: Optional[str] = None):
        root = Path(project_root or ".").expanduser().resolve()
        self.path = root / "state" / "research" / target.replace("/", "_") / "mutations.jsonl"
        self.records: Dict[str, MutationRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                data = json.loads(line)
                data.pop("schema", None)
                record = MutationRecord(**data)
                self.records[record.mutation_id] = record
            except (ValueError, TypeError, json.JSONDecodeError):
                continue

    def add(self, *, surface: str, operation: str, variant: str,
            input_value: Any = "", parent_id: str = "",
            outcome: str = "planned") -> MutationRecord:
        identifier = mutation_id(surface=surface, operation=operation,
                                 variant=variant, input_value=input_value)
        existing = self.records.get(identifier)
        if existing:
            return existing
        digest = hashlib.sha256(str(input_value).encode()).hexdigest()
        record = MutationRecord(identifier, parent_id, str(surface), str(operation),
                                str(variant), digest, str(outcome), _now())
        self.records[identifier] = record
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        return record

    def update_outcome(self, mutation_id_value: str, outcome: str) -> MutationRecord:
        record = self.records.get(mutation_id_value)
        if not record:
            raise ValueError(f"unknown mutation: {mutation_id_value}")
        record.outcome = str(outcome)
        self.path.write_text("".join(json.dumps(item.to_dict(), sort_keys=True) + "\n"
                                  for item in self.records.values()), encoding="utf-8")
        return record

    def report(self) -> Dict[str, Any]:
        by_outcome: Dict[str, int] = {}
        for record in self.records.values():
            by_outcome[record.outcome] = by_outcome.get(record.outcome, 0) + 1
        return {"schema": SCHEMA, "total": len(self.records),
                "by_outcome": by_outcome,
                "roots": sum(not r.parent_id for r in self.records.values())}
