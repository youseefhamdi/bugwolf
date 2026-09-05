#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter skills_manifest.py:1-420 (1.5.h)
## Source: BugWolf configs/claude_skills.json (Phase 1.5 curated library)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

78-skill curated library loader.

Reads :file:`configs/claude_skills.json` and exposes the catalogue via
:class:`SkillManifest`.  Each :class:`Skill` carries:

  * ``name``              — short identifier
  * ``bug_class``         — taxonomy bucket
  * ``severity``          — low | medium | high | critical
  * ``technique``         — short technique label
  * ``requires_scope_verb`` — HTTP / network verb required to exercise it
  * ``description``       — one-line summary

Public API:
  * :class:`Skill`          — frozen dataclass
  * :class:`SkillManifest`  — loader + lookup
  * :attr:`SkillManifest.SKILL_COUNT` — expected skill count (78)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple


SCHEMA = "bugwolf-skill-manifest/v1"
EXPECTED_SKILL_COUNT = 78
DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent.parent.parent / "configs" / "claude_skills.json"


@dataclass(frozen=True)
class Skill:
    """A single skill entry from the curated library."""

    name: str
    bug_class: str
    severity: str
    technique: str
    requires_scope_verb: str
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "technique": self.technique,
            "requires_scope_verb": self.requires_scope_verb,
            "description": self.description,
        }


class SkillManifest:
    """Loader + lookup for the 78-skill curated library.

    The manifest is read from JSON; missing file -> empty manifest with a
    warning flag.  The orchestrator should treat an empty manifest as a
    configuration error rather than a silent degradation.
    """

    SCHEMA = SCHEMA
    SKILL_COUNT = EXPECTED_SKILL_COUNT

    def __init__(self, manifest_path: Optional[Path] = None) -> None:
        self._path = Path(manifest_path) if manifest_path else DEFAULT_MANIFEST_PATH
        self._skills: Dict[str, Skill] = {}
        self._loaded = False
        self._warning: str = ""
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def warning(self) -> str:
        return self._warning

    def _load(self) -> None:
        if not self._path.is_file():
            self._warning = f"manifest not found at {self._path}"
            self._loaded = True
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self._warning = f"manifest unreadable: {exc}"
            self._loaded = True
            return
        if not isinstance(data, Mapping):
            self._warning = "manifest is not a JSON object"
            self._loaded = True
            return
        rows = data.get("skills") or []
        if not isinstance(rows, list):
            self._warning = "manifest.skills is not a list"
            self._loaded = True
            return
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            try:
                skill = Skill(
                    name=str(row.get("name") or ""),
                    bug_class=str(row.get("bug_class") or ""),
                    severity=str(row.get("severity") or ""),
                    technique=str(row.get("technique") or ""),
                    requires_scope_verb=str(row.get("requires_scope_verb") or "GET"),
                    description=str(row.get("description") or ""),
                )
            except Exception:  # noqa: BLE001
                continue
            if skill.name:
                self._skills[skill.name] = skill
        self._loaded = True
        if len(self._skills) != EXPECTED_SKILL_COUNT:
            self._warning = (
                f"manifest has {len(self._skills)} skills, "
                f"expected {EXPECTED_SKILL_COUNT}"
            )

    def get_skill(self, name: str) -> Optional[Skill]:
        return self._skills.get(name)

    def list_skills(self) -> List[Skill]:
        return [self._skills[k] for k in sorted(self._skills.keys())]

    def by_bug_class(self, bug_class: str) -> List[Skill]:
        return [s for s in self.list_skills() if s.bug_class == bug_class]

    def by_severity(self, severity: str) -> List[Skill]:
        return [s for s in self.list_skills() if s.severity == severity]

    def count(self) -> int:
        return len(self._skills)


__all__ = [
    "SCHEMA", "EXPECTED_SKILL_COUNT", "DEFAULT_MANIFEST_PATH",
    "Skill", "SkillManifest",
]