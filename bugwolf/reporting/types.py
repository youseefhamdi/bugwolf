# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-types-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-types-v1"

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_any(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.INFO
        s = str(value).strip().lower()
        mapping = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "high": cls.HIGH,
            "h": cls.HIGH,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "low": cls.LOW,
            "l": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "none": cls.INFO,
        }
        return mapping.get(s, cls.INFO)


class ReportFormat(Enum):
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"
    MARKDOWN = "md"
    H1 = "hackerone"
    BC = "bugcrowd"
    INTIGRITI = "intigriti"
    IMMUNEFI = "immunefi"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    target: str
    evidence: str
    confidence: float
    cvss_score: Optional[float] = None
    cwe: Optional[str] = None
    description: str = ""
    reproduction_steps: list = field(default_factory=list)
    references: list = field(default_factory=list)
    gate_result: Optional[dict] = None
    submission_ids: dict = field(default_factory=dict)
    source: str = "bugwolf"
    finding_class: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity.from_any(self.severity)
        if self.confidence is None:
            self.confidence = 0.0
        try:
            self.confidence = float(self.confidence)
        except (TypeError, ValueError):
            self.confidence = 0.0
        if self.confidence < 0.0:
            self.confidence = 0.0
        if self.confidence > 1.0:
            self.confidence = 1.0
        if self.cvss_score is not None:
            try:
                self.cvss_score = float(self.cvss_score)
            except (TypeError, ValueError):
                self.cvss_score = None
        if not isinstance(self.reproduction_steps, list):
            self.reproduction_steps = list(self.reproduction_steps) if self.reproduction_steps else []
        if not isinstance(self.references, list):
            self.references = list(self.references) if self.references else []
        if not isinstance(self.submission_ids, dict):
            try:
                self.submission_ids = dict(self.submission_ids)
            except Exception:
                self.submission_ids = {}


def finding_to_dict(f: Finding) -> dict:
    out = asdict(f)
    out["severity"] = f.severity.value
    return out


def finding_from_dict(d: dict) -> Finding:
    if d is None:
        d = {}
    if not isinstance(d, dict):
        d = {"title": str(d), "id": str(d)}
    d = dict(d)
    raw_id = d.get("id")
    f_id = "N/A" if raw_id is None or raw_id == "" else str(raw_id)
    raw_title = d.get("title")
    f_title = "N/A" if raw_title is None or raw_title == "" else str(raw_title)
    target = d.get("target", "N/A")
    if target is None or target == "":
        target = "N/A"
    evidence = d.get("evidence", "")
    if evidence is None:
        evidence = ""
    confidence = d.get("confidence", 0.0)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    cvss = d.get("cvss_score")
    if cvss is not None:
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = None
    cwe = d.get("cwe")
    if cwe is not None:
        cwe = str(cwe)
    description = d.get("description", "")
    if description is None:
        description = ""
    repro = d.get("reproduction_steps", [])
    if not isinstance(repro, list):
        try:
            repro = list(repro)
        except Exception:
            repro = [str(repro)]
    refs = d.get("references", [])
    if not isinstance(refs, list):
        try:
            refs = list(refs)
        except Exception:
            refs = [str(refs)]
    gate = d.get("gate_result")
    if gate is not None and not isinstance(gate, dict):
        try:
            gate = dict(gate)
        except Exception:
            gate = None
    sub_ids = d.get("submission_ids", {})
    if not isinstance(sub_ids, dict):
        try:
            sub_ids = dict(sub_ids)
        except Exception:
            sub_ids = {}
    return Finding(
        id=f_id,
        title=f_title,
        severity=Severity.from_any(d.get("severity", "info")),
        target=target,
        evidence=evidence,
        confidence=confidence,
        cvss_score=cvss,
        cwe=cwe,
        description=description,
        reproduction_steps=repro,
        references=refs,
        gate_result=gate,
        submission_ids=sub_ids,
        source=str(d.get("source", "bugwolf")),
        finding_class=str(d.get("finding_class") or d.get("klass") or d.get("category") or ""),
    )
