# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

SCHEMA = "bugwolf-reporting-v1"

from .types import (
    SCHEMA as TYPES_SCHEMA,
    Severity,
    ReportFormat,
    Finding,
    finding_to_dict,
    finding_from_dict,
)
from .main import generate_report, batch_export
from .aggregator import aggregate, aggregate_from_files, stats

__all__ = [
    "finding_to_dict",
    "finding_from_dict",
    "Finding",
    "Severity",
    "ReportFormat",
    "generate_report",
    "batch_export",
    "aggregate",
    "aggregate_from_files",
    "stats",
]
