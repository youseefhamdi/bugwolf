## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL power schedule (afl-fuzz.c: afl-fuzz.h fast schedule formula)
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""AFL fast power schedule (split out for readability)."""
from __future__ import annotations

from bugwolf.fuzz.schedulers import AFLFastScheduler


SCHEMA = "bugwolf-fuzz-scheduler-afl-fast-v1"


__all__ = ["AFLFastScheduler"]
