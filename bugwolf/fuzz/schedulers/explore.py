## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL explore schedule (uniform random baseline)
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Exploration scheduler (uniform random) — split out for readability."""
from __future__ import annotations

from bugwolf.fuzz.schedulers import ExploreScheduler


SCHEMA = "bugwolf-fuzz-scheduler-explore-v1"


__all__ = ["ExploreScheduler"]
