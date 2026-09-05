## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL cut-off edge schedule (COE) — recency-weighted selection
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Cut-off edge (COE) scheduler — split out for readability."""
from __future__ import annotations

from bugwolf.fuzz.schedulers import COEScheduler


SCHEMA = "bugwolf-fuzz-scheduler-coe-v1"


__all__ = ["COEScheduler"]
