"""Chain loader: dedicated access path for multi-step exploit chains.

This complements ``MethodologySearch`` with a focused chain-catalog API.
The implementation is intentionally tiny — the heavy parsing logic
already lives in ``search._parse_chain``. ``ChainLoader`` simply walks
the ``chains/`` directory, parses each YAML file, validates the schema
and exposes lookup helpers.

Use:

    loader = ChainLoader(Path("bugwolf/methodology"))
    loader.load_all()                    # -> List[ChainSpec]
    loader.load("01_oauth_to_ato")       # -> Optional[ChainSpec]
    loader.by_final_severity("critical") # -> List[ChainSpec]

The loader is stub-safe: malformed YAML, missing keys and bad schemas
log a warning and the offending file is skipped — the rest of the
catalog remains available.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from bugwolf.methodology.search import (
    CHAIN_SCHEMA,
    ChainSpec,
    _parse_chain,
)

log = logging.getLogger(__name__)


class ChainLoader:
    """Read-only access to the chain catalog under ``<root>/chains``."""

    def __init__(self, root_path: Path | str) -> None:
        self.root_path = Path(root_path)
        self.chains_dir = self.root_path / "chains"
        self._chains: List[ChainSpec] = []
        self._by_id: Dict[str, ChainSpec] = {}
        self._loaded: bool = False

    @property
    def chains(self) -> List[ChainSpec]:
        return list(self._chains)

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load_all()
            self._loaded = True

    def load_all(self) -> List[ChainSpec]:
        """Walk the chains directory and parse every YAML file."""
        self._chains = []
        self._by_id = {}
        if not self.chains_dir.is_dir():
            log.warning("chains directory missing: %s", self.chains_dir)
            self._loaded = True
            return list(self._chains)

        for ext in ("*.yaml", "*.yml"):
            for yaml_path in sorted(self.chains_dir.rglob(ext)):
                self._load_one(yaml_path)

        self._loaded = True
        return list(self._chains)

    def _load_one(self, yaml_path: Path) -> None:
        try:
            raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            log.warning("chain YAML parse error %s: %s", yaml_path, exc)
            return
        except OSError as exc:
            log.warning("chain read error %s: %s", yaml_path, exc)
            return

        if not isinstance(raw, list):
            raw = [raw]

        for entry in raw:
            spec = _parse_chain(entry, str(yaml_path))
            if spec is None:
                continue
            if spec.chain_id in self._by_id:
                log.warning(
                    "duplicate chain id %s at %s (kept first)",
                    spec.chain_id,
                    yaml_path,
                )
                continue
            self._chains.append(spec)
            self._by_id[spec.chain_id] = spec

    def load(self, chain_id: str) -> Optional[ChainSpec]:
        """Direct lookup by chain id. Returns None if absent."""
        self._ensure_loaded()
        return self._by_id.get(chain_id)

    def ids(self) -> List[str]:
        """All loaded chain ids, sorted alphabetically."""
        self._ensure_loaded()
        return sorted(self._by_id.keys())

    def by_final_severity(self, severity: str) -> List[ChainSpec]:
        """Filter chains whose ``final_severity`` matches the given label."""
        self._ensure_loaded()
        target = severity.strip().lower()
        return [c for c in self._chains if c.final_severity.lower() == target]

    def by_prerequisite(self, prereq_id: str) -> List[ChainSpec]:
        """Chains that declare ``prereq_id`` as a prerequisite."""
        self._ensure_loaded()
        return [c for c in self._chains if prereq_id in c.prerequisites]

    def stats(self) -> Dict[str, int]:
        """Catalog summary: total chains + counts by final severity."""
        self._ensure_loaded()
        out: Dict[str, int] = {"total": len(self._chains)}
        for c in self._chains:
            sev = (c.final_severity or "unknown").lower()
            out[sev] = out.get(sev, 0) + 1
        return out

    def iter_steps(self, chain_id: str) -> Iterable[tuple]:
        """Yield ``(order, description)`` tuples for the given chain id.

        Returns an empty iterable if the chain is absent.
        """
        spec = self.load(chain_id)
        if spec is None:
            return tuple()
        return tuple((order, desc) for order, desc in spec.steps)


__all__ = ["ChainLoader", "CHAIN_SCHEMA"]