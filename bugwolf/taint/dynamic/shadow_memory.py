"""Shadow memory — per-byte taint-bit tracking for dynamic analysis.

A *shadow memory* maps every byte of the program's address space to a
taint label.  Operations on the real memory mirror to operations on the
shadow:

  * ``record(addr, label)`` — set the shadow byte for ``addr`` to ``label``.
  * ``propagate(src, dst, n)`` — copy taint bits from ``src`` to ``dst``
    for ``n`` bytes.
  * ``read(addr)`` — return the current taint label for ``addr``.

This module is **stub-safe**: addresses outside ``[0, capacity)`` yield
an empty label rather than raising.

**Production deployment path**: pair with an mmap'ed region of ``(1 <<
cap_bits)`` bytes, one taint byte per program byte.  See the README for
the recommended ``--shadow-map`` flag.

Schema: ``bugwolf-taint-v1``
"""

## Source: dynamic taint shadow memory (Phase 3.2 — stub-safe)
## License: bugwolf-MIT

from __future__ import annotations

from typing import Dict, Iterable, Tuple


SCHEMA = "bugwolf-taint-v1"


class ShadowMemory:
    """Per-address taint label table."""

    def __init__(self, capacity: int = 1 << 16) -> None:
        self.capacity = int(capacity)
        self._store: Dict[int, str] = {}

    # Core operations ---------------------------------------------------------

    def record(self, address: int, label: str) -> bool:
        """Set taint label for ``address``.  Returns ``False`` on OOB."""

        if not self._in_range(address):
            return False
        if not label:
            return False
        self._store[int(address)] = str(label)
        return True

    def propagate(self, src: int, dst: int, n: int = 1) -> int:
        """Copy taint bits from ``[src, src+n)`` to ``[dst, dst+n)``.

        Returns the number of bytes propagated.
        """

        if n <= 0:
            return 0
        propagated = 0
        for offset in range(int(n)):
            s = int(src) + offset
            d = int(dst) + offset
            if not (self._in_range(s) and self._in_range(d)):
                continue
            label = self._store.get(s)
            if label is None:
                continue
            self._store[d] = label
            propagated += 1
        return propagated

    def read(self, address: int) -> str:
        """Return the taint label for ``address``.  ``""`` when unset / OOB."""

        if not self._in_range(address):
            return ""
        return self._store.get(int(address), "")

    def clear(self) -> None:
        """Reset every shadow byte."""

        self._store.clear()

    def labels(self) -> Iterable[Tuple[int, str]]:
        """Iterate over every (address, label) pair."""

        return iter(self._store.items())

    # Bulk helpers ------------------------------------------------------------

    def merge(self, other: "ShadowMemory", base: int = 0) -> int:
        """Merge ``other``'s labels into this one starting at ``base``.

        Returns the number of labels merged.
        """

        merged = 0
        for addr, label in other.labels():
            target = int(base) + int(addr)
            if self._in_range(target):
                self._store[target] = label
                merged += 1
        return merged

    def snapshot(self) -> Dict[int, str]:
        """Return a shallow copy of the current label table."""

        return dict(self._store)

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, address: int) -> bool:
        return int(address) in self._store

    # Internals ---------------------------------------------------------------

    def _in_range(self, address: int) -> bool:
        try:
            return 0 <= int(address) < self.capacity
        except (TypeError, ValueError):
            return False


def empty_shadow() -> ShadowMemory:
    """Return an empty :class:`ShadowMemory` with default capacity."""

    return ShadowMemory()


__all__ = ["ShadowMemory", "empty_shadow", "propagate_range", "touched_addresses",
           "labels_in_range"]


def propagate_range(shadow: ShadowMemory, base: int, n: int, label: str) -> int:
    """Record ``label`` for every address in ``[base, base+n)``.

    Returns the number of addresses recorded.
    """

    count = 0
    for offset in range(int(n)):
        if shadow.record(int(base) + offset, label):
            count += 1
    return count


def touched_addresses(shadow: ShadowMemory) -> List[int]:
    """Return the sorted list of addresses that currently have a label."""

    return sorted(addr for addr, _ in shadow.labels())


def labels_in_range(shadow: ShadowMemory, base: int, n: int) -> Dict[int, str]:
    """Return labels for every recorded address inside ``[base, base+n)``."""

    out: Dict[int, str] = {}
    upper = int(base) + int(n)
    for addr, label in shadow.labels():
        if int(base) <= addr < upper:
            out[addr] = label
    return out
