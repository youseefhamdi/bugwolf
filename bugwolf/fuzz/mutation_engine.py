## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL mutation operators (https://github.com/AFLplusplus/AFLplusplus)
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Mutation engine for the BugWolf fuzzing substrate.

Implements a small AFL-style mutation operator set:

  * bit-flip       — flip 1/2/4 bits at random offsets
  * byte-flip      — flip 1/2/4 bytes at random offsets
  * interesting    — overwrite bytes with magic values (0, 1, MAX_INT, ...)
  * block-duplicate — splice a chunk from the input back in
  * dictionary     — substitute bytes from a user-supplied dictionary
  * crossover      — splice bytes from a second input

The engine is deterministic-by-default (seeded RNG) and never raises.
"""
from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-fuzz-mutation-v1"


# Magic values used by AFL's "interesting" mutator (8/16/32-bit variants).
_INTERESTING_8: Tuple[int, ...] = (0, 1, 0x10, 0x20, 0x40, 0x7F, 0x80, 0xFF)
_INTERESTING_16: Tuple[int, ...] = (
    0, 1, 0x80, 0x100, 0x1000, 0x7FFF, 0x8000, 0xFFFF,
)
_INTERESTING_32: Tuple[int, ...] = (
    0, 1, 0x80, 0x100, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
)


@dataclass
class MutationEngine:
    """Apply AFL-style mutations to a byte buffer.

    Parameters
    ----------
    seed:
        RNG seed for deterministic output.  ``None`` uses a random
        seed.
    dictionary:
        Optional iterable of byte-strings used by the dictionary
        mutation operator.
    """

    seed: Optional[int] = 0xC0FFEE
    dictionary: Tuple[bytes, ...] = ()
    _rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)
        self.dictionary = tuple(self.dictionary or ())

    # ----------------------------------------------------------------- API

    def mutate(self, input_bytes: bytes, n: int = 10) -> List[bytes]:
        """Return up to ``n`` mutated variants of ``input_bytes``."""
        try:
            n = max(0, int(n))
            if n == 0 or not input_bytes:
                return []
            out: List[bytes] = []
            for _ in range(n):
                variant = self._one_round(input_bytes)
                if variant is not None:
                    out.append(variant)
            return out
        except Exception:
            return []

    def mutate_one(self, input_bytes: bytes) -> bytes:
        """Return a single mutated variant (random operator)."""
        try:
            v = self._one_round(input_bytes)
            return v if v is not None else input_bytes
        except Exception:
            return input_bytes

    # ------------------------------------------------------------ internals

    def _one_round(self, data: bytes) -> Optional[bytes]:
        ops = [
            self._bit_flip,
            self._byte_flip,
            self._interesting_int,
            self._block_duplicate,
            self._dictionary_subst,
        ]
        op = self._rng.choice(ops)
        try:
            return op(data)
        except Exception:
            return None

    # ----------------------------- operators

    def _bit_flip(self, data: bytes) -> bytes:
        if not data:
            return data
        out = bytearray(data)
        idx = self._rng.randrange(len(out))
        bit = 1 << self._rng.randrange(8)
        out[idx] ^= bit
        return bytes(out)

    def _byte_flip(self, data: bytes) -> bytes:
        if not data:
            return data
        out = bytearray(data)
        idx = self._rng.randrange(len(out))
        out[idx] ^= 0xFF
        return bytes(out)

    def _interesting_int(self, data: bytes) -> bytes:
        if not data:
            return data
        out = bytearray(data)
        idx = self._rng.randrange(len(out))
        width = self._rng.choice((1, 2, 4))
        chunk = self._interesting_value(width)
        for i, b in enumerate(chunk):
            if idx + i >= len(out):
                break
            out[idx + i] = b
        return bytes(out)

    def _interesting_value(self, width: int) -> bytes:
        if width == 1:
            return bytes([self._rng.choice(_INTERESTING_8)])
        if width == 2:
            v = self._rng.choice(_INTERESTING_16)
            return struct.pack("<H", v & 0xFFFF)
        v = self._rng.choice(_INTERESTING_32)
        return struct.pack("<I", v & 0xFFFFFFFF)

    def _block_duplicate(self, data: bytes) -> bytes:
        if len(data) < 4:
            return data
        size = self._rng.randrange(1, max(2, len(data) // 4))
        start = self._rng.randrange(0, len(data) - size)
        block = data[start : start + size]
        insert_at = self._rng.randrange(0, len(data))
        return data[:insert_at] + block + data[insert_at:]

    def _dictionary_subst(self, data: bytes) -> bytes:
        if not self.dictionary:
            return self._interesting_int(data)
        token = self._rng.choice(self.dictionary)
        if not data:
            return token
        idx = self._rng.randrange(0, len(data))
        return data[:idx] + token + data[idx:]

    # ----------------------------- crossover

    def crossover(self, a: bytes, b: bytes) -> bytes:
        """Splice a chunk from ``b`` into ``a`` at a random offset."""
        try:
            if not a or not b:
                return a or b
            cut = self._rng.randrange(0, len(b))
            length = self._rng.randrange(1, max(2, len(b) - cut))
            chunk = b[cut : cut + length]
            insert_at = self._rng.randrange(0, len(a))
            return a[:insert_at] + chunk + a[insert_at:]
        except Exception:
            return a


__all__ = ["MutationEngine"]
