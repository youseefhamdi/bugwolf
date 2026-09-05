# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-redis-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Raw-TCP RESP2 Redis client.

No third-party ``redis`` package — we talk RESP2 over a plain socket so
the distributed layer works on a stdlib-only install.  All public
methods are STUB-SAFE: any connection error returns the
``_UNAVAILABLE`` sentinel (``None`` for typed-return methods); they
never raise.  ``reset()`` clears the "unavailable" latch so callers can
retry later.

The client is intentionally minimal — it covers only the verbs the
distributed pool uses (strings, lists, hashes, sets, blocking pop,
PING, EXPIRE).  Anything fancier should go through a proper
third-party client.
"""

from __future__ import annotations

import socket
from typing import Any, List, Optional, Sequence, Set, Tuple

try:
    from tools.core.medium_safety import runtime_check as _runtime_check
except Exception:  # pragma: no cover - tools.* not always importable
    def _runtime_check(condition, message):  # type: ignore[no-redef]
        if not condition:
            raise AssertionError(message)


SCHEMA = "bugwolf-distributed-redis-v1"


class _UnavailableType:
    """Sentinel class returned when Redis is unreachable."""

    _instance: Optional["_UnavailableType"] = None

    def __new__(cls) -> "_UnavailableType":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "<UNAVAILABLE>"

    def __bool__(self) -> bool:
        return False


_UNAVAILABLE: _UnavailableType = _UnavailableType()


class _State:
    CONNECTED = "connected"
    UNAVAILABLE = "unavailable"
    IDLE = "idle"


class RedisClient:
    """Lazy-connect, stub-safe RESP2 client."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        socket_timeout: float = 1.0,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.socket_timeout = float(socket_timeout)
        self._sock: Optional[socket.socket] = None
        self._state: str = _State.IDLE
        self._buf: bytes = b""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> bool:
        """Open a fresh TCP socket and verify with PING."""
        try:
            sock = socket.create_connection(
                (self.host, self.port), timeout=self.socket_timeout
            )
            sock.settimeout(self.socket_timeout)
            self._sock = sock
            self._buf = b""
            self._state = _State.CONNECTED
            self._send_raw(b"*1\r\n$4\r\nPING\r\n")
            line = self._recv_line()
            if not line or not line.startswith(b"+PONG"):
                self._state = _State.UNAVAILABLE
                try:
                    sock.close()
                except OSError:
                    pass
                self._sock = None
                return False
            return True
        except (OSError, socket.error, socket.timeout):
            self._state = _State.UNAVAILABLE
            self._sock = None
            return False

    def _send_raw(self, data: bytes) -> None:
        _runtime_check(self._sock is not None, "redis: socket closed")
        self._sock.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        _runtime_check(self._sock is not None, "redis: socket closed")
        while len(self._buf) < n:
            chunk = self._sock.recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise ConnectionError("redis closed connection")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _recv_line(self) -> bytes:
        _runtime_check(self._sock is not None, "redis: socket closed")
        while b"\r\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("redis closed connection")
            self._buf += chunk
        idx = self._buf.index(b"\r\n")
        out, self._buf = self._buf[:idx], self._buf[idx + 2:]
        return out

    def _ensure(self) -> bool:
        """Make sure we're connected.  Returns False if unavailable."""
        if self._state == _State.CONNECTED and self._sock is not None:
            return True
        if self._state == _State.UNAVAILABLE:
            return False
        return self._connect()

    def _encode_bulk(self, s: str) -> bytes:
        b = s.encode("utf-8", errors="replace")
        return b"$" + str(len(b)).encode("ascii") + b"\r\n" + b + b"\r\n"

    def _encode_command(self, args: Sequence[str]) -> bytes:
        out = bytearray()
        out += b"*" + str(len(args)).encode("ascii") + b"\r\n"
        for a in args:
            out += self._encode_bulk(a)
        return bytes(out)

    def _read_reply(self) -> Any:
        """Read one RESP reply from the wire."""
        _runtime_check(self._sock is not None, "redis: socket closed")
        line = self._recv_line()
        if not line:
            raise ConnectionError("empty reply")
        tag = line[:1]
        rest = line[1:]
        if tag == b"+":
            return rest.decode("utf-8", errors="replace")
        if tag == b"-":
            err = rest.decode("utf-8", errors="replace")
            raise RuntimeError(f"redis error: {err}")
        if tag == b":":
            try:
                return int(rest)
            except ValueError:
                return 0
        if tag == b"$":
            n = int(rest)
            if n < 0:
                return None
            data = self._recv_exact(n)
            self._recv_exact(2)  # trailing CRLF
            return data.decode("utf-8", errors="replace")
        if tag == b"*":
            n = int(rest)
            if n < 0:
                return None
            out: List[Any] = []
            for _ in range(n):
                out.append(self._read_reply())
            return out
        raise RuntimeError(f"unknown RESP tag: {tag!r}")

    def _send(self, *args: str) -> Any:
        """Send a command and read one reply.  Returns ``_UNAVAILABLE`` on failure."""
        if not self._ensure():
            return _UNAVAILABLE
        _runtime_check(self._sock is not None, "redis: socket closed")
        payload = self._encode_command(list(args))
        try:
            self._send_raw(payload)
            return self._read_reply()
        except (OSError, socket.error, socket.timeout, ConnectionError, RuntimeError):
            self._state = _State.UNAVAILABLE
            try:
                if self._sock is not None:
                    self._sock.close()
            except OSError:
                pass
            self._sock = None
            return _UNAVAILABLE

    # ------------------------------------------------------------------
    # Public verbs
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        r = self._send("PING")
        if isinstance(r, _UnavailableType):
            return False
        return r in ("PONG", True)

    def set(self, key: str, value: str) -> bool:
        r = self._send("SET", key, value)
        if isinstance(r, _UnavailableType):
            return False
        return r == "OK"

    def get(self, key: str) -> Optional[str]:
        r = self._send("GET", key)
        if isinstance(r, _UnavailableType) or r is None:
            return None
        return r

    def lpush(self, key: str, value: str) -> int:
        r = self._send("LPUSH", key, value)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def rpush(self, key: str, value: str) -> int:
        r = self._send("RPUSH", key, value)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def lpop(self, key: str) -> Optional[str]:
        r = self._send("LPOP", key)
        if isinstance(r, _UnavailableType) or r is None:
            return None
        return r

    def rpop(self, key: str) -> Optional[str]:
        r = self._send("RPOP", key)
        if isinstance(r, _UnavailableType) or r is None:
            return None
        return r

    def brpop(self, key: str, timeout: int = 1) -> Optional[Tuple[str, str]]:
        r = self._send("BRPOP", key, str(int(timeout)))
        if isinstance(r, _UnavailableType) or r is None:
            return None
        if isinstance(r, list) and len(r) == 2:
            return (r[0], r[1])
        return None

    def llen(self, key: str) -> int:
        r = self._send("LLEN", key)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def hset(self, key: str, field: str, value: str) -> int:
        r = self._send("HSET", key, field, value)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def hget(self, key: str, field: str) -> Optional[str]:
        r = self._send("HGET", key, field)
        if isinstance(r, _UnavailableType) or r is None:
            return None
        return r

    def hgetall(self, key: str) -> dict:
        r = self._send("HGETALL", key)
        if isinstance(r, _UnavailableType) or r is None:
            return {}
        if isinstance(r, list):
            out: dict = {}
            for i in range(0, len(r) - 1, 2):
                out[r[i]] = r[i + 1]
            return out
        return {}

    def hincrby(self, key: str, field: str, incr: int = 1) -> int:
        r = self._send("HINCRBY", key, field, str(int(incr)))
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def sadd(self, key: str, member: str) -> int:
        r = self._send("SADD", key, member)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def smembers(self, key: str) -> Set[str]:
        r = self._send("SMEMBERS", key)
        if isinstance(r, _UnavailableType) or r is None:
            return set()
        if isinstance(r, list):
            return set(r)
        return set()

    def sismember(self, key: str, member: str) -> int:
        r = self._send("SISMEMBER", key, member)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def srem(self, key: str, member: str) -> int:
        r = self._send("SREM", key, member)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def expire(self, key: str, seconds: int) -> int:
        r = self._send("EXPIRE", key, str(int(seconds)))
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def keys(self, pattern: str) -> List[str]:
        r = self._send("KEYS", pattern)
        if isinstance(r, _UnavailableType) or r is None:
            return []
        if isinstance(r, list):
            return r
        return []

    def delete(self, *keys: str) -> int:
        if not keys:
            return 0
        r = self._send("DEL", *keys)
        if isinstance(r, _UnavailableType) or r is None:
            return 0
        return int(r)

    def reset(self) -> None:
        """Force-close and clear the unavailable latch."""
        self._state = _State.IDLE
        self._buf = b""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


__all__ = ["RedisClient", "_UNAVAILABLE", "_UnavailableType", "SCHEMA"]
