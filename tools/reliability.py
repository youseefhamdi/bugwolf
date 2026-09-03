#!/usr/bin/env python3
"""Shared reliability primitives for uncensored BugWolf lab execution.

These controls are operational only: they do not authorize, scope, or block
research targets. They provide durable state, bounded resources, and searchable
records for the intentionally unrestricted lab runtime.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

try:
    from tools.evidence import redact
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from evidence import redact
    from runtime_paths import workspace_root

SCHEMA = "bugwolf-reliability/v1"
DEFAULT_TIMEOUT_SECONDS = 180.0
DEFAULT_OUTPUT_BYTES = 10_000_000
MAX_ARTIFACT_BYTES = 50_000_000


class ReliabilityError(RuntimeError):
    """Base error for operational reliability failures."""


class ResourceLimitError(ReliabilityError):
    """Raised when a configured operational resource limit is exceeded."""


class CorruptRecordError(ReliabilityError):
    """Raised when a strict record cannot be decoded or validated."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def operation_id() -> str:
    """Return a globally unique identifier for one operation."""
    return str(uuid.uuid4())


def ensure_disk_space(path: str | Path, required_bytes: int,
                      *, reserve_bytes: int = 0) -> None:
    """Fail clearly before an operation if the filesystem is too full."""
    if required_bytes < 0 or reserve_bytes < 0:
        raise ValueError("disk requirements must be non-negative")
    directory = Path(path).expanduser().resolve()
    while not directory.exists() and directory != directory.parent:
        directory = directory.parent
    usage = shutil.disk_usage(directory)
    needed = required_bytes + reserve_bytes
    if usage.free < needed:
        raise ResourceLimitError(
            f"insufficient disk space: need {needed} bytes, have {usage.free}")


def _validate_size(content: bytes, max_bytes: int) -> None:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if len(content) > max_bytes:
        raise ResourceLimitError(
            f"artifact is {len(content)} bytes, maximum is {max_bytes}")


def atomic_write_bytes(path: str | Path, content: bytes,
                       *, max_bytes: int = MAX_ARTIFACT_BYTES,
                       mode: Optional[int] = None) -> Path:
    """Write bytes atomically, fsyncing the file and parent directory."""
    destination = Path(path).expanduser()
    _validate_size(content, max_bytes)
    ensure_disk_space(destination.parent, len(content))
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp",
        dir=str(destination.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(destination.parent, os.O_DIRECTORY)
        except (AttributeError, OSError):
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_text(path: str | Path, content: str, *,
                      encoding: str = "utf-8",
                      max_bytes: int = MAX_ARTIFACT_BYTES,
                      mode: Optional[int] = None) -> Path:
    return atomic_write_bytes(
        path, str(content).encode(encoding), max_bytes=max_bytes, mode=mode)


def atomic_write_json(path: str | Path, value: Any, *,
                      max_bytes: int = MAX_ARTIFACT_BYTES) -> Path:
    return atomic_write_text(
        path,
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                   default=str) + "\n",
        max_bytes=max_bytes,
    )


@contextmanager
def locked_file(path: str | Path, mode: str = "a+",
                *, encoding: Optional[str] = "utf-8") -> Iterator[Any]:
    """Open and exclusively lock a file where supported."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    kwargs = {} if "b" in mode else {"encoding": encoding}
    stream = destination.open(mode, **kwargs)
    try:
        if fcntl is not None:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield stream
    finally:
        try:
            stream.flush()
            os.fsync(stream.fileno())
        except (OSError, ValueError):
            pass
        if fcntl is not None:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            except (OSError, ValueError):
                pass
        stream.close()


def append_jsonl(path: str | Path, record: Mapping[str, Any], *,
                 max_bytes: int = MAX_ARTIFACT_BYTES) -> None:
    """Append one redacted JSONL record under an exclusive lock."""
    line = json.dumps(redact(dict(record)), sort_keys=True,
                      ensure_ascii=False, default=str) + "\n"
    encoded = line.encode("utf-8")
    destination = Path(path).expanduser()
    if len(encoded) > max_bytes or (destination.exists() and
                                    destination.stat().st_size + len(encoded) > max_bytes):
        raise ResourceLimitError(
            f"JSONL artifact exceeds maximum size: {destination}")
    ensure_disk_space(destination.parent, len(encoded))
    with locked_file(destination, "a", encoding="utf-8") as stream:
        stream.write(line)


def read_jsonl(path: str | Path, *, strict: bool = False,
               max_line_bytes: int = MAX_ARTIFACT_BYTES) -> tuple[list[dict[str, Any]], list[str]]:
    """Read JSONL with line-level recovery and explicit corruption reporting."""
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    source = Path(path).expanduser()
    if not source.is_file():
        return records, errors
    with source.open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            if len(raw) > max_line_bytes:
                message = f"line {line_number}: exceeds {max_line_bytes} bytes"
                errors.append(message)
                if strict:
                    raise CorruptRecordError(message)
                continue
            try:
                value = json.loads(raw.decode("utf-8"))
                if not isinstance(value, dict):
                    raise TypeError("record is not an object")
                records.append(value)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
                message = f"line {line_number}: {type(exc).__name__}: {exc}"
                errors.append(message)
                if strict:
                    raise CorruptRecordError(message) from exc
    return records, errors


def validate_object(value: Any, *, required: Sequence[str] = (),
                    schema: str = SCHEMA) -> dict[str, Any]:
    """Small dependency-free object schema validator for model/tool records."""
    if not isinstance(value, dict):
        raise CorruptRecordError("record must be a JSON object")
    missing = [name for name in required if name not in value]
    if missing:
        raise CorruptRecordError(
            f"record missing required fields: {', '.join(missing)}")
    result = dict(value)
    if "schema" in result and result["schema"] != schema:
        raise CorruptRecordError(
            f"unsupported schema {result['schema']!r}; expected {schema!r}")
    result.setdefault("schema", schema)
    return result


def run_bounded_subprocess(command: Sequence[str], *, cwd: str | Path,
                           timeout: float = DEFAULT_TIMEOUT_SECONDS,
                           max_output_bytes: int = DEFAULT_OUTPUT_BYTES,
                           env: Optional[Mapping[str, str]] = None,
                           stdin: Any = subprocess.DEVNULL,
                           input_bytes: Optional[bytes] = None
                           ) -> subprocess.CompletedProcess[bytes]:
    """Run argv-only subprocesses with timeout, output cap, and cleanup.

    ``input_bytes`` feeds the child's stdin (implies PIPE); ``stdin`` is the
    Popen stdin handle used when no input payload is supplied.
    """
    if not command or any(not isinstance(item, str) for item in command):
        raise ValueError("command must be a non-empty string argv sequence")
    if timeout <= 0 or timeout > 3600:
        raise ValueError("timeout must be between 0 and 3600 seconds")
    if max_output_bytes <= 0 or max_output_bytes > MAX_ARTIFACT_BYTES:
        raise ValueError("max_output_bytes is outside the supported range")
    if input_bytes is not None and not isinstance(input_bytes, (bytes, bytearray)):
        raise ValueError("input_bytes must be bytes")
    if input_bytes is not None:
        stdin = subprocess.PIPE
    process: Optional[subprocess.Popen[bytes]] = None
    try:
        process = subprocess.Popen(
            list(command), cwd=str(Path(cwd).expanduser().resolve()),
            stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, env=dict(env) if env is not None else None)
        stdout, stderr = process.communicate(
            input=bytes(input_bytes) if input_bytes is not None else None,
            timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if process is not None:
            try:
                os.killpg(process.pid, 9)
            except (AttributeError, OSError):
                process.kill()
            stdout, stderr = process.communicate()
        else:
            stdout, stderr = b"", b""
        raise subprocess.TimeoutExpired(
            command, timeout, output=stdout[:max_output_bytes],
            stderr=stderr[:max_output_bytes]) from exc
    if len(stdout) > max_output_bytes or len(stderr) > max_output_bytes:
        raise ResourceLimitError(
            f"subprocess output exceeded {max_output_bytes} bytes")
    return subprocess.CompletedProcess(
        list(command), process.returncode if process is not None else -1,
        stdout, stderr)


def operation_record(*, action: str, target: str = "", status: str,
                     metadata: Optional[Mapping[str, Any]] = None,
                     command: Optional[Sequence[str]] = None,
                     model: str = "", tool: str = "") -> dict[str, Any]:
    """Build a structured operation record with UUID identity."""
    valid_states = {"planned", "attempted", "completed", "failed", "blocked"}
    if status not in valid_states:
        raise ValueError(f"unknown operation state: {status}")
    return {
        "schema": "bugwolf/operation/v1",
        "operation_id": operation_id(),
        "state": status,
        "action": str(action),
        "target": str(target),
        "model": str(model),
        "tool": str(tool),
        "command": list(command or []),
        "timestamp": utc_now(),
        "metadata": redact(dict(metadata or {})),
    }


def operation_log(project_root: Optional[str | Path] = None) -> Path:
    return workspace_root(project_root) / "state" / "operations" / "operations.jsonl"


def record_operation(record: Mapping[str, Any], *,
                     project_root: Optional[str | Path] = None) -> None:
    append_jsonl(operation_log(project_root), record)
