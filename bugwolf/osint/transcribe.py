"""Audio transcription — Whisper / SpeechRecognition.

Stub-safe: when no speech_recognition or whisper install is present,
:class:`Transcriber` returns a :class:`TranscriptUnavailable` result
instead of raising.

No third-party deps — only stdlib is required to *exist* as a module.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-transcribe-v1"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TranscriptSegment:
    start: float
    end: float
    text: str
    confidence: float = 0.0


@dataclass(frozen=True)
class Transcript:
    """Successful transcript."""
    text: str
    language: str
    segments: List[TranscriptSegment]
    source: str          # path / url
    engine: str          # "whisper" | "speech_recognition" | "stub"
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TranscriptUnavailable:
    """Transcript was not produced (and that is OK)."""
    reason: str
    source: str = ""
    engine: str = "none"


# ---------------------------------------------------------------------------
# Engine detection
# ---------------------------------------------------------------------------


def _has_whisper() -> bool:
    try:
        import importlib
        importlib.import_module("whisper")
        return True
    except ImportError:
        return False


def _has_speech_recognition() -> bool:
    try:
        import importlib
        importlib.import_module("speech_recognition")
        return True
    except ImportError:
        return False


def _http_get_bytes(url: str, *, timeout: float = 15.0) -> bytes:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "bugwolf-transcribe/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return b""


# ---------------------------------------------------------------------------
# Transcriber
# ---------------------------------------------------------------------------


class Transcriber:
    """Audio-to-text façade.

    All methods return either a :class:`Transcript` or a
    :class:`TranscriptUnavailable`.  Tests inspect the type to confirm
    the stub-safe behaviour.
    """

    def __init__(self, *, prefer: str = "whisper") -> None:
        if prefer not in ("whisper", "speech_recognition"):
            prefer = "whisper"
        self._prefer = prefer

    def transcribe(self, audio_path: Path, *,
                   language: str = "en") -> Any:
        path = Path(audio_path)
        if not path.exists():
            return TranscriptUnavailable(reason="file not found",
                                         source=str(path),
                                         engine="none")
        if self._prefer == "whisper" and _has_whisper():
            return self._whisper_transcribe(path, language=language)
        if _has_speech_recognition():
            return self._sr_transcribe(path, language=language)
        return self._stub_transcribe(path, language=language)

    def transcribe_url(self, url: str, *,
                       language: str = "en") -> Any:
        body = _http_get_bytes(url)
        if not body:
            return TranscriptUnavailable(reason="download failed",
                                         source=str(url),
                                         engine="none")
        digest = hashlib.sha256(body).hexdigest()[:16]
        tmp = Path("/tmp") / f"bugwolf-{digest}.audio"
        try:
            tmp.write_bytes(body)
        except OSError:
            return TranscriptUnavailable(reason="tmp write failed",
                                         source=str(url),
                                         engine="none")
        return self.transcribe(tmp, language=language)

    # -- engines ----------------------------------------------------------

    def _whisper_transcribe(self, path: Path, *, language: str) -> Any:
        try:
            import whisper  # type: ignore
            model = whisper.load_model("base")
            result = model.transcribe(str(path), language=language,
                                      fp16=False)
            segments = [
                TranscriptSegment(
                    start=float(seg.get("start") or 0.0),
                    end=float(seg.get("end") or 0.0),
                    text=str(seg.get("text") or "").strip(),
                    confidence=0.9,
                )
                for seg in (result.get("segments") or [])
            ]
            return Transcript(
                text=str(result.get("text") or "").strip(),
                language=language,
                segments=segments,
                source=str(path),
                engine="whisper",
            )
        except Exception as exc:  # noqa: BLE001
            return TranscriptUnavailable(
                reason=f"whisper error: {exc!r}",
                source=str(path),
                engine="whisper",
            )

    def _sr_transcribe(self, path: Path, *, language: str) -> Any:
        try:
            import speech_recognition as sr  # type: ignore
            recognizer = sr.Recognizer()
            with sr.AudioFile(str(path)) as source:
                audio = recognizer.record(source)
            text = recognizer.recognize_google(audio, language=language)
            return Transcript(
                text=str(text or ""),
                language=language,
                segments=[TranscriptSegment(0.0, 0.0, str(text or ""), 0.7)],
                source=str(path),
                engine="speech_recognition",
            )
        except Exception as exc:  # noqa: BLE001
            return TranscriptUnavailable(
                reason=f"speech_recognition error: {exc!r}",
                source=str(path),
                engine="speech_recognition",
            )

    def _stub_transcribe(self, path: Path, *, language: str) -> Any:
        # We do NOT raise.  We return a deterministic "not available"
        # result that tests / callers can branch on.
        return TranscriptUnavailable(
            reason="no speech_recognition installed",
            source=str(path),
            engine="none",
        )


__all__ = [
    "SCHEMA",
    "Transcriber",
    "Transcript",
    "TranscriptSegment",
    "TranscriptUnavailable",
]