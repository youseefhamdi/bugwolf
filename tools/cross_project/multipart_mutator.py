#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter multipart_mutator.py:1-340 (1.5.c)
## Source: HackGATE multipart/fuzz.py:55-260
## License: MIT (sister projects)
## Port: 2026-09-05

10 multipart parser-confusion mutation techniques.

Multiparser libraries (Spring, Rack, Tomcat, Werkzeug, multer, fastapi,
nginx, Envoy) interpret multipart boundaries and field names differently.
A payload that one parser treats as benign can become a shell-include
or boundary-escape under a different parser.

Each technique returns a :class:`MultipartVariant` — a deterministic
serialised body + boundary + content-type header.

Techniques (10):
  prefix, suffix, name_alias, content_type_override, encoding_b64,
  nested_multipart, malformed_boundary, duplicate_field, unicode_name,
  transfer_encoding_chunked
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-multipart-mutator/v1"


_TECHNIQUE_NAMES = (
    "prefix", "suffix", "name_alias", "content_type_override",
    "encoding_b64", "nested_multipart", "malformed_boundary",
    "duplicate_field", "unicode_name", "transfer_encoding_chunked",
)


@dataclass(frozen=True)
class MultipartVariant:
    """One multipart mutation."""

    technique: str
    boundary: str
    field_name: str
    body: bytes
    content_type: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "technique": self.technique,
            "boundary": self.boundary,
            "field_name": self.field_name,
            "body_sha256": _sha256(self.body),
            "content_type": self.content_type,
            "extra": dict(self.extra),
        }


def _sha256(data: bytes) -> str:
    import hashlib as _hashlib
    return _hashlib.sha256(data).hexdigest()


def _build(boundary: str, field_name: str, content: bytes, *,
           ctype: str = "text/plain") -> bytes:
    body = (
        b"--" + boundary.encode("ascii") + b"\r\n"
        + b"Content-Disposition: form-data; name=\"" + field_name.encode("utf-8") + b"\"\r\n"
        + b"Content-Type: " + ctype.encode("ascii") + b"\r\n\r\n"
        + content + b"\r\n"
        + b"--" + boundary.encode("ascii") + b"--\r\n"
    )
    return body


class MultipartMutator:
    """Apply parser-confusion mutations to a multipart body."""

    SCHEMA = SCHEMA
    TECHNIQUES: List[str] = list(_TECHNIQUE_NAMES)

    def mutate(self, boundary: str, field_name: str,
               content: bytes) -> List[MultipartVariant]:
        """Return one variant per technique (10 total)."""
        variants: List[MultipartVariant] = []
        for t in self.TECHNIQUES:
            try:
                v = self._one(t, boundary, field_name, content)
            except Exception:  # noqa: BLE001 — never block the suite
                continue
            if v is not None:
                variants.append(v)
        return variants

    def _one(self, technique: str, boundary: str,
             field_name: str, content: bytes) -> Optional[MultipartVariant]:
        if technique == "prefix":
            new_b = boundary + "_x"
            return MultipartVariant(technique, new_b, field_name,
                                    _build(new_b, field_name, content),
                                    content_type="multipart/form-data; boundary=" + new_b)
        if technique == "suffix":
            new_b = "x_" + boundary
            return MultipartVariant(technique, new_b, field_name,
                                    _build(new_b, field_name, content),
                                    content_type="multipart/form-data; boundary=" + new_b)
        if technique == "name_alias":
            new_name = field_name + "_alias"
            return MultipartVariant(technique, boundary, new_name,
                                    _build(boundary, new_name, content),
                                    content_type="multipart/form-data; boundary=" + boundary)
        if technique == "content_type_override":
            new_body = _build(boundary, field_name, content,
                              ctype="application/json")
            return MultipartVariant(technique, boundary, field_name,
                                    new_body,
                                    content_type="multipart/form-data; boundary=" + boundary,
                                    extra={"ctype": "application/json"})
        if technique == "encoding_b64":
            enc = base64.b64encode(content)
            new_body = _build(boundary, field_name, enc,
                              ctype="text/plain; charset=base64")
            return MultipartVariant(technique, boundary, field_name,
                                    new_body,
                                    content_type="multipart/form-data; boundary=" + boundary,
                                    extra={"encoding": "base64"})
        if technique == "nested_multipart":
            inner_b = boundary + "_inner"
            inner = _build(inner_b, "inner", content)
            return MultipartVariant(technique, boundary, field_name,
                                    _build(boundary, field_name, inner),
                                    content_type="multipart/form-data; boundary=" + boundary,
                                    extra={"inner_boundary": inner_b})
        if technique == "malformed_boundary":
            new_b = boundary[:-2] + "ZZ" if len(boundary) > 2 else boundary + "ZZ"
            return MultipartVariant(technique, new_b, field_name,
                                    _build(new_b, field_name, content),
                                    content_type="multipart/form-data; boundary=" + new_b,
                                    extra={"malformed": True})
        if technique == "duplicate_field":
            # Duplicate field name in the same body — only one wins per
            # parser; the loser is the basis for many parser-confusion bugs.
            body = _build(boundary, field_name, content) + \
                _build(boundary, field_name, content).rsplit(b"--" + boundary.encode() + b"--\r\n", 1)[0]
            return MultipartVariant(technique, boundary, field_name, body,
                                    content_type="multipart/form-data; boundary=" + boundary,
                                    extra={"duplicate": True})
        if technique == "unicode_name":
            new_name = field_name + "-\u00e9"
            return MultipartVariant(technique, boundary, new_name,
                                    _build(boundary, new_name, content),
                                    content_type="multipart/form-data; boundary=" + boundary,
                                    extra={"unicode": True})
        if technique == "transfer_encoding_chunked":
            # Build a chunked-transfer-encoding variant
            chunk_size = hex(len(content))[2:].encode("ascii")
            from_email = chunk_size + b"\r\n" + content + b"\r\n0\r\n\r\n"
            new_body = (
                b"--" + boundary.encode("ascii") + b"\r\n"
                + b"Content-Disposition: form-data; name=\"" + field_name.encode("utf-8") + b"\"\r\n"
                + b"Content-Type: application/octet-stream\r\n"
                + b"Content-Transfer-Encoding: chunked\r\n\r\n"
                + from_email
                + b"--" + boundary.encode("ascii") + b"--\r\n"
            )
            return MultipartVariant(technique, boundary, field_name, new_body,
                                    content_type="multipart/form-data; boundary=" + boundary,
                                    extra={"chunked": True})
        return None


__all__ = ["SCHEMA", "MultipartVariant", "MultipartMutator"]