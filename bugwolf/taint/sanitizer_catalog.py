"""Sanitizer catalog — known safe functions that neutralise taint.

Each entry maps a sanitizer name to the regex pattern used to recognise
it.  When a taint flow passes through a recognised sanitizer, the flow's
``is_vulnerable`` flag is set to ``False`` and the sanitizer is recorded
in the ``TaintFlow.sanitizers`` tuple.

Schema: ``bugwolf-taint-v1``
"""

## Source: taint flow catalog (Phase 3.2 — sanitizers)
## License: bugwolf-MIT

from __future__ import annotations

from typing import Dict, List


SCHEMA = "bugwolf-taint-v1"


SANITIZERS: Dict[str, str] = {
    # SQL escaping
    "parameterized_query": "execute\\(.*%s|execute\\(.*\\?|execute\\(.*:\\d",
    "sqlalchemy_param": "text\\(|bindparam\\(",
    "pymysql_escape": "pymysql.escape_string\\(|MySQLdb.escape_string\\(",
    # HTML escaping
    "html_escape": "html.escape\\(|markupsafe.escape\\(|escape\\(",
    "django_escape": "django.utils.html.escape\\(",
    "bleach_clean": "bleach.clean\\(",
    "dompurify": "DOMPurify.sanitize\\(|sanitize-html\\(",
    # Command escaping
    "shlex_quote": "shlex.quote\\(|shlex.split\\(",
    "shell_escape": "shell-escape\\(|pipes.quote\\(",
    # Path traversal
    "secure_filename": "secure_filename\\(|werkzeug.utils.secure_filename\\(",
    "path_realpath": "os.path.realpath\\(|pathlib.Path.resolve\\(",
    "abspath_check": "os.path.abspath\\(|os.path.normpath\\(",
    # SSRF guards
    "url_validate": "urllib.parse.urlparse\\(|validators.url\\(",
    "ip_is_private": "ipaddress.ip_address\\(|is_private\\(",
    # Deserialization guards
    "yaml_safe_load": "yaml.safe_load\\(|yaml.load\\(.*Loader=SafeLoader",
    "json_safe": "json.loads\\(",
    # Redirect guards
    "url_has_allowed": "url_has_allowed_host_and_scheme\\(|is_safe_url\\(",
    # Generic escapes
    "int_cast": "int\\(|float\\(",
    "str_strip": "\\.strip\\(|\\.lower\\(|\\.upper\\(",
    "re_sub": "re.sub\\(|regex.replace\\(",
    "encoding_normalize": "unicodedata.normalize\\(",
    # Framework-specific
    "django_escapejs": "escapejs\\(|conditional_escape\\(",
    "jinja_autoescape": "autoescape=\\(|select_autoescape\\(",
    "ejs_escape": "ejs.escape\\(|he.encode\\(",
    "golang_html_escape": "html.EscapeString\\(|template.HTMLEscapeString\\(",
    "rust_ammonia": "ammonia::clean\\(",
    "rust_escape": "htmlescape::encode\\(",
    "java_escape_html": "StringEscapeUtils.escapeHtml\\(",
    "java_escape_sql": "EscapeUtils.escapeSql\\(",
    "solidity_require": "require\\(",
    "ts_node_validator": "validator\\.(escape|isEmail|isURL)\\(",
    "owasp_encoder": "Encoder.encodeForHTML\\(|Encode.forHtml\\(",
}


def is_sanitizer(name: str) -> bool:
    """Return True if ``name`` is a known sanitizer."""

    return name in SANITIZERS


def pattern_for(name: str) -> str:
    """Return the regex pattern for a known sanitizer.  Empty on miss."""

    return SANITIZERS.get(name, "")


def all_sanitizers() -> List[str]:
    """Return the list of known sanitizer names."""

    return list(SANITIZERS.keys())


def sanitizer_count() -> int:
    """Return the number of entries in the catalog."""

    return len(SANITIZERS)


__all__ = [
    "SANITIZERS",
    "is_sanitizer",
    "pattern_for",
    "all_sanitizers",
    "sanitizer_count",
    "CATEGORY_BY_SANITIZER",
    "category_for",
    "expand_sanitizers",
]


CATEGORY_BY_SANITIZER: Dict[str, str] = {
    "parameterized_query": "sqli",
    "sqlalchemy_param": "sqli",
    "pymysql_escape": "sqli",
    "html_escape": "xss",
    "django_escape": "xss",
    "bleach_clean": "xss",
    "dompurify": "xss",
    "shlex_quote": "command_injection",
    "shell_escape": "command_injection",
    "secure_filename": "lfi",
    "path_realpath": "lfi",
    "abspath_check": "lfi",
    "url_validate": "ssrf",
    "ip_is_private": "ssrf",
    "yaml_safe_load": "deserialization",
    "json_safe": "deserialization",
    "url_has_allowed": "redirect",
    "int_cast": "general",
    "str_strip": "general",
    "re_sub": "general",
    "encoding_normalize": "general",
    "django_escapejs": "xss",
    "jinja_autoescape": "ssti",
    "ejs_escape": "xss",
    "golang_html_escape": "xss",
    "rust_ammonia": "xss",
    "rust_escape": "xss",
    "java_escape_html": "xss",
    "java_escape_sql": "sqli",
    "solidity_require": "general",
    "ts_node_validator": "general",
    "owasp_encoder": "xss",
}


__all__.append("CATEGORY_BY_SANITIZER")


def category_for(name: str) -> str:
    """Return the vuln class neutralised by ``name``.  ``"unknown"`` on miss."""

    return CATEGORY_BY_SANITIZER.get(name, "unknown")


def expand_sanitizers(extra: Dict[str, str]) -> None:
    """Append ``extra`` sanitizers at runtime."""

    SANITIZERS.update(extra)


__all__.extend(["category_for", "expand_sanitizers"])


def category_coverage() -> Dict[str, int]:
    """Return a count of sanitizers per vuln class."""

    counts: Dict[str, int] = {}
    for name in SANITIZERS:
        cat = CATEGORY_BY_SANITIZER.get(name, "unknown")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


__all__.append("category_coverage")
