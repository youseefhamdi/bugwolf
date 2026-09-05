"""Source catalog — user-controlled entry points per framework.

Schema: ``bugwolf-taint-v1``
"""

## Source: taint flow catalog (Phase 3.2 — sources)
## License: bugwolf-MIT

from __future__ import annotations

from typing import Dict, List


SCHEMA = "bugwolf-taint-v1"


SOURCES: Dict[str, List[str]] = {
    "flask": [
        "request.args",
        "request.form",
        "request.json",
        "request.values",
        "request.cookies",
        "request.headers",
        "request.files",
        "request.data",
        "request.view_args",
        "request.args.get",
        "request.form.get",
        "request.json.get",
    ],
    "django": [
        "request.GET",
        "request.POST",
        "request.COOKIES",
        "request.META",
        "request.FILES",
        "request.body",
        "request.path",
        "request.GET.get",
        "request.POST.get",
        "self.request.GET",
        "self.request.POST",
    ],
    "fastapi": [
        "Request.body",
        "Request.json",
        "Request.headers",
        "Request.query_params",
        "Request.cookies",
        "Request.path_params",
        "Form(",
        "Query(",
        "Body(",
        "Header(",
        "Cookie(",
        "File(",
    ],
    "express": [
        "req.query",
        "req.body",
        "req.params",
        "req.headers",
        "req.cookies",
        "req.query.",
        "req.body.",
        "req.params.",
        "req.headers.",
        "req.cookies.",
    ],
    "koa": [
        "ctx.request.query",
        "ctx.request.body",
        "ctx.params",
        "ctx.request.headers",
        "ctx.cookies.get",
        "ctx.query.",
    ],
    "gin": [
        "c.Query(",
        "c.PostForm(",
        "c.GetHeader(",
        "c.Param(",
        "c.Request.URL.Query",
        "c.Request.Body",
    ],
    "echo": [
        "c.QueryParam(",
        "c.FormValue(",
        "c.Param(",
        "c.Get(",
        "c.Request().Body",
        "c.Cookie(",
    ],
    "actix": [
        "web::Query<",
        "web::Form<",
        "web::Json<",
        "web::Header<",
        "web::Path<",
        "HttpRequest::query",
    ],
    "spring-boot": [
        "@RequestParam",
        "@RequestBody",
        "@RequestHeader",
        "@PathVariable",
        "@CookieValue",
        "HttpServletRequest.getParameter",
        "HttpServletRequest.getHeader",
        "MultipartFile",
    ],
    "rails": [
        "params[",
        "params.fetch",
        "request.params",
        "request.headers",
        "request.cookies",
        "request.query_parameters",
    ],
    "laravel": [
        "$request->input",
        "$request->query",
        "$request->post",
        "$request->header",
        "$request->cookie",
        "$request->file",
        "$request->json()",
        "$request->all()",
    ],
    "generic": [
        "os.environ",
        "os.environ.get",
        "process.env",
        "std::env::var",
        "System.getenv",
        "std::env::args",
        "sys.argv",
        "process.argv",
        "System.in",
        "input()",
        "raw_input()",
        "readLine()",
    ],
}


def sources_for(framework: str) -> List[str]:
    """Return the source patterns for a framework.  Empty list on miss."""

    return SOURCES.get(framework, [])


def source_count() -> int:
    """Return the total number of source entries."""

    return sum(len(v) for v in SOURCES.values())


def all_source_patterns() -> List[str]:
    """Flatten the catalog."""

    patterns: List[str] = []
    for entries in SOURCES.values():
        patterns.extend(entries)
    return patterns


__all__ = ["SOURCES", "sources_for", "source_count", "all_source_patterns",
           "FRAMEWORK_LANGUAGE", "language_for_framework", "expand_sources"]


# Cross-reference: framework slug -> language slug.  Used by the
# cross-file analyzer to pick the right engine per request pattern.


FRAMEWORK_LANGUAGE: Dict[str, str] = {
    "flask": "python",
    "django": "python",
    "fastapi": "python",
    "express": "javascript",
    "koa": "javascript",
    "nest": "typescript",
    "next": "javascript",
    "gin": "go",
    "echo": "go",
    "chi": "go",
    "actix": "rust",
    "axum": "rust",
    "warp": "rust",
    "spring-boot": "java",
    "spring": "java",
    "jersey": "java",
    "rails": "ruby",
    "laravel": "php",
}


__all__.append("FRAMEWORK_LANGUAGE")


def language_for_framework(framework: str) -> str:
    """Return the language slug associated with ``framework``."""

    return FRAMEWORK_LANGUAGE.get(framework, "unknown")


def expand_sources(extra: Dict[str, List[str]]) -> None:
    """Append ``extra`` sources to the catalog at runtime."""

    for framework, patterns in extra.items():
        SOURCES.setdefault(framework, []).extend(patterns)


__all__.extend(["language_for_framework", "expand_sources"])


def detect_framework(source: str) -> Optional[str]:
    """Return the framework whose request pattern best matches ``source``."""

    for framework, patterns in SOURCES.items():
        for pat in patterns:
            if pat in source:
                return framework
    return None


def coverage_matrix() -> Dict[str, int]:
    """Return a dict mapping framework → count of source patterns."""

    return {fw: len(patterns) for fw, patterns in SOURCES.items()}


__all__.extend(["detect_framework", "coverage_matrix"])
