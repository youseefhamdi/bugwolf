#!/usr/bin/env bash
#
# BugWolf Recon Engine v1.0.0
# Full pipeline: subdomains → permutations → resolve → live → port → vhost →
# screenshots → dirs → URLs → JS → params → email → takeover → vulns → secrets
#
# Usage:
#   ./tools/recon_engine.sh example.com --scope-file scope.json --confirm-active
#   ./tools/recon_engine.sh example.com --fast --scope-file scope.json --confirm-active
#   ./tools/recon_engine.sh example.com --deep --scope-file scope.json --confirm-active
#
# Every phase uses the PRIMARY tool from references/recon-tooling.md with a
# `command -v` guard and a built-in fallback — a missing tool degrades to the
# next option, never fails the pipeline.
#
# Output: recon/<target>/{subs.txt,resolved.txt,live-hosts.txt,urls.txt,jsfiles.txt,
#                         nuclei.txt,secrets.txt,ports.txt,takeovers.txt,params.txt,...}

set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target-domain> [--fast|--deep] --scope-file scope.json --confirm-active"
  exit 1
fi
shift || true

MODE="--normal"
SCOPE_FILE=""
CONFIRM_ACTIVE="false"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --fast|--deep) MODE="$1" ;;
    --scope-file) SCOPE_FILE="${2:-}" ; shift ;;
    --confirm-active) CONFIRM_ACTIVE="true" ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

TOOL_ROOT="$(cd "$(dirname "$0")" && pwd)"
CODE_ROOT="$(cd "$TOOL_ROOT/.." && pwd)"
# Runtime artifacts belong to the invoking project, not the installed skill.
ROOT="${BUGWOLF_PROJECT_ROOT:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"
cd "$ROOT"
export PYTHONPATH="$CODE_ROOT${PYTHONPATH:+:$PYTHONPATH}"
if ! python3 - "$TARGET" "$SCOPE_FILE" "$CONFIRM_ACTIVE" <<'PY'
import sys
from tools.safety import AuthorizationError, require_authorized_target
try:
    require_authorized_target(
        sys.argv[1], sys.argv[2] or None,
        active=True, confirm_active=sys.argv[3] == "true")
except AuthorizationError as exc:
    print(f"[!] Authorization denied: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
then
  exit 2
fi

# Recon is the first target-facing stage. It cannot run until the operator has
# explicitly completed setup, environment preflight, and authorization in the
# persistent no-skip workflow controller.
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$TARGET" "$ROOT" <<'PY'
import sys
from tools.stage_controller import WorkflowController, WorkflowError
try:
    WorkflowController(sys.argv[1], project_root=sys.argv[2]).require_stage("passive-recon")
except (WorkflowError, ValueError) as exc:
    print(f"[!] Workflow denied: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
then
  exit 2
fi

RECON_DIR="${ROOT}/recon/${TARGET}"
mkdir -p "${RECON_DIR}"

# Mandatory sequential freshness research. The JSON summary is kept beside
# recon so the operator can see whether live search was available; the loop
# itself persists detailed checkpoint results under research/${TARGET}/.
run_research_checkpoint() {
  local checkpoint="$1"
  python3 "${CODE_ROOT}/tools/research_loop.py" \
    --checkpoint "${checkpoint}" --mode web --target "${TARGET}" \
    --execute --require-latest --json \
    > "${RECON_DIR}/research-${checkpoint}.json" \
    || echo "{\"checkpoint\":\"${checkpoint}\",\"latest_ready\":false,\"error\":\"research execution failed\"}" \
       > "${RECON_DIR}/research-${checkpoint}.json"
}

run_research_sequence() {
  local phase="$1"
  python3 "${CODE_ROOT}/tools/research_loop.py" \
    --sequential --phase "${phase}" --mode web --target "${TARGET}" \
    --execute --json \
    > "${RECON_DIR}/research-sequence-${phase}.json" \
    || echo "{\"phase\":\"${phase}\",\"latest_ready\":false,\"error\":\"research sequence failed\"}" \
       > "${RECON_DIR}/research-sequence-${phase}.json"
}
run_research_checkpoint pre-hunt

TMP="$(mktemp -d "${TMPDIR:-/tmp}/recon-XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

# Pre-create every temp file the `cat` stages concatenate, so a missing optional
# tool never trips `set -e`/`pipefail` and aborts the pipeline.
touch "${TMP}"/subfinder.txt "${TMP}"/assetfinder.txt "${TMP}"/bbot.txt \
      "${TMP}"/subdog.txt "${TMP}"/crtsh.txt "${TMP}"/chaos.txt \
      "${TMP}"/alterx.txt "${TMP}"/dnsgen.txt "${TMP}"/katana.txt \
      "${TMP}"/wayback.txt "${TMP}"/gau.txt "${TMP}"/waymore.txt \
      "${TMP}"/hakrawler.txt 2>/dev/null || true

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# shellcheck disable=SC2317  # used as a function reference in some tools
have() { type -P "$1" &>/dev/null; }

# All target-facing binaries run through one non-shell adapter. It applies the
# same scope gate, argv-only execution, per-process timeout, and output cap;
# local text utilities below remain ordinary offline processing.
run_tool() {
  if python3 "${CODE_ROOT}/tools/recon_exec.py" \
    --target "${TARGET}" --scope-file "${SCOPE_FILE}" \
    --confirm-active --project-root "${ROOT}" \
    --timeout "${RECON_TOOL_TIMEOUT:-180}" \
    --max-output "${RECON_TOOL_MAX_OUTPUT:-10000000}" -- "$@"; then
    return 0
  else
    rc=$?
    printf '%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$rc" \
      >> "${RECON_DIR}/tool-failures.log"
    return "$rc"
  fi
}

# Same scope-bound adapter for low-level health probes (e.g. the fallback
# curl checks when httpx is absent). A non-zero exit here is an expected
# observation (connection refused, timeout), not a tool failure, so failures
# are not logged to tool-failures.log — but every URL argument still passes
# through the same per-URL scope validation before curl runs.
run_probe() {
  python3 "${CODE_ROOT}/tools/recon_exec.py" \
    --target "${TARGET}" --scope-file "${SCOPE_FILE}" \
    --confirm-active --project-root "${ROOT}" \
    --timeout "${RECON_TOOL_TIMEOUT:-180}" \
    --max-output "${RECON_TOOL_MAX_OUTPUT:-10000000}" -- "$@"
}
for _recon_tool in subfinder assetfinder bbot subdog alterx dnsgen puredns dnsx \
    naabu rustscan nmap httpx ffuf gowitness feroxbuster dirsearch indextree \
    katana waybackurls gau waymore hakrawler goswagger jsluice linkfinder x8 \
    emailfinder subzy nuclei dnstake afrog xssrecon redirectfinder trufflehog curl; do
  eval "${_recon_tool}() { run_tool '${_recon_tool}' \"\\$@\"; }"
done
# Hyphenated binaries are valid shell function names when declared this way.
for _recon_tool in mx-takeover; do
  eval "function ${_recon_tool} { run_tool '${_recon_tool}' \"\\$@\"; }"
done

# Keep every discovered host/URL inside the same explicit authorization scope.
# Recon tools may return sibling domains or links that are not authorized.
scope_filter() {
  local input="$1"
  local output="$2"
  python3 - "$input" "$output" "$SCOPE_FILE" <<'PY'
import sys
from pathlib import Path
from tools.safety import AuthorizationError, load_authorized_scope, target_in_scope

source, destination, scope_path = sys.argv[1:]
try:
    scope = load_authorized_scope(scope_path)
except AuthorizationError as exc:
    print(f"[!] Authorization denied while filtering recon output: {exc}", file=sys.stderr)
    raise SystemExit(2)

kept = []
for line in Path(source).read_text(errors="replace").splitlines():
    if not line.strip():
        continue
    candidate = line.strip().split()[0]
    try:
        if target_in_scope(candidate, scope):
            kept.append(line)
    except AuthorizationError:
        continue
Path(destination).write_text("\n".join(kept) + ("\n" if kept else ""))
PY
}

# ---------------------------------------------------------------------------
# Phase 1: Subdomain enumeration
# ---------------------------------------------------------------------------
log "Phase 1: Subdomain enumeration for *.${TARGET}"

have subfinder && { subfinder -d "${TARGET}" -silent -all 2>/dev/null > "${TMP}/subfinder.txt" || true; log "  subfinder: $(wc -l < "${TMP}/subfinder.txt" 2>/dev/null || echo 0)"; }

have assetfinder && { assetfinder --subs-only "${TARGET}" 2>/dev/null > "${TMP}/assetfinder.txt" || true; log "  assetfinder: $(wc -l < "${TMP}/assetfinder.txt" 2>/dev/null || echo 0)"; }

have bbot && [ "$MODE" != "--fast" ] && { bbot -t "${TARGET}" -f subdomain-enum 2>/dev/null > "${TMP}/bbot.txt" || true; log "  bbot: $(wc -l < "${TMP}/bbot.txt" 2>/dev/null || echo 0)"; }

have subdog && { subdog -t "${TARGET}" 2>/dev/null > "${TMP}/subdog.txt" || true; log "  subdog: $(wc -l < "${TMP}/subdog.txt" 2>/dev/null || echo 0)"; }

# Certificate Transparency — crt.name (dated) with crt.sh fallback.
# The Python adapter applies the same explicit scope before output is merged.
if python3 "${CODE_ROOT}/tools/js_ct_intel.py" \
    --target "${TARGET}" --scope-file "${SCOPE_FILE}" \
    --output-dir "${RECON_DIR}" --ct-only --quiet 2>/dev/null; then
  cp "${RECON_DIR}/ct-subdomains.txt" "${TMP}/crtsh.txt" 2>/dev/null || true
else
  : > "${TMP}/crtsh.txt"
fi
log "  CT records: $(wc -l < "${TMP}/crtsh.txt" 2>/dev/null || echo 0)"

# Chaos API collection is offline-only; provider exports are imported separately.
if false; then
  curl --silent --show-error --connect-timeout 5 --max-time 15 "https://dns.projectdiscovery.io/dns/${TARGET}/subdomains" \
    -H "Authorization: ${CHAOS_API_KEY}" 2>/dev/null | \
    jq -r '.subdomains[]' 2>/dev/null | sed "s/$/.${TARGET}/" > "${TMP}/chaos.txt" || true
  log "  chaos: $(wc -l < "${TMP}/chaos.txt" 2>/dev/null || echo 0)"
fi

cat "${TMP}"/subfinder.txt "${TMP}"/assetfinder.txt "${TMP}"/bbot.txt \
    "${TMP}"/subdog.txt "${TMP}"/crtsh.txt "${TMP}"/chaos.txt 2>/dev/null | \
  grep -iF -- "${TARGET}" | sort -u > "${RECON_DIR}/subs.txt" || true
scope_filter "${RECON_DIR}/subs.txt" "${TMP}/subs-in-scope.txt"
cp "${TMP}/subs-in-scope.txt" "${RECON_DIR}/subs.txt"
log "  Unique subdomains: $(wc -l < "${RECON_DIR}/subs.txt" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# Phase 2: Permutations + brute force (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ]; then
  log "Phase 2: Permutations + brute force"
  have alterx && { alterx -l "${RECON_DIR}/subs.txt" -silent 2>/dev/null > "${TMP}/alterx.txt" || true; log "  alterx: $(wc -l < "${TMP}/alterx.txt" 2>/dev/null || echo 0)"; }
  have dnsgen && { dnsgen "${RECON_DIR}/subs.txt" 2>/dev/null > "${TMP}/dnsgen.txt" || true; log "  dnsgen: $(wc -l < "${TMP}/dnsgen.txt" 2>/dev/null || echo 0)"; }
  cat "${TMP}"/alterx.txt "${TMP}"/dnsgen.txt 2>/dev/null | sort -u > "${TMP}/perms.txt" || true
  if have puredns; then
    RESOLVERS="${CODE_ROOT}/wordlists/resolvers.txt"
    if [ -f "$RESOLVERS" ]; then
      puredns resolve "${TMP}/perms.txt" -r "$RESOLVERS" --write "${TMP}/puredns-resolved.txt" 2>/dev/null || true
    else
      puredns resolve "${TMP}/perms.txt" --write "${TMP}/puredns-resolved.txt" 2>/dev/null || true
    fi
    awk '{print $1}' "${TMP}/puredns-resolved.txt" 2>/dev/null | grep -iF -- "${TARGET}" | sort -u >> "${RECON_DIR}/subs.txt" || true
    log "  puredns resolved: $(wc -l < "${TMP}/puredns-resolved.txt" 2>/dev/null || echo 0)"
  fi
  sort -u "${RECON_DIR}/subs.txt" -o "${RECON_DIR}/subs.txt"
  scope_filter "${RECON_DIR}/subs.txt" "${TMP}/subs-in-scope.txt"
  cp "${TMP}/subs-in-scope.txt" "${RECON_DIR}/subs.txt"
  log "  Total after permutations: $(wc -l < "${RECON_DIR}/subs.txt")"
fi

# ---------------------------------------------------------------------------
# Phase 3: DNS resolution
# ---------------------------------------------------------------------------
log "Phase 3: DNS resolution"

if have dnsx; then
  dnsx -l "${RECON_DIR}/subs.txt" -silent -a -cname -resp-only -json > "${RECON_DIR}/dnsx.json" 2>/dev/null || true
  jq -r '.host + " [" + (.a[0] // "") + "]"' "${RECON_DIR}/dnsx.json" 2>/dev/null | sort -u > "${TMP}/resolved.txt" || true
  jq -r 'select(.cname != null) | "\(.host) CNAME \(.cname[0])"' "${RECON_DIR}/dnsx.json" 2>/dev/null > "${RECON_DIR}/cnames.txt" || true
else
  while read -r sub; do
    host "$sub" 2>/dev/null | grep "has address" | awk '{print $1" ["$NF"]"}' >> "${TMP}/resolved.txt" || true
  done < "${RECON_DIR}/subs.txt"
fi

grep -v '^$' "${TMP}/resolved.txt" 2>/dev/null | sort -u > "${RECON_DIR}/resolved.txt" || touch "${RECON_DIR}/resolved.txt"
scope_filter "${RECON_DIR}/resolved.txt" "${TMP}/resolved-in-scope.txt"
cp "${TMP}/resolved-in-scope.txt" "${RECON_DIR}/resolved.txt"
log "  Resolved: $(wc -l < "${RECON_DIR}/resolved.txt" 2>/dev/null || echo 0) hosts"

# Offline asset graph and diff inputs. Provider query plans are emitted but
# Shodan/Censys/FOFA/ZoomEye/SpiderFoot are never contacted automatically.
ASSET_INTEL_DIR="${RECON_DIR}/asset-intel"
python3 "${CODE_ROOT}/tools/asset_intel.py" \
  --target "${TARGET}" --scope-file "${SCOPE_FILE}" \
  --input-file "${RECON_DIR}/subs.txt" --input-file "${RECON_DIR}/resolved.txt" \
  --output-dir "${ASSET_INTEL_DIR}" 2>/dev/null || true
log "  Asset intelligence: ${ASSET_INTEL_DIR}/"

# ---------------------------------------------------------------------------
# Phase 4: Port scanning (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ]; then
  log "Phase 4: Port scanning"
  awk '{print $1}' "${RECON_DIR}/resolved.txt" 2>/dev/null > "${TMP}/hosts-only.txt"
  if have naabu; then
    naabu -list "${TMP}/hosts-only.txt" -silent -top-ports 1000 -o "${RECON_DIR}/ports.txt" 2>/dev/null || true
  elif have rustscan; then
    rustscan -a "$(paste -sd, "${TMP}/hosts-only.txt" 2>/dev/null)" --ulimit 5000 -g 2>/dev/null > "${RECON_DIR}/ports.txt" || true
  elif have nmap; then
    nmap -iL "${TMP}/hosts-only.txt" --top-ports 1000 -T4 -oG "${TMP}/nmap.gnmap" 2>/dev/null >/dev/null || true
    grep -oE 'Ports:.*' "${TMP}/nmap.gnmap" 2>/dev/null | sed 's/Ports: //' > "${RECON_DIR}/ports.txt" || true
  fi
  log "  Ports file: ${RECON_DIR}/ports.txt ($(wc -l < "${RECON_DIR}/ports.txt" 2>/dev/null || echo 0) lines)"
fi

# ---------------------------------------------------------------------------
# Phase 5: Live host discovery
# ---------------------------------------------------------------------------
log "Phase 5: Live host probing"

awk '{print $1}' "${RECON_DIR}/resolved.txt" 2>/dev/null > "${TMP}/hosts-only.txt"

if have httpx; then
  httpx -l "${TMP}/hosts-only.txt" -silent -status-code -title -tech-detect -json \
    -o "${RECON_DIR}/httpx.json" 2>/dev/null || true
  jq -r 'select(.status_code != null) | "\(.url) [\(.status_code)] \(.title // "N/A")"' \
    "${RECON_DIR}/httpx.json" 2>/dev/null > "${RECON_DIR}/live-hosts.txt" || true  else
    while read -r host; do
      for proto in https http; do
        status=$(run_probe curl --silent --output /dev/null --write-out "%{http_code}" \
          --connect-timeout 5 --max-time 15 "${proto}://${host}" 2>/dev/null || echo "000")
        [ "$status" != "000" ] && echo "${proto}://${host} [${status}]" >> "${RECON_DIR}/live-hosts.txt" || true
      done
    done < "${TMP}/hosts-only.txt"
  fi
if [ -f "${RECON_DIR}/live-hosts.txt" ]; then
  scope_filter "${RECON_DIR}/live-hosts.txt" "${TMP}/live-in-scope.txt"
  cp "${TMP}/live-in-scope.txt" "${RECON_DIR}/live-hosts.txt"
else
  : > "${RECON_DIR}/live-hosts.txt"
fi
log "  Live hosts: $(wc -l < "${RECON_DIR}/live-hosts.txt" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# Phase 6: VHOST discovery (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ] && have ffuf; then
  log "Phase 6: VHOST discovery (custom target-specific wordlist)"
  VHOST_WL="${TMP}/vhosts-target.txt"
  python3 "${CODE_ROOT}/tools/wordlist_gen.py" --target "${TARGET}" \
    --urls-file "${RECON_DIR}/urls.txt" --mode vhosts --research > "${VHOST_WL}" 2>/dev/null || true
  awk '{print $1}' "${RECON_DIR}/live-hosts.txt" 2>/dev/null > "${TMP}/live-urls.txt"
  while read -r url; do
    host=$(echo "$url" | sed -E 's#https?://##')
    ffuf -u "${url}" -H "Host: FUZZ.${host}" -w "${VHOST_WL}" \
      -mc 200 -s -t 50 2>/dev/null >> "${RECON_DIR}/vhosts.txt" || true
  done < "${TMP}/live-urls.txt"
  log "  VHOST candidates: $(wc -l < "${RECON_DIR}/vhosts.txt" 2>/dev/null || echo 0)"
fi

# ---------------------------------------------------------------------------
# Phase 7: Screenshots (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ] && have gowitness; then
  log "Phase 7: Screenshots"
  awk '{print $1}' "${RECON_DIR}/live-hosts.txt" 2>/dev/null > "${TMP}/live-urls.txt"
  gowitness scan file -f "${TMP}/live-urls.txt" --write-db --write-json \
    --destination "${RECON_DIR}/screenshots" 2>/dev/null || true
  log "  Screenshots → ${RECON_DIR}/screenshots/"
fi

# ---------------------------------------------------------------------------
# Phase 8: Directory enumeration (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ]; then
  log "Phase 8: Directory enumeration"
  awk '{print $1}' "${RECON_DIR}/live-hosts.txt" 2>/dev/null > "${TMP}/live-urls.txt"
  if have feroxbuster; then
    while read -r url; do
      feroxbuster -u "${url}" --silent --depth 2 -x txt,json,bak,zip 2>/dev/null >> "${RECON_DIR}/dirs.txt" || true
    done < "${TMP}/live-urls.txt"
  elif have dirsearch; then
    while read -r url; do
      dirsearch -u "${url}" -e txt,json,bak,zip --quiet 2>/dev/null >> "${RECON_DIR}/dirs.txt" || true
    done < "${TMP}/live-urls.txt"
  fi
  # indextree — crawl directory-index listings into a tree
  if have indextree; then
    cat "${TMP}/live-urls.txt" | indextree --depth 2 --silent --output "${RECON_DIR}/indextree.txt" 2>/dev/null || true
    log "  indextree: $(wc -l < "${RECON_DIR}/indextree.txt" 2>/dev/null || echo 0) indexed paths"
  fi
  log "  Directory hits: $(wc -l < "${RECON_DIR}/dirs.txt" 2>/dev/null || echo 0)"
fi

# ---------------------------------------------------------------------------
# Phase 9: URL collection
# ---------------------------------------------------------------------------
log "Phase 9: URL crawling"

awk '{print $1}' "${RECON_DIR}/live-hosts.txt" 2>/dev/null > "${TMP}/live-urls.txt"

have katana && [ "$MODE" != "--fast" ] && { katana -list "${TMP}/live-urls.txt" -d 3 -silent -jc 2>/dev/null > "${TMP}/katana.txt" || true; log "  katana: $(wc -l < "${TMP}/katana.txt" 2>/dev/null || echo 0) URLs"; }

have waybackurls && { echo "${TARGET}" | waybackurls 2>/dev/null > "${TMP}/wayback.txt" || true; log "  waybackurls: $(wc -l < "${TMP}/wayback.txt" 2>/dev/null || echo 0) URLs"; }

have gau && { gau "${TARGET}" 2>/dev/null > "${TMP}/gau.txt" || true; log "  gau: $(wc -l < "${TMP}/gau.txt" 2>/dev/null || echo 0) URLs"; }

have waymore && [ "$MODE" != "--fast" ] && { waymore -i "${TARGET}" -mode U 2>/dev/null > "${TMP}/waymore.txt" || true; log "  waymore: $(wc -l < "${TMP}/waymore.txt" 2>/dev/null || echo 0) URLs"; }

have hakrawler && [ "$MODE" != "--fast" ] && { echo "${TARGET}" | hakrawler -d 3 2>/dev/null > "${TMP}/hakrawler.txt" || true; log "  hakrawler: $(wc -l < "${TMP}/hakrawler.txt" 2>/dev/null || echo 0) URLs"; }

cat "${TMP}"/katana.txt "${TMP}"/wayback.txt "${TMP}"/gau.txt \
    "${TMP}"/waymore.txt "${TMP}"/hakrawler.txt 2>/dev/null | \
  grep -iF -- "${TARGET}" | sort -u > "${RECON_DIR}/urls.txt" || true
scope_filter "${RECON_DIR}/urls.txt" "${TMP}/urls-in-scope.txt"
cp "${TMP}/urls-in-scope.txt" "${RECON_DIR}/urls.txt"

log "  Total unique URLs: $(wc -l < "${RECON_DIR}/urls.txt" 2>/dev/null || echo 0)"

# goswagger — detect Swagger/OpenAPI UI + extract the API surface from live hosts
if have goswagger; then
  cat "${TMP}/live-urls.txt" | goswagger --concurrent 50 > "${RECON_DIR}/swagger.txt" 2>/dev/null || true
  log "  goswagger: $(wc -l < "${RECON_DIR}/swagger.txt" 2>/dev/null || echo 0) Swagger endpoints"
fi

# ---------------------------------------------------------------------------
# Phase 10: JavaScript extraction + deep analysis
# ---------------------------------------------------------------------------
log "Phase 10: JavaScript extraction"

grep '\.js' "${RECON_DIR}/urls.txt" 2>/dev/null | grep -v '\.json' | sort -u > "${RECON_DIR}/jsfiles.txt" || true
log "  JS files: $(wc -l < "${RECON_DIR}/jsfiles.txt" 2>/dev/null || echo 0)"

# jsluice (deep): extract endpoints + secrets straight from the URL list
if [ "$MODE" == "--deep" ] && have jsluice; then
  jsluice urls "${RECON_DIR}/jsfiles.txt" > "${RECON_DIR}/js-endpoints.txt" 2>/dev/null || true
  jsluice secrets "${RECON_DIR}/jsfiles.txt" > "${RECON_DIR}/js-secrets.txt" 2>/dev/null || true
  log "  jsluice: endpoints + secrets → js-endpoints.txt / js-secrets.txt"
fi

# Download JS files for offline analysis (deep)
if [ "$MODE" == "--deep" ]; then
  mkdir -p "${RECON_DIR}/js/"
  while read -r jsurl; do
    fname=$(echo "$jsurl" | sha256sum | cut -c1-16)
    run_probe curl --silent --show-error --connect-timeout 5 --max-time 15 \
      "$jsurl" -o "${RECON_DIR}/js/${fname}.js" 2>/dev/null || true
  done < "${RECON_DIR}/jsfiles.txt"
  if have linkfinder && [ -n "$(ls -A "${RECON_DIR}/js/" 2>/dev/null)" ]; then
    find "${RECON_DIR}/js/" -name '*.js' -exec python3 -m linkfinder -i {} -o cli \; 2>/dev/null >> "${RECON_DIR}/js-endpoints.txt" || true
  fi
  log "  Downloaded JS files to ${RECON_DIR}/js/"
fi

# Dedicated JS intelligence phase: local analysis only. Crawlers were already
# scope-filtered in Phase 9; --collect-crawlers is intentionally not enabled.
JS_INTEL_DIR="${RECON_DIR}/js-intel"
python3 "${CODE_ROOT}/tools/js_ct_intel.py" \\
  --target "${TARGET}" --scope-file "${SCOPE_FILE}" \\
  --urls-file "${RECON_DIR}/urls.txt" --js-dir "${RECON_DIR}/js" \\
  --output-dir "${JS_INTEL_DIR}" --js-only --quiet 2>/dev/null || true
log "  JS intelligence: ${JS_INTEL_DIR}/"

# ---------------------------------------------------------------------------
# Phase 10b: Schema extraction + discovery core (surface model + mutation plan)
# ---------------------------------------------------------------------------
log "Phase 10b: Schema extraction + discovery core"
DISCOVERY_DIR="${RECON_DIR}/discovery"
mkdir -p "${DISCOVERY_DIR}"

# Optionally download discovered schemas + GraphQL introspection. This is an
# active step and only runs with an explicit scope and --confirm-active; it
# passes every request through the execution controller.
if [ "${CONFIRM_ACTIVE}" = "true" ] && [ -n "${SCOPE_FILE}" ]; then
  python3 "${CODE_ROOT}/tools/schema_extractor.py" \
    --target "${TARGET}" --recon-dir "${RECON_DIR}" --fetch \
    --scope-file "${SCOPE_FILE}" --confirm-active 2>/dev/null || true
fi

# Build the surface model + discovery plan from recon artifacts (offline).
python3 "${CODE_ROOT}/tools/schema_extractor.py" \
  --target "${TARGET}" --recon-dir "${RECON_DIR}" \
  --output "${DISCOVERY_DIR}/surface-model.json" 2>/dev/null || true
python3 "${CODE_ROOT}/tools/discovery_scheduler.py" \
  --target "${TARGET}" --recon-dir "${RECON_DIR}" \
  --output-dir "${DISCOVERY_DIR}" --budget 200 --min-focus medium 2>/dev/null || true

# Header-trust probe plan (offline): forged forwarded/trust headers are trust
# hypotheses, never executed payloads. Live baseline-vs-forged replay stays
# gated behind --confirm-active + a scope file and is not run automatically.
python3 "${CODE_ROOT}/tools/header_trust.py" \
  --target "${TARGET}" --recon-dir "${RECON_DIR}" \
  --output "${DISCOVERY_DIR}/header-trust-plan.json" 2>/dev/null || true

log "  Discovery core: ${DISCOVERY_DIR}/"

# ---------------------------------------------------------------------------
# Phase 11: Hidden parameter discovery (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ] && have x8; then
  log "Phase 11: Hidden parameter discovery (custom target-specific wordlist)"
  PARAM_WL="${TMP}/params-target.txt"
  python3 "${CODE_ROOT}/tools/wordlist_gen.py" --target "${TARGET}" \
    --urls-file "${RECON_DIR}/urls.txt" --mode params --research > "${PARAM_WL}" 2>/dev/null || true
  awk '{print $1}' "${RECON_DIR}/live-hosts.txt" 2>/dev/null > "${TMP}/live-urls.txt"
  x8 -u "${TMP}/live-urls.txt" -w "${PARAM_WL}" > "${RECON_DIR}/params.txt" 2>/dev/null || true
  log "  Hidden params: $(wc -l < "${RECON_DIR}/params.txt" 2>/dev/null || echo 0)"
fi

# ---------------------------------------------------------------------------
# Phase 12: Email enumeration
# ---------------------------------------------------------------------------
if have emailfinder; then
  log "Phase 12: Email enumeration"
  emailfinder -d "${TARGET}" > "${RECON_DIR}/emails.txt" 2>/dev/null || true
  log "  Emails: $(wc -l < "${RECON_DIR}/emails.txt" 2>/dev/null || echo 0)"
fi

# ---------------------------------------------------------------------------
# Phase 13: Subdomain / DNS / MX takeover
# ---------------------------------------------------------------------------
log "Phase 13: Takeover checks"

if have subzy; then
  subzy run --targets "${RECON_DIR}/subs.txt" --hide_fails 2>/dev/null > "${RECON_DIR}/takeovers.txt" || true
elif have nuclei; then
  nuclei -l "${RECON_DIR}/subs.txt" -t http/takeovers/ -silent -o "${RECON_DIR}/takeovers.txt" 2>/dev/null || true
fi
have dnstake && { dnstake "${RECON_DIR}/subs.txt" -o "${RECON_DIR}/dnstake.txt" 2>/dev/null || true; }
have mx-takeover && { mx-takeover -d "${TARGET}" 2>/dev/null > "${RECON_DIR}/mx-takeover.txt" || true; }
log "  Takeover findings: $(wc -l < "${RECON_DIR}/takeovers.txt" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# Phase 14: Vulnerability scanning
# ---------------------------------------------------------------------------
log "Phase 14: Nuclei scanning"

if have nuclei && [ "$MODE" != "--fast" ]; then
  nuclei -l "${TMP}/live-urls.txt" -severity critical,high,medium \
    -silent -stats -stats-interval 30 -o "${RECON_DIR}/nuclei.txt" 2>/dev/null || true
  log "  Nuclei findings: $(wc -l < "${RECON_DIR}/nuclei.txt" 2>/dev/null || echo 0)"
else
  echo "# Nuclei scan skipped (not installed or --fast mode)" > "${RECON_DIR}/nuclei.txt"
fi

# Offline methodology layer: convert scanner/recon signals into manual
# trigger-impact tasks and non-executing tool plans.
PLAYBOOK_DIR="${RECON_DIR}/methodology"
python3 "${CODE_ROOT}/tools/methodology_playbook.py" \
  --target "${TARGET}" --scope-file "${SCOPE_FILE}" \
  --urls-file "${RECON_DIR}/urls.txt" --signals-file "${RECON_DIR}/nuclei.txt" \
  --output-dir "${PLAYBOOK_DIR}" 2>/dev/null || true
log "  Methodology plans: ${PLAYBOOK_DIR}/"

# afrog — second-opinion PoC scanner (deep only)
if have afrog && [ "$MODE" == "--deep" ]; then
  afrog -l "${TMP}/live-urls.txt" > "${RECON_DIR}/afrog.txt" 2>/dev/null || true
  log "  afrog findings: $(wc -l < "${RECON_DIR}/afrog.txt" 2>/dev/null || echo 0)"
fi

# xssrecon — reflected XSS from the URL list (HTML-only, no Chrome needed)
if have xssrecon && [ "$MODE" != "--fast" ]; then
  cat "${RECON_DIR}/urls.txt" | xssrecon --no-chromedp > "${RECON_DIR}/xss.txt" 2>/dev/null || true
  log "  xssrecon findings: $(wc -l < "${RECON_DIR}/xss.txt" 2>/dev/null || echo 0)"
fi

# redirectfinder — open redirect detection from the URL list
if have redirectfinder && [ "$MODE" != "--fast" ]; then
  cat "${RECON_DIR}/urls.txt" | redirectfinder > "${RECON_DIR}/redirects.txt" 2>/dev/null || true
  log "  redirectfinder findings: $(wc -l < "${RECON_DIR}/redirects.txt" 2>/dev/null || echo 0)"
fi

# ---------------------------------------------------------------------------
# Phase 15: Secret scanning
# ---------------------------------------------------------------------------
log "Phase 15: Secret scanning"

if have trufflehog && [ "$MODE" != "--fast" ] && [ -d "${RECON_DIR}/js/" ]; then
  trufflehog filesystem "${RECON_DIR}/js/" --json --no-update 2>/dev/null > "${TMP}/trufflehog.json" || true
  python3 - "${TMP}/trufflehog.json" "${RECON_DIR}/secrets.json" <<'PY'
import json
import sys
from pathlib import Path
from tools.evidence import redact, redact_text
source, destination = map(Path, sys.argv[1:])
rows = []
for line in source.read_text(errors="replace").splitlines():
    if not line.strip():
        continue
    try:
        safe = redact(json.loads(line))
        if isinstance(safe, dict):
            for key in ("Raw", "raw", "Secret", "secret", "match"):
                if key in safe:
                    safe[key] = "[REDACTED]"
        rows.append(json.dumps(safe, sort_keys=True))
    except json.JSONDecodeError:
        rows.append(redact_text(line))
destination.write_text("\\n".join(rows) + ("\\n" if rows else ""))
PY
  log "  Secrets found: $(wc -l < "${RECON_DIR}/secrets.json" 2>/dev/null || echo 0)"
elif [ -f "${RECON_DIR}/urls.txt" ]; then
  {
    grep -oE 'ghp_[A-Za-z0-9_]{36}' "${RECON_DIR}/urls.txt" 2>/dev/null | sha256sum | awk '{print "github_token:sha256:"$1}' || true
    grep -oE 'AKIA[0-9A-Z]{16}' "${RECON_DIR}/urls.txt" 2>/dev/null | sha256sum | awk '{print "aws_access_key:sha256:"$1}' || true
    grep -oE 'sk_live_[0-9a-zA-Z]{24,}' "${RECON_DIR}/urls.txt" 2>/dev/null | sha256sum | awk '{print "stripe_key:sha256:"$1}' || true
    grep -oE 'hooks\.slack\.com/services/[A-Za-z0-9/]+' "${RECON_DIR}/urls.txt" 2>/dev/null | sha256sum | awk '{print "slack_webhook:sha256:"$1}' || true
  } | sort -u > "${RECON_DIR}/secrets-quick.txt"
  log "  Quick secret scan: $(wc -l < "${RECON_DIR}/secrets-quick.txt" 2>/dev/null || echo 0) potential matches"
fi

# ---------------------------------------------------------------------------
# Mandatory post-recon and post-maps research (strict order)
# ---------------------------------------------------------------------------
run_research_sequence recon

# Persist newly observed research/technique candidates for later reviewed reuse.
# This is local-only and never changes executable source or runs a payload.
python3 "${CODE_ROOT}/tools/adaptive_learning.py" \
  --target "${TARGET}" --journey-type recon \
  --research-dir "${ROOT}/research/${TARGET}" --json \
  > "${RECON_DIR}/adaptive-learning.json" 2>/dev/null \
  || echo '{"status":"error","journey_type":"recon"}' > "${RECON_DIR}/adaptive-learning.json"

# Persist the technology fingerprint as a required workflow artifact. This
# is static/local analysis; it does not make a target request.
python3 "${CODE_ROOT}/tools/tech_fingerprint.py" \
  --path "${ROOT}" --json > "${RECON_DIR}/tech-fingerprint.json" 2>/dev/null \
  || echo '{"schema":"tech_fingerprint/1.0","components":[],"stack":""}' \
     > "${RECON_DIR}/tech-fingerprint.json"

# Paper-derived passive artifact handoff. These inputs are operator-supplied
# local exports, not collected by recon. When present, process them before the
# completion marker so the maps stage receives the same deterministic handoff.
PAPER_INTEL_OUTPUT="${RECON_DIR}/paper-intelligence"
PAPER_INTEL_MAP="${ROOT}/state/sessions/${TARGET}/maps/paper-intelligence.md"
PAPER_TRAFFIC=""
PAPER_PROFILES=""
PAPER_AGENT=""
for candidate in \
    "${RECON_DIR}/https-traffic.json" "${RECON_DIR}/https-traffic.jsonl" \
    "${RECON_DIR}/traffic.json" "${RECON_DIR}/traffic.jsonl"; do
  if [ -z "${PAPER_TRAFFIC}" ] && [ -s "${candidate}" ]; then PAPER_TRAFFIC="${candidate}"; fi
done
for candidate in \
    "${RECON_DIR}/site-profiles.json" "${RECON_DIR}/site-profiles.jsonl" \
    "${ROOT}/site-profiles.json" "${ROOT}/site-profiles.jsonl"; do
  if [ -z "${PAPER_PROFILES}" ] && [ -s "${candidate}" ]; then PAPER_PROFILES="${candidate}"; fi
done
for candidate in \
    "${RECON_DIR}/agent-control-plane.json" "${RECON_DIR}/agent-control-plane.jsonl" \
    "${ROOT}/agent-inventory.json" "${ROOT}/agent-inventory.jsonl" \
    "${ROOT}/audit/agent-inventory.json" "${ROOT}/audit/agent-inventory.jsonl" \
    "${ROOT}/audit/${TARGET}/agent-inventory.json" "${ROOT}/audit/${TARGET}/agent-inventory.jsonl"; do
  if [ -z "${PAPER_AGENT}" ] && [ -s "${candidate}" ]; then PAPER_AGENT="${candidate}"; fi
done
if [ -n "${PAPER_TRAFFIC}" ] || [ -n "${PAPER_AGENT}" ]; then
  mkdir -p "${PAPER_INTEL_OUTPUT}"
  PAPER_ARGS=(--output-dir "${PAPER_INTEL_OUTPUT}" --map-output "${PAPER_INTEL_MAP}" --json)
  [ -n "${PAPER_TRAFFIC}" ] && PAPER_ARGS+=(--https-traffic-file "${PAPER_TRAFFIC}")
  [ -n "${PAPER_PROFILES}" ] && PAPER_ARGS+=(--site-profiles-file "${PAPER_PROFILES}")
  [ -n "${PAPER_AGENT}" ] && PAPER_ARGS+=(--agent-control-plane-file "${PAPER_AGENT}")
  python3 "${CODE_ROOT}/tools/paper_intel.py" "${PAPER_ARGS[@]}" \
    > "${PAPER_INTEL_OUTPUT}/run.json" \
    || { echo "[!] Paper-intelligence artifact processing failed." >&2; exit 1; }
fi

# Marker written only after the complete recon pipeline reaches its end. The
# next stages still require their own artifacts and cannot be skipped.
python3 - "${RECON_DIR}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
recon = Path(sys.argv[1])
required = ["subs.txt", "resolved.txt", "live-hosts.txt", "urls.txt",
            "tech-fingerprint.json", "research-sequence-recon.json"]
missing = [name for name in required if not (recon / name).is_file()]
failures = (recon / "tool-failures.log").read_text(errors="replace").splitlines() \
    if (recon / "tool-failures.log").exists() else []
for auxiliary in ("adaptive-learning.json", "tech-fingerprint.json"):
    try:
        payload = json.loads((recon / auxiliary).read_text())
        if payload.get("status") == "error":
            failures.append(auxiliary + ": reported error")
    except (OSError, json.JSONDecodeError):
        failures.append(auxiliary + ": invalid output")
(recon / "recon-complete.json").write_text(json.dumps({
    "schema": "bugwolf-recon-complete/v2",
    "complete": not missing and not failures,
    "degraded": bool(missing or failures),
    "missing_artifacts": missing,
    "tool_failures": len(failures),
    "completed_at": datetime.now(timezone.utc).isoformat(),
    "artifacts": sorted(path.name for path in recon.iterdir()
                         if path.is_file()),
    "network": "authorized recon pipeline only",
}, indent=2) + "\\n")
if missing or failures:
    print("[!] Recon completed in degraded state; workflow validation is blocked.",
          file=sys.stderr)
    raise SystemExit(1)
PY

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""

echo "=============================================="
echo " BugWolf Recon Complete"
echo "=============================================="
echo " Target:         ${TARGET}"
echo " Subs:           $(wc -l < "${RECON_DIR}/subs.txt" 2>/dev/null || echo 0)"
echo " Resolved:       $(wc -l < "${RECON_DIR}/resolved.txt" 2>/dev/null || echo 0)"
echo " Live hosts:     $(wc -l < "${RECON_DIR}/live-hosts.txt" 2>/dev/null || echo 0)"
echo " URLs:           $(wc -l < "${RECON_DIR}/urls.txt" 2>/dev/null || echo 0)"
echo " JS files:       $(wc -l < "${RECON_DIR}/jsfiles.txt" 2>/dev/null || echo 0)"
echo " Takeovers:      $(wc -l < "${RECON_DIR}/takeovers.txt" 2>/dev/null || echo 0)"
echo " Output:         ${RECON_DIR}/"
echo "=============================================="

# Initialize hunt state if the state module exists
if python3 -c "from tools.state import load_state" 2>/dev/null; then
  python3 -c "
from tools.state import load_state
s = load_state('${TARGET}')
print('[+] State available for ${TARGET}: '
      f'{s.endpoints_tested} endpoints, {s.findings_count} findings')
" 2>/dev/null || true
fi
