#!/usr/bin/env bash
#
# BugWolf Recon Engine v1.0.0
# Full pipeline: subdomains → permutations → resolve → live → port → vhost →
# screenshots → dirs → URLs → JS → params → email → takeover → vulns → secrets
#
# Usage:
#   ./tools/recon_engine.sh example.com
#   ./tools/recon_engine.sh example.com --fast        (skip slow steps)
#   ./tools/recon_engine.sh example.com --deep        (port scan, brute, screenshots, dir enum, deep JS)
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
  echo "Usage: $0 <target-domain> [--fast|--deep]"
  exit 1
fi

MODE="${2:---normal}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECON_DIR="${ROOT}/recon/${TARGET}"
mkdir -p "${RECON_DIR}"

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
have() { command -v "$1" &>/dev/null; }

# ---------------------------------------------------------------------------
# Phase 1: Subdomain enumeration
# ---------------------------------------------------------------------------
log "Phase 1: Subdomain enumeration for *.${TARGET}"

have subfinder && { subfinder -d "${TARGET}" -silent -all 2>/dev/null > "${TMP}/subfinder.txt" || true; log "  subfinder: $(wc -l < "${TMP}/subfinder.txt" 2>/dev/null || echo 0)"; }

have assetfinder && { assetfinder --subs-only "${TARGET}" 2>/dev/null > "${TMP}/assetfinder.txt" || true; log "  assetfinder: $(wc -l < "${TMP}/assetfinder.txt" 2>/dev/null || echo 0)"; }

have bbot && [ "$MODE" != "--fast" ] && { bbot -t "${TARGET}" -f subdomain-enum 2>/dev/null > "${TMP}/bbot.txt" || true; log "  bbot: $(wc -l < "${TMP}/bbot.txt" 2>/dev/null || echo 0)"; }

have subdog && { subdog -t "${TARGET}" 2>/dev/null > "${TMP}/subdog.txt" || true; log "  subdog: $(wc -l < "${TMP}/subdog.txt" 2>/dev/null || echo 0)"; }

# crt.sh (certificate transparency) — always available via curl
curl -sk "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | \
  sed 's/\*\.//g' | tr ',' '\n' | sort -u > "${TMP}/crtsh.txt" || true
log "  crt.sh: $(wc -l < "${TMP}/crtsh.txt" 2>/dev/null || echo 0)"

# Chaos API (if key configured)
if [ -n "${CHAOS_API_KEY:-}" ]; then
  curl -sk "https://dns.projectdiscovery.io/dns/${TARGET}/subdomains" \
    -H "Authorization: ${CHAOS_API_KEY}" 2>/dev/null | \
    jq -r '.subdomains[]' 2>/dev/null | sed "s/$/.${TARGET}/" > "${TMP}/chaos.txt" || true
  log "  chaos: $(wc -l < "${TMP}/chaos.txt" 2>/dev/null || echo 0)"
fi

cat "${TMP}"/subfinder.txt "${TMP}"/assetfinder.txt "${TMP}"/bbot.txt \
    "${TMP}"/subdog.txt "${TMP}"/crtsh.txt "${TMP}"/chaos.txt 2>/dev/null | \
  grep -i "${TARGET}" | sort -u > "${RECON_DIR}/subs.txt"
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
    RESOLVERS="${ROOT}/wordlists/resolvers.txt"
    if [ -f "$RESOLVERS" ]; then
      puredns resolve "${TMP}/perms.txt" -r "$RESOLVERS" --write "${TMP}/puredns-resolved.txt" 2>/dev/null || true
    else
      puredns resolve "${TMP}/perms.txt" --write "${TMP}/puredns-resolved.txt" 2>/dev/null || true
    fi
    awk '{print $1}' "${TMP}/puredns-resolved.txt" 2>/dev/null | grep -i "${TARGET}" | sort -u >> "${RECON_DIR}/subs.txt" || true
    log "  puredns resolved: $(wc -l < "${TMP}/puredns-resolved.txt" 2>/dev/null || echo 0)"
  fi
  sort -u "${RECON_DIR}/subs.txt" -o "${RECON_DIR}/subs.txt"
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
log "  Resolved: $(wc -l < "${RECON_DIR}/resolved.txt" 2>/dev/null || echo 0) hosts"

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
    "${RECON_DIR}/httpx.json" 2>/dev/null > "${RECON_DIR}/live-hosts.txt" || true
else
  while read -r host; do
    for proto in https http; do
      status=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${proto}://${host}" 2>/dev/null || echo "000")
      [ "$status" != "000" ] && echo "${proto}://${host} [${status}]" >> "${RECON_DIR}/live-hosts.txt" || true
    done
  done < "${TMP}/hosts-only.txt"
fi
log "  Live hosts: $(wc -l < "${RECON_DIR}/live-hosts.txt" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# Phase 6: VHOST discovery (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ] && have ffuf; then
  log "Phase 6: VHOST discovery (custom target-specific wordlist)"
  VHOST_WL="${TMP}/vhosts-target.txt"
  python3 "${ROOT}/tools/wordlist_gen.py" --target "${TARGET}" \
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
  grep -i "${TARGET}" | sort -u > "${RECON_DIR}/urls.txt"
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

grep '\.js' "${RECON_DIR}/urls.txt" 2>/dev/null | grep -v '\.json' | sort -u > "${RECON_DIR}/jsfiles.txt"
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
    curl -sk --max-time 10 "$jsurl" -o "${RECON_DIR}/js/${fname}.js" 2>/dev/null || true
  done < "${RECON_DIR}/jsfiles.txt"
  if have linkfinder && [ -n "$(ls -A "${RECON_DIR}/js/" 2>/dev/null)" ]; then
    find "${RECON_DIR}/js/" -name '*.js' -exec python3 -m linkfinder -i {} -o cli \; 2>/dev/null >> "${RECON_DIR}/js-endpoints.txt" || true
  fi
  log "  Downloaded JS files to ${RECON_DIR}/js/"
fi

# ---------------------------------------------------------------------------
# Phase 11: Hidden parameter discovery (deep only)
# ---------------------------------------------------------------------------
if [ "$MODE" == "--deep" ] && have x8; then
  log "Phase 11: Hidden parameter discovery (custom target-specific wordlist)"
  PARAM_WL="${TMP}/params-target.txt"
  python3 "${ROOT}/tools/wordlist_gen.py" --target "${TARGET}" \
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
  trufflehog filesystem "${RECON_DIR}/js/" --json --no-update 2>/dev/null > "${RECON_DIR}/secrets.json" || true
  log "  Secrets found: $(wc -l < "${RECON_DIR}/secrets.json" 2>/dev/null || echo 0)"
elif [ -f "${RECON_DIR}/urls.txt" ]; then
  {
    grep -oE 'ghp_[A-Za-z0-9_]{36}' "${RECON_DIR}/urls.txt" 2>/dev/null || true
    grep -oE 'AKIA[0-9A-Z]{16}' "${RECON_DIR}/urls.txt" 2>/dev/null || true
    grep -oE 'sk_live_[0-9a-zA-Z]{24,}' "${RECON_DIR}/urls.txt" 2>/dev/null || true
    grep -oE 'hooks\.slack\.com/services/[A-Za-z0-9/]+' "${RECON_DIR}/urls.txt" 2>/dev/null || true
  } | sort -u > "${RECON_DIR}/secrets-quick.txt"
  log "  Quick secret scan: $(wc -l < "${RECON_DIR}/secrets-quick.txt" 2>/dev/null || echo 0) potential matches"
fi

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
from tools.state import load_state, save_state
s = load_state('${TARGET}')
s.endpoints_tested = 0
s.findings_count = 0
save_state('${TARGET}', s)
print('[+] State initialized for ${TARGET}')
" 2>/dev/null || true
fi
