#!/usr/bin/env bash
# BugWolf CI anti-pattern grep gate (Plan Appendix G + H).
#
# Fails the build if any of the audit-cited anti-patterns reappear as
# FUNCTIONAL code (not just documentation references or anti-pattern
# regression tests):
#
#   * A-1 / A-4   ``shell=True`` used as a keyword argument in tools/
#                  (subprocess injection risk).  We require a leading
#                  comma or opening paren within the line to distinguish
#                  from docstrings/comments.
#   * A-8         bypass / yolo aliases in tools/ (real declaration)
#   * A-13        ``## Description:`` frontmatter in agents/bugwolf/
#                  (the package uses YAML frontmatter only — a stray
#                  ``## Description:`` is the classic prompt-injection
#                  smuggling vector)
#   * AP-XP-5     ``verify=False`` used as a kwarg in tools/ (TLS bypass)
#   * AP-XP-6     ``from scrapling.parser`` import in tools/ (scrapling
#                  fuzzing is forbidden by Appendix H)
#   * AP-XP-8     ``POUET`` / ``UNCHECKOUT`` markers in tools/
#                  (Phase 0 UNCENSORED / kill-switch bypasses)
#   * AP-XP-11    auto-install / community-skill / skill-marketplace
#                  references anywhere (520/17,022 community skills leak
#                  credentials per the Loop Engineering article).
#
# The script additionally keeps the existing Phase 0 ``# UNCENSORED:``
# marker sweep that ``grep -rn`` every Python file under the repo
# root, excluding tests/ (which legitimately simulate bypasses) and
# scripts/ci_anti_patterns.sh itself.
#
# Exit codes:
#   0   all gates pass
#   1   at least one gate failed
#   2   internal error (missing grep / wrong directory)
#
# Usage:
#   bash scripts/ci_anti_patterns.sh
#
# The script is intentionally bash + grep only — no Python mocks.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ESC_FAIL=$'\033[31m'
ESC_OK=$'\033[32m'
ESC_RESET=$'\033[0m'

fail_count=0
fail() {
    echo "${ESC_FAIL}[CI-ANTIPATTERN] FAIL: $1${ESC_RESET}" >&2
    fail_count=$((fail_count + 1))
}

ok() {
    echo "${ESC_OK}[CI-ANTIPATTERN] PASS: $1${ESC_RESET}"
}

# Guard: grep must exist.
if ! command -v grep >/dev/null 2>&1; then
    echo "${ESC_FAIL}[CI-ANTIPATTERN] grep binary missing${ESC_RESET}" >&2
    exit 2
fi

# Guard: tools/ and agents/bugwolf/ must exist.
if [ ! -d "tools" ]; then
    echo "${ESC_FAIL}[CI-ANTIPATTERN] tools/ directory missing under $ROOT${ESC_RESET}" >&2
    exit 2
fi
if [ ! -d "agents/bugwolf" ]; then
    echo "${ESC_FAIL}[CI-ANTIPATTERN] agents/bugwolf/ directory missing under $ROOT${ESC_RESET}" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# A-1 / A-4: shell=True used as a keyword argument in tools/
# (the line must contain an opening paren or trailing comma BEFORE
# ``shell=True`` to filter out documentation / docstring mentions).
# ---------------------------------------------------------------------------

if grep -rEn '(,[[:space:]]*|\()[[:space:]]*shell=True[[:space:]]*[,)]' tools/ \
        --include='*.py' \
        --exclude-dir='__pycache__' >/dev/null 2>&1; then
    fail "A-1/A-4: functional shell=True call found in tools/"
    grep -rEn '(,[[:space:]]*|\()[[:space:]]*shell=True[[:space:]]*[,)]' tools/ \
        --include='*.py' \
        --exclude-dir='__pycache__' >&2 || true
else
    ok "A-1/A-4: no functional shell=True call in tools/"
fi

# ---------------------------------------------------------------------------
# A-8: bypass / yolo aliases (declaration, not mention)
# Matches patterns like ``alias bypass=...`` or ``alias yolo=...``.
# ---------------------------------------------------------------------------

if grep -rEn 'alias[[:space:]]+(bypass|yolo)' tools/ \
        --include='*.py' \
        --include='*.sh' \
        --exclude-dir='__pycache__' >/dev/null 2>&1; then
    fail "A-8: bypass / yolo alias declaration found in tools/"
    grep -rEn 'alias[[:space:]]+(bypass|yolo)' tools/ \
        --include='*.py' \
        --include='*.sh' \
        --exclude-dir='__pycache__' >&2 || true
else
    ok "A-8: no bypass / yolo alias declaration in tools/"
fi

# ---------------------------------------------------------------------------
# A-13: ## Description: frontmatter in agents/bugwolf/
# The package uses YAML frontmatter only — a stray ``## Description:``
# at the start of a line is the classic prompt-injection smuggling
# vector and is forbidden.
# ---------------------------------------------------------------------------

if grep -rn "^## Description:" agents/bugwolf/ \
        --exclude-dir='__pycache__' >/dev/null 2>&1; then
    fail "A-13: '## Description:' frontmatter found in agents/bugwolf/"
    grep -rn "^## Description:" agents/bugwolf/ \
        --exclude-dir='__pycache__' >&2 || true
else
    ok "A-13: no '## Description:' frontmatter in agents/bugwolf/"
fi

# ---------------------------------------------------------------------------
# AP-XP-5: verify=False used as a kwarg in tools/ (TLS bypass)
# Same discriminator as A-1: a leading ``,`` or ``(`` before
# ``verify=False`` filters out docstring references.
# ---------------------------------------------------------------------------

if grep -rEn '(,[[:space:]]*|\()[[:space:]]*verify=False[[:space:]]*[,)]' tools/ \
        --include='*.py' \
        --exclude-dir='__pycache__' >/dev/null 2>&1; then
    fail "AP-XP-5: functional verify=False call found in tools/"
    grep -rEn '(,[[:space:]]*|\()[[:space:]]*verify=False[[:space:]]*[,)]' tools/ \
        --include='*.py' \
        --exclude-dir='__pycache__' >&2 || true
else
    ok "AP-XP-5: no functional verify=False call in tools/"
fi

# ---------------------------------------------------------------------------
# AP-XP-6: from scrapling.parser in tools/
# (only ``import`` statements — not docstring mentions).
# ---------------------------------------------------------------------------

if grep -rEn 'from[[:space:]]+scrapling\.parser[[:space:]]+import' tools/ \
        --include='*.py' \
        --exclude-dir='__pycache__' >/dev/null 2>&1; then
    fail "AP-XP-6: 'from scrapling.parser' import found in tools/"
    grep -rEn 'from[[:space:]]+scrapling\.parser[[:space:]]+import' tools/ \
        --include='*.py' \
        --exclude-dir='__pycache__' >&2 || true
else
    ok "AP-XP-6: no scrapling.parser import in tools/"
fi

# ---------------------------------------------------------------------------
# AP-XP-8: POUET / UNCHECKOUT markers (Phase 0 UNCENSORED smuggling)
# These are kill-switch / unsafe-confirm tokens that bypass the gate;
# they must not appear as functional code.
# ---------------------------------------------------------------------------

# POUET only matches when used as a bare token (not as a substring of
# an identifier).  We allow the strings to appear inside triple-quoted
# docstrings (where they are documented) by matching only at the start
# of an identifier boundary.
if grep -rEn '(^|[^A-Za-z0-9_])(POUET|UNCHECKOUT)([^A-Za-z0-9_]|$)' tools/ \
        --include='*.py' \
        --include='*.sh' \
        --exclude-dir='__pycache__' >/dev/null 2>&1; then
    fail "AP-XP-8: POUET / UNCHECKOUT marker found in tools/"
    grep -rEn '(^|[^A-Za-z0-9_])(POUET|UNCHECKOUT)([^A-Za-z0-9_]|$)' tools/ \
        --include='*.py' \
        --include='*.sh' \
        --exclude-dir='__pycache__' >&2 || true
else
    ok "AP-XP-8: no POUET / UNCHECKOUT markers in tools/"
fi

# ---------------------------------------------------------------------------
# AP-XP-11: auto-installed community skills (3% credential-leak rate per
# the "Loop Engineering" X article: 520/17,022 community skills leak
# credentials).  Bugwolf currently has NO auto-install flow, but if it
# ever adds a marketplace / plugin install, this gate prevents accidental
# community-skill auto-installation.
#
# We use a tighter regex (auto_install_plugin, auto_install_skill,
# community_skill_install, skill_marketplace_*) to avoid false positives
# in CIS benchmark docs / cloud-provider config files that mention
# "auto-install" for completely unrelated concepts (MMA agent, etc.).
# ---------------------------------------------------------------------------

if grep -rEn '(auto_install_(plugin|skill|extension|module)|community_skill_(install|registry|marketplace)|skill_marketplace_(install|enable))' . \
        --include='*.py' \
        --include='*.sh' \
        --exclude-dir='__pycache__' \
        --exclude-dir='.git' \
        --exclude-dir='state' \
        --exclude-dir='dist' \
        --exclude-dir='docs' \
        --exclude-dir='tests' \
        --exclude-dir='cloud' \
        --exclude='ci_anti_patterns.sh' \
        --exclude='SECURITY.md' \
        --exclude='MAX_*.md' >/dev/null 2>&1; then
    fail "AP-XP-11: community-skill auto-install reference detected"
    grep -rEn '(auto_install_(plugin|skill|extension|module)|community_skill_(install|registry|marketplace)|skill_marketplace_(install|enable))' . \
        --include='*.py' \
        --include='*.sh' \
        --exclude-dir='__pycache__' \
        --exclude-dir='.git' \
        --exclude-dir='state' \
        --exclude-dir='dist' \
        --exclude-dir='docs' \
        --exclude-dir='tests' \
        --exclude-dir='cloud' \
        --exclude='ci_anti_patterns.sh' \
        --exclude='SECURITY.md' \
        --exclude='MAX_*.md' >&2 || true
else
    ok "AP-XP-11: no community-skill auto-install references"
fi

# ---------------------------------------------------------------------------
# Phase 0 UNCENSORED marker sweep (whole repo, excluding tests/ which
# legitimately simulate bypasses, and the audit-trail docstrings in
# bugwolf/governance/ that document that the bypasses were closed).
#
# A genuine `# UNCENSORED:` bypass marker takes the form:
#     # UNCENSORED: <reason>
# at the start of a comment, NOT inside a triple-quoted docstring.
# We require the marker to be at the START of a line (after optional
# leading whitespace) so docstring mentions are ignored.
# ---------------------------------------------------------------------------

if grep -rEn '^[[:space:]]*#[[:space:]]*UNCENSORED:' . \
        --include='*.py' \
        --exclude-dir='__pycache__' \
        --exclude-dir='.git' \
        --exclude-dir='state' \
        --exclude-dir='dist' \
        --exclude-dir='tests' \
        --exclude-dir='docs' \
        --exclude='ci_anti_patterns.sh' >/dev/null 2>&1; then
    fail "Phase 0: '# UNCENSORED:' marker found in repo"
    grep -rEn '^[[:space:]]*#[[:space:]]*UNCENSORED:' . \
        --include='*.py' \
        --exclude-dir='__pycache__' \
        --exclude-dir='.git' \
        --exclude-dir='state' \
        --exclude-dir='dist' \
        --exclude-dir='tests' \
        --exclude-dir='docs' \
        --exclude='ci_anti_patterns.sh' >&2 || true
else
    ok "Phase 0: no '# UNCENSORED:' marker in repo"
fi

# ---------------------------------------------------------------------------
# Summary + exit.
# ---------------------------------------------------------------------------

if [ "$fail_count" -gt 0 ]; then
    echo "${ESC_FAIL}[CI-ANTIPATTERN] $fail_count gate(s) FAILED${ESC_RESET}" >&2
    exit 1
fi

echo "${ESC_OK}[CI-ANTIPATTERN] all gates passed${ESC_RESET}"
exit 0