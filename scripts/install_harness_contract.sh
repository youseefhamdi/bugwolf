#!/usr/bin/env bash
set -euo pipefail

# Install only the short, harness-neutral project contract. This works from a
# source checkout and does not assume Claude Code, Freebuff, or Codebuff.
# Usage: ./scripts/install_harness_contract.sh [target-project-dir]

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-.}"
TARGET="$(cd "$TARGET" && pwd)"

install_if_missing() {
  local source="$1"
  local destination="$2"
  if [ -e "$destination" ]; then
    echo "    Keeping existing $destination"
  else
    cp "$source" "$destination"
    echo "    Installed $destination"
  fi
}

install_if_missing "$ROOT/configs/harness/BUGWOLF.md" "$TARGET/BUGWOLF.md"
install_if_missing "$ROOT/configs/harness/AGENTS.md" "$TARGET/AGENTS.md"
install_if_missing "$ROOT/configs/harness/CLAUDE.md" "$TARGET/CLAUDE.md"

PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/harness_guard.py" --init \
  --project-root "$TARGET" --skill-root "$ROOT" --json

echo "==> Universal BugWolf harness contract installed in $TARGET"
echo "    Reload BUGWOLF.md after context compaction or handoff."
