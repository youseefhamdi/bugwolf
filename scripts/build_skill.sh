#!/usr/bin/env bash
set -euo pipefail

# Build the BugWolf release bundles.
#   dist/bugwolf-v<version>.skill          — Claude.ai (web/app) upload: zip with SKILL.md at root
#   dist/bugwolf-v<version>.freebuff.zip   — Freebuff/Codebuff: zip laid out as .agents/skills/bugwolf/…
#                                            (unzip into any project, or install with
#                                            `npx skills add youseefhamdi/bugwolf --skill bugwolf`)
# Usage: ./scripts/build_skill.sh
# Output: dist/bugwolf-v<version>.skill and dist/bugwolf-v<version>.freebuff.zip

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(cat VERSION | tr -d '[:space:]')"
OUT_DIR="$ROOT/dist"
OUT_SKILL="$OUT_DIR/bugwolf-v${VERSION}.skill"
OUT_FREEBUFF="$OUT_DIR/bugwolf-v${VERSION}.freebuff.zip"
STAGE="$(mktemp -d)"
STAGE_FB="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$STAGE_FB"' EXIT

echo "==> Building BugWolf v${VERSION} release bundles"

mkdir -p "$OUT_DIR" "$STAGE" "$STAGE_FB"

# Shared payload for both bundles.
cp -r \
  SKILL.md \
  README.md \
  CHANGELOG.md \
  VERSION \
  LICENSE \
  references \
  tools \
  wordlists \
  tests \
  scripts \
  configs \
  docs \
  .claude-plugin \
  hooks \
  commands \
  bridge \
  "$STAGE/"

# Strip build artifacts from the bundle
find "$STAGE" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.pyc' -delete
find "$STAGE" -name '*.tmp' -delete
find "$STAGE" -name '.DS_Store' -delete

# --- Claude.ai .skill bundle (SKILL.md at archive root) --------------------
if command -v zip >/dev/null 2>&1; then
  (cd "$STAGE" && zip -qr "$OUT_SKILL" .)
else
  (cd "$STAGE" && python3 -c "
import shutil
shutil.make_archive('$STAGE/bundle', 'zip', '$STAGE')
")
  mv "$STAGE/bundle.zip" "$OUT_SKILL"
fi

# --- Freebuff/Codebuff bundle (.agents/skills/bugwolf/ at archive root) ----
mkdir -p "$STAGE_FB/.agents/skills/bugwolf"
cp -r "$STAGE"/. "$STAGE_FB/.agents/skills/bugwolf/"
if command -v zip >/dev/null 2>&1; then
  (cd "$STAGE_FB" && zip -qr "$OUT_FREEBUFF" .)
else
  (cd "$STAGE_FB" && python3 -c "
import shutil
shutil.make_archive('$STAGE_FB/bundle', 'zip', '$STAGE_FB')
")
  mv "$STAGE_FB/bundle.zip" "$OUT_FREEBUFF"
fi

echo "==> Claude.ai bundle:   $OUT_SKILL ($(du -h "$OUT_SKILL" | cut -f1))"
echo "==> Freebuff bundle:    $OUT_FREEBUFF ($(du -h "$OUT_FREEBUFF" | cut -f1))"
