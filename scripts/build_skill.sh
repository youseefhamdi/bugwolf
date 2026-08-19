#!/usr/bin/env bash
set -euo pipefail

# Build the BugWolf .skill release bundle for Claude.ai (web/app upload).
# Usage: ./scripts/build_skill.sh
# Output: dist/bugwolf-v<version>.skill  (zip archive with SKILL.md at root)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(cat VERSION | tr -d '[:space:]')"
OUT_DIR="$ROOT/dist"
OUT_FILE="$OUT_DIR/bugwolf-v${VERSION}.skill"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> Building BugWolf v${VERSION} .skill bundle"

mkdir -p "$OUT_DIR" "$STAGE/bugwolf"

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
  "$STAGE/bugwolf/"

# Strip build artifacts from the bundle
rm -rf "$STAGE/bugwolf/tools/__pycache__" "$STAGE/bugwolf/tests/__pycache__"
find "$STAGE/bugwolf" -name '*.pyc' -delete
find "$STAGE/bugwolf" -name '*.tmp' -delete
find "$STAGE/bugwolf" -name '.DS_Store' -delete

if command -v zip >/dev/null 2>&1; then
  (cd "$STAGE" && zip -qr "$OUT_FILE" bugwolf)
else
  (cd "$STAGE" && python3 -c "
import shutil
shutil.make_archive('$STAGE/bundle', 'zip', '$STAGE', 'bugwolf')
")
  mv "$STAGE/bundle.zip" "$OUT_FILE"
fi

echo "==> Bundle written to $OUT_FILE ($(du -h "$OUT_FILE" | cut -f1))"