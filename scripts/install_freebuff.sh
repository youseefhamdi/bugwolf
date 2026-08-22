#!/usr/bin/env bash
set -euo pipefail

# Install BugWolf into a Freebuff/Codebuff project's .agents/skills/ directory
# (the directory Freebuff and Codebuff load skills from at session start).
# This is the same layout `npx skills add youseefhamdi/bugwolf --skill bugwolf --copy`
# produces, minus the other agent directories — offline and CLI-free.
# Usage: ./scripts/install_freebuff.sh [target-project-dir]   (default: current directory)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-.}"
DEST="$TARGET/.agents/skills/bugwolf"

if [ -e "$DEST" ]; then
  echo "==> Removing existing $DEST"
  rm -rf "$DEST"
fi

mkdir -p "$DEST"
cp -r \
  "$ROOT"/SKILL.md \
  "$ROOT"/README.md \
  "$ROOT"/CHANGELOG.md \
  "$ROOT"/VERSION \
  "$ROOT"/LICENSE \
  "$ROOT"/references \
  "$ROOT"/tools \
  "$ROOT"/wordlists \
  "$ROOT"/tests \
  "$ROOT"/scripts \
  "$ROOT"/configs \
  "$DEST/"

rm -rf "$DEST/tools/__pycache__" "$DEST/tests/__pycache__"
find "$DEST" -name '*.pyc' -delete
find "$DEST" -name '*.tmp' -delete
find "$DEST" -name '.DS_Store' -delete

# Install short project-local instructions understood by multiple harnesses.
# Never overwrite an existing project instruction file.
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
install_if_missing "$DEST/configs/harness/BUGWOLF.md" "$TARGET/BUGWOLF.md"
install_if_missing "$DEST/configs/harness/AGENTS.md" "$TARGET/AGENTS.md"
install_if_missing "$DEST/configs/harness/CLAUDE.md" "$TARGET/CLAUDE.md"

# Initialize a tamper-evident, offline contract manifest in the project.
PYTHONDONTWRITEBYTECODE=1 python3 "$DEST/tools/harness_guard.py" --init \
  --project-root "$TARGET" --skill-root "$DEST" --json

echo "==> BugWolf installed to $DEST"
echo "    Start any supported AI harness in $TARGET — reload BUGWOLF.md when context changes."
