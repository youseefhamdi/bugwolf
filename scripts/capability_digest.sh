#!/bin/bash
# Capability digest drift check (Plan R-14).
# Recomputes a SHA-256 over the capability_registry + scanners/__init__
# modules and compares against the stored digest.  On the first run the
# digest is written (and committed) so subsequent runs have a baseline.
#
# Exit codes:
#   0  digest matches (or was just initialised)
#   1  drift detected -- capability surface changed without updating the
#      digest file.  Bump scripts/capability_digest.txt to acknowledge.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - <<'PYEOF'
import hashlib, sys
from pathlib import Path

def digest(paths):
    h = hashlib.sha256()
    for p in sorted(paths):
        if p.is_file():
            h.update(p.read_bytes())
            h.update(b"\0")
    return h.hexdigest()

paths = list(Path("tools/capability_registry.py").parent.glob("capability_registry.py"))
paths += list(Path("bugwolf/scanners/__init__.py").parent.glob("__init__.py"))
new = digest(paths)
stored_path = Path("scripts/capability_digest.txt")
stored = stored_path.read_text().strip() if stored_path.exists() else ""
if not stored:
    stored_path.write_text(new + "\n")
    print("[+] Initial digest committed:", new[:16])
elif stored != new:
    print("[!] DRIFT: stored", stored[:16], "vs current", new[:16])
    sys.exit(1)
else:
    print("[+] Capability digest matches:", new[:16])
PYEOF
