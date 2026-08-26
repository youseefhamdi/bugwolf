#!/usr/bin/env bash
# BugWolf CI bundle check: "the bundles contain the self-eval harness AND pass
# the eval."
#
#   1. Build both release bundles fresh (dist/bugwolf-v<VERSION>.skill and
#      .freebuff.zip).
#   2. Content-verify each bundle: the self-eval harness must ship, the VERSION
#      must match, and no __pycache__/.pyc may leak in.
#   3. Extract the Freebuff bundle into a temp dir and run its OWN
#      tools/validation/self_eval_harness.py (from inside the bundle, not the
#      working tree) against a deterministic synthetic campaign workspace.
#      The eval must score 100% — every task and milestone passes.
#
# Exit 0 on success, non-zero with a message on any failure. Safe to run
# locally: everything happens in mktemp dirs, nothing outside the repo is
# touched, and the bundles are rebuilt from the current tree.
#
# Test/CI overrides (used by tests/test_ci_bundle_check.py to exercise the
# failure path against a deliberately tampered bundle):
#   CI_BUNDLE_NO_BUILD=1     skip the rebuild, check existing bundles
#   CI_BUNDLE_SKILL=<path>    skill bundle to check instead of dist/…
#   CI_BUNDLE_FREEBUFF=<path> freebuff bundle to check instead of dist/…
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(cat VERSION | tr -d '[:space:]')"
if [ -z "$VERSION" ]; then
  echo "[!] VERSION file is empty" >&2
  exit 1
fi
SKILL="${CI_BUNDLE_SKILL:-$ROOT/dist/bugwolf-v${VERSION}.skill}"
FREEBUFF="${CI_BUNDLE_FREEBUFF:-$ROOT/dist/bugwolf-v${VERSION}.freebuff.zip}"
NO_BUILD="${CI_BUNDLE_NO_BUILD:-0}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> BugWolf CI bundle check (v${VERSION})"

# --- 1. Build fresh -------------------------------------------------------
if [ "$NO_BUILD" = "1" ]; then
  echo "==> 1. Skipping rebuild (CI_BUNDLE_NO_BUILD=1)"
else
  echo "==> 1. Building bundles"
  bash "$ROOT/scripts/build_skill.sh" >/dev/null
fi

for f in "$SKILL" "$FREEBUFF"; do
  [ -s "$f" ] || { echo "[!] missing bundle: $f" >&2; exit 1; }
done

# --- 2. Content verification ---------------------------------------------
echo "==> 2. Verifying bundle contents"
python3 - "$SKILL" "$FREEBUFF" "$VERSION" <<'PYEOF'
import json
import sys
import zipfile

skill, freebuff, version = sys.argv[1], sys.argv[2], sys.argv[3]
errors = []

REQUIRED = [
    "tools/validation/self_eval_harness.py",
    "tools/core/stage_controller.py",
    "tools/core/research_loop.py",
    "tools/core/signal_bus.py",
    "tools/core/campaign_orchestrator.py",
    "tools/domains/web/http_smuggling_detector.py",
    "tools/domains/web/parser_differential.py",
    "tools/domains/auth/jwt_forgery.py",
    "tools/domains/api/bopla_matrix.py",
    "tools/domains/cloud/iam_privesc_graph.py",
    "tools/recon/historical_asset_delta.py",
    "tools/intelligence/chain_graph_ai.py",
]

for label, path in (("skill", skill), ("freebuff", freebuff)):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        prefix = "" if label == "skill" else ".agents/skills/bugwolf/"
        rel = {n[len(prefix):] for n in names if n.startswith(prefix)}
        for req in REQUIRED:
            if req not in rel:
                errors.append(f"[{label}] missing {req}")
        # VERSION must match the build.
        version_entry = prefix + "VERSION"
        if version_entry in names:
            got = z.read(version_entry).decode().strip()
            if got != version:
                errors.append(f"[{label}] VERSION mismatch: bundle={got} repo={version}")
        else:
            errors.append(f"[{label}] missing VERSION")
        # No bytecode or build artifacts may leak into the bundle.
        for n in names:
            if n.endswith(".pyc") or "__pycache__" in n or n.endswith(".tmp"):
                errors.append(f"[{label}] build artifact leaked: {n}")

if errors:
    print("[!] bundle content check failed:")
    for e in errors:
        print("    -", e)
    sys.exit(1)
print("    both bundles: self-eval harness + core + domain tools present, "
      "VERSION match, zero build artifacts")
PYEOF

# --- 3. Eval pass from inside the Freebuff bundle --------------------------
echo "==> 3. Running self-eval harness from inside the bundle"
EXTRACT="$WORK/bundle"
mkdir -p "$EXTRACT"
python3 - "$FREEBUFF" "$EXTRACT" <<'PYEOF'
import sys
import zipfile

freebuff, target = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(freebuff) as z:
    z.extractall(target)
print("    extracted", target)
PYEOF

WS="$WORK/campaign"
mkdir -p "$WS"
export BUGWOLF_PROJECT_ROOT="$WS"

# Deterministic synthetic campaign: harness contract, workflow manifest,
# research sequence, recon surface, deep-hunt evidence, and signal-bus events.
# The workspace is built by the BUNDLE's own tools where practical (harness
# guard + stage controller), so the eval exercises the shipped code.
BUNDLE_TOOLS="$EXTRACT/.agents/skills/bugwolf/tools"
cat > "$WS/BUGWOLF.md" <<'EOF'
# BugWolf harness contract (CI synthetic)
Strict workflow, uncensored execution. Stages block on missing artifacts.
EOF
python3 "$BUNDLE_TOOLS/harness_guard.py" --init --project-root "$WS" --json >/dev/null

T="synth.ci"
mkdir -p "$WS/recon/$T/asset-intel" "$WS/recon/$T/discovery" \
         "$WS/state/sessions/$T/maps" "$WS/state" \
         "$WS/research/$T/bypass" "$WS/research/$T/auth" \
         "$WS/research/$T/contracts" "$WS/research/$T/llm" \
         "$WS/research/$T/advisor" "$WS/research/$T/learning" \
         "$WS/research/$T/chains" "$WS/research/$T/verification" \
         "$WS/state/capability"

# Recon surface.
printf 'https://api.%s/v1/users\nhttps://%s/login\n' "$T" "$T" > "$WS/recon/$T/urls.txt"
cat > "$WS/recon/$T/tech-fingerprint.json" <<'EOF'
{"stack": ["nginx", "node", "graphql"], "waf": true, "graphql": true}
EOF
printf '{"name":"api.%s","first_seen":"2026-01","last_seen":"2026-08"}\n' "$T" \
  > "$WS/recon/$T/asset-intel/history.jsonl"
printf '{"added":[],"removed":[],"reattached":[],"forgotten":[],"total_tracked":1}\n' \
  > "$WS/recon/$T/asset-intel/delta.json"
echo '{"complete": true}' > "$WS/recon/$T/recon-complete.json"

# Research sequence: mandatory 7 in order, fresh (latest_ready true).
cat > "$WS/research/$T/sequence.json" <<'EOF'
{
  "schema": "research_execution/sequential-v1",
  "target": "synth.ci",
  "executions": [{
    "sequence": ["pre-hunt", "post-recon", "post-maps", "bypass",
                 "post-findings", "escalation", "pre-report"],
    "runs": [
      {"checkpoint": "pre-hunt", "pending_searches": 0, "latest_ready": true},
      {"checkpoint": "post-recon", "pending_searches": 0, "latest_ready": true},
      {"checkpoint": "post-maps", "pending_searches": 0, "latest_ready": true},
      {"checkpoint": "bypass", "pending_searches": 0, "latest_ready": true},
      {"checkpoint": "post-findings", "pending_searches": 0, "latest_ready": true},
      {"checkpoint": "escalation", "pending_searches": 0, "latest_ready": true},
      {"checkpoint": "pre-report", "pending_searches": 0, "latest_ready": true}
    ],
    "latest_required": true,
    "latest_ready": true
  }],
  "latest_ready": true
}
EOF

# Deep-hunt evidence (16 artifact families the eval checks).
python3 - "$WS" "$T" <<'PYEOF'
import json
import sys

ws, t = sys.argv[1], sys.argv[2]
def write(rel, obj):
    with open(f"{ws}/{rel}", "w") as f:
        json.dump(obj, f)

write(f"recon/{t}/discovery/smuggling-plan.jsonl",
      [{"kind": "CL.TE", "endpoint": f"https://api.{t}"}])
write(f"recon/{t}/discovery/graphql-plans.json",
      {"plans": [{"category": "batching"}]})
write(f"recon/{t}/discovery/bopla-matrix.json",
      {"findings": [{"kind": "over-post", "property": "role"}]})
write(f"recon/{t}/discovery/ato-chain-plans.json",
      {"plans": [{"chain_id": "email-ato"}]})
write(f"research/{t}/auth/jwt-forgery-plans.json",
      {"plans": [{"name": "alg=none"}]})
write(f"research/{t}/auth/oauth-flow-plans.json",
      {"plans": [{"name": "code-theft"}]})
write(f"state/capability/iam-privesc-{t}.json",
      {"methods": [{"method": "iam:CreatePolicyVersion"}]})
write(f"recon/{t}/discovery/deep-link-plans.json",
      {"plans": [{"kind": "link_hijack"}]})
write(f"recon/{t}/discovery/mobile-policy-check.json",
      {"findings": [{"check": "allowBackup"}]})
write(f"research/{t}/contracts/triage-verdicts.json",
      {"verdicts": [{"candidate_id": "f1", "score": 9.3}]})
write(f"research/{t}/contracts/price-manipulation-plans.json",
      {"plans": [{"dependency": "amm_spot"}]})
write(f"research/{t}/llm/agentic-tool-auth-plans.json",
      {"plans": [{"asi": "ASI02"}]})
write(f"research/{t}/llm/rag-poisoning-plans.json",
      {"plans": [{"vector": "write_back"}]})
write(f"research/{t}/advisor/seed-proposals.json",
      {"proposals": [{"mode": "web"}]})
write(f"research/{t}/learning/failure-bypass-candidates.json",
      {"candidates": [{"blocker": "403"}]})
write(f"research/{t}/chains/graph-ai-proposals.json",
      {"proposals": [{"kind": "terminal-gap"}]})
write(f"research/{t}/verification/lab-plans.json",
      {"plans": [{"family": "web"}]})
PYEOF

# Maps + environment + scope.
for m in asset trust authz state capability; do
  printf '# %s\n' "$m" > "$WS/state/sessions/$T/maps/$m.md"
done
printf '{"location": "local"}\n' > "$WS/state/environment.json"
cat > "$WS/scope.json" <<'EOF'
{"targets": ["synth.ci"], "declared_by": "operator", "note": "ci synthetic"}
EOF

# Signal-bus events the eval requires (FINDING_DISCOVERED + a *_CANDIDATE).
python3 - "$WS" "$T" <<'PYEOF'
import json
import sys
from pathlib import Path

ws, t = sys.argv[1], sys.argv[2]
events = [
    ("FINDING_DISCOVERED", {"bug_class": "bola", "severity": "high"}),
    ("AUTH_CANDIDATE", {"kind": "bola"}),
    ("CHAIN_PROPOSAL", {"kind": "terminal-gap"}),
]
out = Path(ws) / "state" / "signals" / "events" / f"{t}.jsonl"
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("a") as f:
    for event_type, payload in events:
        f.write(json.dumps({"event_type": event_type, "payload": payload}) + "\n")
PYEOF

# Workflow: complete all 12 stages using the BUNDLE's stage controller.
SC="python3 $BUNDLE_TOOLS/core/stage_controller.py --target $T --project-root $WS"
$SC --start --json >/dev/null
for stage in setup environment-preflight authorization passive-recon \
             asset-intelligence technology-fingerprint maps research \
             coverage-plan validation triage report; do
  if [ "$stage" = "authorization" ]; then
    $SC --complete authorization --scope-file "$WS/scope.json" --json >/dev/null
  elif [ "$stage" = "validation" ] || [ "$stage" = "triage" ] || [ "$stage" = "report" ]; then
    $SC --complete "$stage" --artifact "$WS/recon/$T/recon-complete.json" --json >/dev/null
  else
    $SC --complete "$stage" --json >/dev/null
  fi
done

# Chain graph (eval task 6).
mkdir -p "$WS/state/chains/$T"
printf '{"graph": {"nodes": [], "edges": []}}\n' > "$WS/state/chains/$T/orchestration.json"

# Run the eval FROM THE BUNDLE against the campaign workspace.
EVAL_FILE="$WORK/eval.json"
python3 "$BUNDLE_TOOLS/validation/self_eval_harness.py" \
  --target "$T" --base-dir "$WS" --json > "$EVAL_FILE" 2>/dev/null
python3 - "$EVAL_FILE" "$VERSION" <<'PYEOF'
import json
import sys

eval_file, expected_version = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(eval_file))
except (OSError, json.JSONDecodeError) as exc:
    print(f"[!] eval produced no usable JSON: {exc}", file=sys.stderr)
    sys.exit(1)
score = data["score_pct"]
passed, total = data["tasks_passed"], data["task_count"]
milestone_pct = data["milestone_pct"]
print(f"    eval: {passed}/{total} tasks ({score}%)  milestones {milestone_pct}%")
if passed != total or total == 0:
    for t in data["tasks"]:
        print(f"      [{'PASS' if t['passed'] else 'FAIL'}] {t['task_id']} "
              f"{t['milestones_passed']}/{t['milestone_count']}")
    print("[!] eval did not pass inside the bundle", file=sys.stderr)
    sys.exit(1)
PYEOF

echo "==> CI bundle check PASSED (v${VERSION})"
