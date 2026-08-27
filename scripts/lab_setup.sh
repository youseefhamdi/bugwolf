#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.lab.yml"

usage() {
  echo "Usage: $0 {up|down|status|doctor} [runtime ...]"
  echo "Runtimes: browser emulator chain_node model mcp cloud"
}

compose_cmd=()
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose_cmd=(docker compose -f "$COMPOSE_FILE")
elif command -v docker-compose >/dev/null 2>&1; then
  compose_cmd=(docker-compose -f "$COMPOSE_FILE")
fi

profiles=(browser emulator chain_node model mcp cloud)
selected=("${@:2}")
if [ "${#selected[@]}" -eq 0 ]; then selected=("${profiles[@]}"); fi
profile_args=()
for runtime in "${selected[@]}"; do
  case " ${profiles[*]} " in
    *" $runtime "*) profile_args+=(--profile "$runtime");;
    *) echo "Unknown runtime: $runtime" >&2; usage; exit 2;;
  esac
done

case "${1:-}" in
  up)
    if [ "${#compose_cmd[@]}" -eq 0 ]; then
      echo "Docker Compose unavailable. Host fallback diagnostics:"
      echo "  browser: install Playwright/Chromium; run python3 -m playwright install chromium"
      echo "  emulator: install Android SDK emulator, or use a local Android container runtime"
      echo "  chain_node: install Foundry and run anvil --host 127.0.0.1 --port 8545"
      echo "  model: install Ollama and run ollama serve; pull a pinned model explicitly"
      echo "  mcp: run python3 lab/mcp/mcp_local_server.py (if supplied)"
      echo "  cloud: install LocalStack or use the local container image"
      exit 2
    fi
    "${compose_cmd[@]}" "${profile_args[@]}" up -d
    ;;
  down)
    if [ "${#compose_cmd[@]}" -eq 0 ]; then echo "Docker Compose unavailable" >&2; exit 2; fi
    "${compose_cmd[@]}" down --remove-orphans
    ;;
  status)
    if [ "${#compose_cmd[@]}" -eq 0 ]; then echo "Docker Compose unavailable" >&2; exit 2; fi
    "${compose_cmd[@]}" ps
    ;;
  doctor)
    exec python3 "$ROOT/tools/lab_doctor.py" --json
    ;;
  *) usage; exit 2;;
esac
