#!/usr/bin/env bash
set -euo pipefail

# ─── Configurable ports ───────────────────────────────────────────────
API_PORT="${API_PORT:-3000}"
WEB_PORT="${WEB_PORT:-5173}"
# ──────────────────────────────────────────────────────────────────────

ROOT="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$ROOT/.ogre/keys"
LOG_DIR="$ROOT/.ogre/logs"
mkdir -p "$LOG_DIR"

API_LOG="$LOG_DIR/api.log"
WEB_LOG="$LOG_DIR/web.log"

cleanup() {
  echo ""
  echo "Shutting down..."
  kill "$API_PID" "$WEB_PID" 2>/dev/null || true
  wait "$API_PID" "$WEB_PID" 2>/dev/null || true
  echo "Done. Logs at: $LOG_DIR/"
}
trap cleanup EXIT INT TERM

# Check ports are free
for port in "$API_PORT" "$WEB_PORT"; do
  if lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
    pid=$(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1)
    name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
    echo "ERROR: Port $port is already in use by $name (pid $pid)"
    echo "  Either kill it or use a different port:"
    echo "  API_PORT=4000 WEB_PORT=8080 ./dev.sh"
    exit 1
  fi
done

# Build backend
echo "Building backend..."
cargo build -p ogre-api --quiet

# Start API server (output to log file)
OGRE_BIND="0.0.0.0:$API_PORT" \
  cargo run -p ogre-api --quiet > "$API_LOG" 2>&1 &
API_PID=$!

# Start frontend dev server (output to log file)
cd "$ROOT/web"
VITE_API_PORT="$API_PORT" \
  npx vite --port "$WEB_PORT" --strictPort > "$WEB_LOG" 2>&1 &
WEB_PID=$!
cd "$ROOT"

# Wait for API to be ready
printf "Waiting for API"
for i in $(seq 1 30); do
  if curl -s "http://localhost:$API_PORT/api/v1/dashboard/summary" >/dev/null 2>&1; then
    break
  fi
  printf "."
  sleep 0.5
done
echo " ready!"

# Print banner
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  OGRE — Operational Governance for Resource Enforcement"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Dashboard:   http://localhost:$WEB_PORT"
echo "  API Base:    http://localhost:$API_PORT/api/v1"
echo ""
echo "  ── Quick Links ──"
echo "  GET  /dashboard/summary    http://localhost:$API_PORT/api/v1/dashboard/summary"
echo "  GET  /agents               http://localhost:$API_PORT/api/v1/agents"
echo "  GET  /rules                http://localhost:$API_PORT/api/v1/rules"
echo "  GET  /actions/pending      http://localhost:$API_PORT/api/v1/actions/pending"
echo "  GET  /connectors           http://localhost:$API_PORT/api/v1/connectors"
echo "  GET  /audit                http://localhost:$API_PORT/api/v1/audit"
echo "  GET  /keys                 http://localhost:$API_PORT/api/v1/keys"
echo ""
if [ -d "$KEYS_DIR" ]; then
  echo "  ── Keys (.ogre/keys/) ──"
  for f in "$KEYS_DIR"/*.key; do
    name="$(basename "$f" .key)"
    printf "  %-12s %s\n" "$name:" "$(cat "$f")"
  done
  echo ""
fi
echo "  ── Logs ──"
echo "  API:         tail -f $API_LOG"
echo "  Frontend:    tail -f $WEB_LOG"
echo ""
echo "  ── Examples ──"
echo ""
echo "  # Register an agent"
echo "  curl -X POST http://localhost:$API_PORT/api/v1/agents \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"agent_id\": \"my-bot\"}'"
echo ""
echo "  # Create a RequireApproval rule"
echo "  curl -X POST http://localhost:$API_PORT/api/v1/rules \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"description\": \"Approve destructive ops\", \"condition\": {\"op\": \"action_level_is\", \"level\": \"destructive\"}, \"effect\": \"require_approval\", \"priority\": 50}'"
echo ""
echo "  # Change ports: API_PORT=4000 WEB_PORT=8080 ./dev.sh"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Press Ctrl+C to stop"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

wait
