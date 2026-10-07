#!/usr/bin/env bash
# Start the standalone Aspire dashboard installed by install.sh.
# Idempotent: if the UI or OTLP ports are already listening, do not start a second instance.
set -euo pipefail

ASPIRE_DASHBOARD_VERSION=13.6.0
ROOT="/opt/aspire-dashboard/${ASPIRE_DASHBOARD_VERSION}"
BIN="${ROOT}/tools/Aspire.Dashboard"
LOG_FILE="${ASPIRE_DASHBOARD_LOG:-/tmp/aspire-dashboard.log}"
PID_FILE="${ASPIRE_DASHBOARD_PID:-/tmp/aspire-dashboard.pid}"

port_listening() {
  python3 - "$1" <<'PY'
import socket, sys
port = int(sys.argv[1])
targets = [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]
for family, addr in targets:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            sock.connect((addr, port))
            sys.exit(0)
    except OSError:
        continue
sys.exit(1)
PY
}

ui_status() {
  local url="$1"
  curl -sS -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null || true
}

wait_for_ui() {
  local i code url
  for i in $(seq 1 90); do
    if port_listening 4317; then
      for url in "http://127.0.0.1:18888/" "http://localhost:18888/"; do
        code="$(ui_status "$url")"
        if [[ "$code" =~ ^[23] ]]; then
          echo "Aspire dashboard UI responding at ${url} (HTTP ${code})."
          return 0
        fi
      done
    fi
    sleep 0.5
  done
  echo "Aspire dashboard UI did not respond at http://localhost:18888" >&2
  if [[ -f "$LOG_FILE" ]]; then
    echo "Last log lines:" >&2
    tail -n 40 "$LOG_FILE" >&2 || true
  fi
  return 1
}

if [[ ! -x "$BIN" ]]; then
  if [[ -f "$BIN" ]]; then
    chmod +x "$BIN" 2>/dev/null || sudo chmod +x "$BIN"
  fi
fi
if [[ ! -x "$BIN" ]]; then
  echo "Aspire dashboard binary not found at ${BIN}. Run bash .cursor/install.sh first." >&2
  exit 1
fi

pid=""
if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
    pid=""
  fi
fi

if [[ -n "$pid" ]] || port_listening 18888 || port_listening 4317 || port_listening 4318; then
  echo "Aspire dashboard already listening; not starting another instance."
  wait_for_ui
  exit 0
fi

mkdir -p "$(dirname "$LOG_FILE")"
(
  cd "${ROOT}/tools"
  setsid nohup env \
    ASPNETCORE_URLS="http://localhost:18888" \
    ASPIRE_DASHBOARD_OTLP_ENDPOINT_URL="http://localhost:4317" \
    ASPIRE_DASHBOARD_OTLP_HTTP_ENDPOINT_URL="http://localhost:4318" \
    ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS="true" \
    "$BIN" >>"$LOG_FILE" 2>&1 < /dev/null &
  echo $! > "$PID_FILE"
)

if ! wait_for_ui; then
  exit 1
fi
echo "Aspire dashboard pid $(cat "$PID_FILE"), log ${LOG_FILE}"
