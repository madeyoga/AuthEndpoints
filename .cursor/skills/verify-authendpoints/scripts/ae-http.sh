#!/usr/bin/env bash
# HTTP harness for the AuthEndpoints in-repo test host.
# Invoke from the repository root. See ../SKILL.md.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ae-http.sh <command> [args]

Commands:
  launch              Build and start the test host. Writes pid/url under AE_RUN_DIR.
  doctor              Read-only health check (process, port, GET /identity/csrfToken).
  stop                Stop the host started by launch (PID file only). Does not delete evidence.
  csrf [path]         Print csrfToken JSON field (default /identity/csrfToken).
  get <path>          GET a path. Writes status/headers/body under AE_EVIDENCE_DIR when --out is set.
  post <path> [json]  POST JSON. Add --csrf to send RequestVerificationToken. Optional --out NAME.

Environment:
  AE_RUN_ID         Unique id for this run (default: timestamp-pid)
  AE_PORT          Listen port (default: 5088)
  AE_BASE_URL      Base URL (default: http://127.0.0.1:$AE_PORT)
  AE_RUN_DIR       Scratch dir for pid/log/cookie jar (default: /tmp/authendpoints-verify-$AE_RUN_ID)
  AE_EVIDENCE_DIR  Proof output dir; never deleted by stop (default: $AE_RUN_DIR/evidence)
  AE_COOKIE_JAR    curl cookie jar (default: $AE_RUN_DIR/cookies.txt)
  AE_REPO_ROOT     Repository root (default: git root or cwd)
  AE_HOST_MODE     Test host mapping: compose (default) or bearer-facade

Examples:
  AE_RUN_ID=demo ./ae-http.sh launch
  ./ae-http.sh doctor
  ./ae-http.sh post /identity/register '{"email":"a@test.local","password":"Passw0rd!"}' --out register
  ./ae-http.sh post /identity/login '{"email":"a@test.local","password":"Passw0rd!"}' --out login
  ./ae-http.sh get /identity/manage/info --out info
  ./ae-http.sh post --csrf /identity/logout --out logout
  ./ae-http.sh stop
EOF
}

json_get() {
  python3 -c '
import json, sys
key_camel, key_pascal = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
if not raw.strip():
    sys.exit(2)
doc = json.loads(raw)
if isinstance(doc, dict):
    val = doc.get(key_camel)
    if val is None:
        val = doc.get(key_pascal)
    if val is None:
        sys.exit(3)
    print(val)
else:
    sys.exit(2)
' "$1" "$2"
}

retry_sleep() {
  local attempt="$1"
  python3 -c "print(min(2 ** ${attempt}, 16))"
}

http() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local csrf="${4:-}"
  local out_name="${5:-}"
  local url="${AE_BASE_URL}${path}"
  local tmp
  tmp="$(mktemp)"
  local args=(
    -sS
    -D "${tmp}.headers"
    -o "${tmp}.body"
    -w "%{http_code}"
    -X "$method"
    -b "$AE_COOKIE_JAR"
    -c "$AE_COOKIE_JAR"
    "$url"
  )
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: application/json" --data "$body")
  fi
  if [[ -n "$csrf" ]]; then
    args+=(-H "RequestVerificationToken: $csrf")
  fi
  if [[ -n "${AE_BEARER:-}" ]]; then
    args+=(-H "Authorization: Bearer $AE_BEARER")
  fi
  if [[ -n "${AE_REAUTH:-}" ]]; then
    args+=(-H "X-AuthEndpoints-Reauth: $AE_REAUTH")
  fi

  local attempt status
  for attempt in 0 1 2 3 4 5; do
    status="$(curl "${args[@]}")"
    if [[ "$status" != "429" ]]; then
      break
    fi
    sleep "$(retry_sleep "$attempt")"
  done

  if [[ -n "$out_name" ]]; then
    mkdir -p "$AE_EVIDENCE_DIR"
    printf '%s\n' "$status" > "${AE_EVIDENCE_DIR}/${out_name}.status"
    cp "${tmp}.headers" "${AE_EVIDENCE_DIR}/${out_name}.headers"
    cp "${tmp}.body" "${AE_EVIDENCE_DIR}/${out_name}.body"
    {
      echo "METHOD $method"
      echo "URL $url"
      if [[ -n "$body" ]]; then
        echo "BODY $body"
      fi
    } > "${AE_EVIDENCE_DIR}/${out_name}.request"
  fi

  AE_LAST_STATUS="$status"
  AE_LAST_BODY="$(cat "${tmp}.body")"
  AE_LAST_HEADERS="$(cat "${tmp}.headers")"
  rm -f "${tmp}.headers" "${tmp}.body" "$tmp"
  printf '%s' "$AE_LAST_BODY"
  echo
  echo "HTTP $status" >&2
  if [[ "$status" == "429" ]]; then
    echo "Rate limited after retries. Wait and retry the whole drive." >&2
    return 1
  fi
}

parse_common() {
  local -a rest=()
  AE_USE_CSRF=0
  AE_OUT=""
  AE_PATH=""
  AE_JSON=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --csrf) AE_USE_CSRF=1; shift ;;
      --out) AE_OUT="$2"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      --) shift; rest+=("$@"); break ;;
      *) rest+=("$1"); shift ;;
    esac
  done
  if [[ ${#rest[@]} -ge 1 ]]; then
    AE_PATH="${rest[0]}"
  fi
  if [[ ${#rest[@]} -ge 2 ]]; then
    AE_JSON="${rest[1]}"
  fi
}

resolve_paths() {
  if [[ -z "${AE_REPO_ROOT:-}" ]]; then
    if git rev-parse --show-toplevel >/dev/null 2>&1; then
      AE_REPO_ROOT="$(git rev-parse --show-toplevel)"
    else
      AE_REPO_ROOT="$(pwd)"
    fi
  fi
  AE_RUN_ID="${AE_RUN_ID:-$(date +%Y%m%dT%H%M%S)-$$}"
  AE_PORT="${AE_PORT:-5088}"
  AE_BASE_URL="${AE_BASE_URL:-http://127.0.0.1:${AE_PORT}}"
  AE_RUN_DIR="${AE_RUN_DIR:-/tmp/authendpoints-verify-${AE_RUN_ID}}"
  AE_EVIDENCE_DIR="${AE_EVIDENCE_DIR:-${AE_RUN_DIR}/evidence}"
  AE_COOKIE_JAR="${AE_COOKIE_JAR:-${AE_RUN_DIR}/cookies.txt}"
  AE_HOST_MODE="${AE_HOST_MODE:-compose}"
  AE_PID_FILE="${AE_RUN_DIR}/host.pid"
  AE_LOG_FILE="${AE_RUN_DIR}/host.log"
  AE_URL_FILE="${AE_RUN_DIR}/base.url"
  AE_PROJECT="${AE_REPO_ROOT}/tests/AuthEndpoints.Tests/AuthEndpoints.Tests.csproj"
  AE_DLL="${AE_REPO_ROOT}/tests/AuthEndpoints.Tests/bin/Debug/net10.0/AuthEndpoints.Tests.dll"
}

port_in_use() {
  python3 - "$AE_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(0.3)
try:
    s.connect(("127.0.0.1", port))
except OSError:
    sys.exit(1)
else:
    s.close()
    sys.exit(0)
PY
}

wait_ready() {
  local i status
  local ready_path="/identity/csrfToken"
  local ready_code="200"
  if [[ "$AE_HOST_MODE" == "bearer-facade" ]]; then
    ready_path="/identity/manage/info"
    ready_code="401"
  fi
  for i in $(seq 1 60); do
    status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 1 "${AE_BASE_URL}${ready_path}" 2>/dev/null || true)"
    if [[ "$status" == "$ready_code" ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "Host did not become ready at ${AE_BASE_URL}${ready_path} (want HTTP ${ready_code})" >&2
  echo "Last log lines:" >&2
  tail -n 40 "$AE_LOG_FILE" >&2 || true
  return 1
}

cmd_launch() {
  mkdir -p "$AE_RUN_DIR"
  mkdir -p "$AE_EVIDENCE_DIR"
  : > "$AE_COOKIE_JAR"

  if ! command -v dotnet >/dev/null 2>&1; then
    echo "dotnet is not on PATH. Install the .NET 10 SDK and retry." >&2
    exit 1
  fi
  local ver
  ver="$(dotnet --version)"
  if [[ "$ver" != 10.* ]]; then
    echo "Need .NET 10 SDK; got ${ver}" >&2
    exit 1
  fi
  if [[ ! -f "$AE_PROJECT" ]]; then
    echo "Missing test project at $AE_PROJECT" >&2
    exit 1
  fi
  if port_in_use; then
    echo "Port ${AE_PORT} is already answering. Pick another AE_PORT; do not drive a shared instance." >&2
    exit 1
  fi

  echo "Building $AE_PROJECT" >&2
  dotnet build "$AE_PROJECT" -c Debug -v q
  if [[ ! -f "$AE_DLL" ]]; then
    echo "Build succeeded but $AE_DLL is missing." >&2
    exit 1
  fi

  echo "Starting host on ${AE_BASE_URL}" >&2
  (
    cd "$(dirname "$AE_DLL")"
    exec env \
      ASPNETCORE_ENVIRONMENT=Development \
      ASPNETCORE_URLS="$AE_BASE_URL" \
      ASPNETCORE_HTTP_PORTS="" \
      ASPNETCORE_HTTPS_PORTS="" \
      TestDbName="AuthEndpointsVerify_${AE_RUN_ID}" \
      DOTNET_ENVIRONMENT=Development \
      AE_HOST_MODE="$AE_HOST_MODE" \
      dotnet "$AE_DLL"
  ) >"$AE_LOG_FILE" 2>&1 &
  echo $! > "$AE_PID_FILE"
  echo "$AE_BASE_URL" > "$AE_URL_FILE"
  echo "$AE_HOST_MODE" > "$AE_RUN_DIR/host.mode"
  if ! wait_ready; then
    cmd_stop || true
    exit 1
  fi
  echo "Ready at ${AE_BASE_URL} (pid $(cat "$AE_PID_FILE"))" >&2
  echo "$AE_BASE_URL"
}

cmd_doctor() {
  if [[ ! -f "$AE_PID_FILE" ]]; then
    echo "No pid file at $AE_PID_FILE — this run did not start a host." >&2
    exit 1
  fi
  if [[ -f "$AE_RUN_DIR/host.mode" ]]; then
    AE_HOST_MODE="$(cat "$AE_RUN_DIR/host.mode")"
  fi
  local pid
  pid="$(cat "$AE_PID_FILE")"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "Pid $pid is not running. Host is down." >&2
    exit 1
  fi
  if ! port_in_use; then
    echo "Pid $pid is running but ${AE_BASE_URL} is not accepting connections." >&2
    exit 1
  fi
  local body status
  if [[ "$AE_HOST_MODE" == "bearer-facade" ]]; then
    status="$(curl -sS -o "${AE_RUN_DIR}/doctor.body" -w "%{http_code}" "${AE_BASE_URL}/identity/manage/info")"
    if [[ "$status" != "401" ]]; then
      echo "GET /identity/manage/info returned HTTP $status (want 401 for bearer-facade)." >&2
      cat "${AE_RUN_DIR}/doctor.body" >&2 || true
      exit 1
    fi
    echo "ok pid=$pid url=${AE_BASE_URL} mode=bearer-facade manage/info=401"
    return 0
  fi
  status="$(curl -sS -o "${AE_RUN_DIR}/doctor.body" -w "%{http_code}" "${AE_BASE_URL}/identity/csrfToken")"
  if [[ "$status" != "200" ]]; then
    echo "GET /identity/csrfToken returned HTTP $status (want 200)." >&2
    cat "${AE_RUN_DIR}/doctor.body" >&2 || true
    exit 1
  fi
  json_get csrfToken CsrfToken < "${AE_RUN_DIR}/doctor.body" >/dev/null
  echo "ok pid=$pid url=${AE_BASE_URL} csrfToken=present"
}

cmd_stop() {
  if [[ ! -f "$AE_PID_FILE" ]]; then
    echo "No pid file; nothing to stop." >&2
    return 0
  fi
  local pid
  pid="$(cat "$AE_PID_FILE")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    local i
    for i in $(seq 1 20); do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.25
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" || true
    fi
  fi
  rm -f "$AE_PID_FILE"
  echo "Stopped pid $pid. Evidence kept at ${AE_EVIDENCE_DIR}" >&2
}

cmd_csrf() {
  local path="${1:-/identity/csrfToken}"
  http GET "$path" "" "" "" >/dev/null
  printf '%s' "$AE_LAST_BODY" | json_get csrfToken CsrfToken
  echo
}

cmd_get() {
  parse_common "$@"
  if [[ -z "$AE_PATH" ]]; then
    echo "get requires a path" >&2
    exit 1
  fi
  http GET "$AE_PATH" "" "" "$AE_OUT"
}

cmd_post() {
  parse_common "$@"
  if [[ -z "$AE_PATH" ]]; then
    echo "post requires a path" >&2
    exit 1
  fi
  local csrf=""
  if [[ "$AE_USE_CSRF" == "1" ]]; then
    local csrf_path="/identity/csrfToken"
    case "$AE_PATH" in
      /auth/*) csrf_path="/auth/csrfToken" ;;
    esac
    csrf="$(AE_OUT="" http GET "$csrf_path" "" "" "" >/dev/null; printf '%s' "$AE_LAST_BODY" | json_get csrfToken CsrfToken)"
  fi
  http POST "$AE_PATH" "$AE_JSON" "$csrf" "$AE_OUT"
}

resolve_paths
cmd="${1:-}"
if [[ -n "$cmd" ]]; then
  shift
fi
case "$cmd" in
  launch) cmd_launch "$@" ;;
  doctor) cmd_doctor "$@" ;;
  stop) cmd_stop "$@" ;;
  csrf) cmd_csrf "$@" ;;
  get) cmd_get "$@" ;;
  post) cmd_post "$@" ;;
  -h|--help|help|"") usage ;;
  *) echo "Unknown command: $cmd" >&2; usage; exit 1 ;;
esac
