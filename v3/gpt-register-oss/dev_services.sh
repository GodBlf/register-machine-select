#!/usr/bin/env bash

set -u
set -o pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$PROJECT_ROOT/logs/dev-services"
PID_DIR="$RUNTIME_DIR/pids"

SERVICES=(backend frontend)
FG_PIDS=()
FG_NAMES=()
CLEANED_UP=0

mkdir -p "$PID_DIR"

usage() {
  cat <<'EOF'
用法:
  ./dev_services.sh fg       前台启动两个服务，按 Ctrl+C 一键关闭
  ./dev_services.sh bg       后台启动两个服务
  ./dev_services.sh stop     停止由本脚本后台启动的两个服务
  ./dev_services.sh restart  重启后台服务
  ./dev_services.sh status   查看后台服务状态

说明:
  - 后台模式日志目录: logs/dev-services/
  - 后台模式 PID 目录: logs/dev-services/pids/
EOF
}

service_title() {
  case "$1" in
    backend) printf '%s' "backend" ;;
    frontend) printf '%s' "frontend" ;;
    *) printf '%s' "$1" ;;
  esac
}

service_log_file() {
  printf '%s/%s.log' "$RUNTIME_DIR" "$1"
}

service_pid_file() {
  printf '%s/%s.pid' "$PID_DIR" "$1"
}

service_command() {
  local service="$1"
  local cmd=""

  case "$service" in
    backend)
      printf -v cmd 'cd %q && exec %q api_server.py' "$PROJECT_ROOT" "$PROJECT_ROOT/.venv/bin/python"
      ;;
    frontend)
      if [[ -x "$PROJECT_ROOT/frontend/node_modules/.bin/vite" ]]; then
        printf -v cmd 'cd %q && exec %q' "$PROJECT_ROOT/frontend" "$PROJECT_ROOT/frontend/node_modules/.bin/vite"
      else
        printf -v cmd 'cd %q && exec pnpm run dev' "$PROJECT_ROOT/frontend"
      fi
      ;;
    *)
      echo "未知服务: $service" >&2
      return 1
      ;;
  esac

  printf '%s' "$cmd"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "缺少命令: $1" >&2
    exit 1
  fi
}

check_dependencies() {
  require_command bash

  if [[ ! -x "$PROJECT_ROOT/.venv/bin/python" ]]; then
    echo "缺少 Python 解释器: $PROJECT_ROOT/.venv/bin/python" >&2
    exit 1
  fi

  if [[ ! -d "$PROJECT_ROOT/frontend" ]]; then
    echo "缺少前端目录: $PROJECT_ROOT/frontend" >&2
    exit 1
  fi

  if [[ ! -x "$PROJECT_ROOT/frontend/node_modules/.bin/vite" ]]; then
    require_command pnpm
  fi
}

is_pid_running() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

service_pid() {
  local pid_file
  pid_file="$(service_pid_file "$1")"
  [[ -f "$pid_file" ]] || return 1

  local pid
  pid="$(tr -d '[:space:]' <"$pid_file")"
  [[ -n "$pid" ]] || return 1
  printf '%s' "$pid"
}

service_running() {
  local pid
  pid="$(service_pid "$1")" || return 1
  is_pid_running "$pid"
}

clear_stale_pid() {
  local service="$1"
  local pid_file
  pid_file="$(service_pid_file "$service")"

  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi

  local pid
  pid="$(tr -d '[:space:]' <"$pid_file")"
  if ! is_pid_running "$pid"; then
    rm -f "$pid_file"
  fi
}

kill_pid_group() {
  local pid="$1"
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
}

force_kill_pid_group() {
  local pid="$1"
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

stop_service() {
  local service="$1"
  clear_stale_pid "$service"

  local pid
  pid="$(service_pid "$service")" || return 0

  if ! is_pid_running "$pid"; then
    rm -f "$(service_pid_file "$service")"
    return 0
  fi

  printf '停止 %-12s pid=%s\n' "$(service_title "$service")" "$pid"
  kill_pid_group "$pid"

  local i
  for i in $(seq 1 20); do
    if ! is_pid_running "$pid"; then
      rm -f "$(service_pid_file "$service")"
      return 0
    fi
    sleep 0.5
  done

  force_kill_pid_group "$pid"
  rm -f "$(service_pid_file "$service")"
}

ensure_no_managed_services_running() {
  local busy=0
  local service

  for service in "${SERVICES[@]}"; do
    clear_stale_pid "$service"
    if service_running "$service"; then
      local pid
      pid="$(service_pid "$service")"
      printf '%-12s 已在运行 pid=%s，请先执行 ./dev_services.sh stop\n' "$(service_title "$service")" "$pid" >&2
      busy=1
    fi
  done

  if (( busy != 0 )); then
    exit 1
  fi
}

start_service_background() {
  local service="$1"
  local cmd
  cmd="$(service_command "$service")"

  local log_file pid_file
  log_file="$(service_log_file "$service")"
  pid_file="$(service_pid_file "$service")"

  {
    printf '\n[%s] starting %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$(service_title "$service")"
    printf '[%s] command: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$cmd"
  } >>"$log_file"

  if command -v setsid >/dev/null 2>&1; then
    setsid bash -lc "$cmd" >>"$log_file" 2>&1 < /dev/null &
  else
    bash -lc "$cmd" >>"$log_file" 2>&1 < /dev/null &
  fi
  local pid=$!
  printf '%s\n' "$pid" >"$pid_file"

  sleep 1
  if is_pid_running "$pid"; then
    printf '启动 %-12s 成功 pid=%s log=%s\n' "$(service_title "$service")" "$pid" "$log_file"
    return 0
  fi

  echo "启动 $(service_title "$service") 失败，最近日志:" >&2
  tail -n 20 "$log_file" >&2 || true
  rm -f "$pid_file"
  return 1
}

start_background() {
  check_dependencies
  ensure_no_managed_services_running

  local started=()
  local service
  for service in "${SERVICES[@]}"; do
    if start_service_background "$service"; then
      started+=("$service")
    else
      local started_service
      for started_service in "${started[@]}"; do
        stop_service "$started_service"
      done
      exit 1
    fi
  done

  echo
  echo "后台服务已启动。"
  echo "停止命令: ./dev_services.sh stop"
  echo "状态命令: ./dev_services.sh status"
}

show_status() {
  local service
  for service in "${SERVICES[@]}"; do
    clear_stale_pid "$service"

    local title pid_file log_file
    title="$(service_title "$service")"
    pid_file="$(service_pid_file "$service")"
    log_file="$(service_log_file "$service")"

    if service_running "$service"; then
      local pid
      pid="$(service_pid "$service")"
      printf '%-12s running  pid=%-8s log=%s\n' "$title" "$pid" "$log_file"
    else
      printf '%-12s stopped  pid=%-8s log=%s\n' "$title" "-" "$log_file"
    fi
  done
}

stop_background() {
  local service
  for service in "${SERVICES[@]}"; do
    stop_service "$service"
  done
}

cleanup_foreground() {
  if (( CLEANED_UP != 0 )); then
    return 0
  fi
  CLEANED_UP=1

  if (( ${#FG_PIDS[@]} == 0 )); then
    return 0
  fi

  echo
  echo "正在关闭前台服务..."

  local pid
  for pid in "${FG_PIDS[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done

  sleep 1

  for pid in "${FG_PIDS[@]}"; do
    if is_pid_running "$pid"; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  done

  wait "${FG_PIDS[@]}" 2>/dev/null || true
}

on_foreground_interrupt() {
  echo
  echo "收到中断信号，准备关闭两个服务..."
  cleanup_foreground
  exit 130
}

start_service_foreground() {
  local service="$1"
  local cmd
  cmd="$(service_command "$service")"

  local log_file
  log_file="$(service_log_file "$service")"
  : >"$log_file"

  printf '启动 %-12s 前台模式\n' "$(service_title "$service")"
  bash -lc "$cmd" > >(tee -a "$log_file" | sed -u "s/^/[$(service_title "$service")] /") 2>&1 &
  FG_PIDS+=("$!")
  FG_NAMES+=("$service")
}

monitor_foreground() {
  while true; do
    local idx
    for idx in "${!FG_PIDS[@]}"; do
      local pid service
      pid="${FG_PIDS[$idx]}"
      service="${FG_NAMES[$idx]}"

      if ! is_pid_running "$pid"; then
        wait "$pid"
        local status=$?
        echo
        echo "$(service_title "$service") 已退出，退出码=$status，其余服务也会一并关闭。"
        return "$status"
      fi
    done
    sleep 1
  done
}

start_foreground() {
  check_dependencies
  ensure_no_managed_services_running

  trap on_foreground_interrupt INT TERM
  trap cleanup_foreground EXIT

  local service
  for service in "${SERVICES[@]}"; do
    start_service_foreground "$service"
  done

  echo
  echo "两个服务已进入前台托管模式。按 Ctrl+C 可一键关闭。"
  monitor_foreground
}

main() {
  local action="${1:-}"

  case "$action" in
    fg)
      start_foreground
      ;;
    bg)
      start_background
      ;;
    stop)
      stop_background
      ;;
    restart)
      stop_background
      start_background
      ;;
    status)
      show_status
      ;;
    -h|--help|help|"")
      usage
      ;;
    *)
      echo "未知命令: $action" >&2
      echo >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
