#!/usr/bin/env bash
# Run full Linux pktana (web.rs + capture + DPI/DLP/IDPS) in Docker.
# Intended for macOS Docker Desktop — same idea as a Linux appliance next to
# the Electron Packet Tracer desktop app.
#
# Usage:
#   ./docker_mac.sh start [PORT]
#   ./docker_mac.sh stop
#   ./docker_mac.sh restart [PORT]
#   ./docker_mac.sh status
#   ./docker_mac.sh logs
#   ./docker_mac.sh shell
#   ./docker_mac.sh build
#   ./docker_mac.sh pull-or-build
#
# Open on the Mac:  http://127.0.0.1:8080
#
# Limits (honest):
#   - You get *full Linux pktana features inside the container*.
#   - Docker Desktop on Mac cannot attach to the Mac's physical Wi‑Fi/Ethernet
#     the same way bare-metal Linux can. Capture sees the container network
#     (and traffic that passes through it). For host NIC capture, run pktana
#     on a Linux VM/host, or use this container for UI + PCAP analysis.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

IMAGE_NAME="${PKTANA_IMAGE:-pktana-web:0.6.0}"
CONTAINER_NAME="${PKTANA_CONTAINER:-pktana-web}"
DEFAULT_PORT="${PKTANA_PORT:-8080}"
PLATFORM="${PKTANA_PLATFORM:-linux/amd64}"
VERSION="${PKTANA_VERSION:-0.6.0}"

have_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "Docker is required. On Mac: install Docker Desktop, then re-run."
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    echo "Docker daemon is not running. Start Docker Desktop and retry."
    exit 1
  }
}

image_exists() {
  docker image inspect "$IMAGE_NAME" >/dev/null 2>&1
}

container_running() {
  docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"
}

container_exists() {
  docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"
}

cmd_build() {
  have_docker
  echo "Building ${IMAGE_NAME} (platform ${PLATFORM})..."
  docker build \
    --platform "$PLATFORM" \
    --build-arg "PKTANA_VERSION=${VERSION}" \
    -f Dockerfile.web \
    -t "$IMAGE_NAME" \
    .
  echo "Built ${IMAGE_NAME}"
}

cmd_pull_or_build() {
  if image_exists; then
    echo "Image ${IMAGE_NAME} already present."
  else
    cmd_build
  fi
}

cmd_start() {
  have_docker
  local port="${1:-$DEFAULT_PORT}"

  if container_running; then
    echo "Already running: ${CONTAINER_NAME}"
    echo "Open http://127.0.0.1:${port}"
    exit 0
  fi

  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi

  cmd_pull_or_build

  echo "Starting ${CONTAINER_NAME} on port ${port}..."
  # NET_RAW / NET_ADMIN: packet capture + iface introspection inside the Linux netns.
  # --privileged: needed for some ethtool/dataplane probes under Docker Desktop.
  docker run -d \
    --name "$CONTAINER_NAME" \
    --platform "$PLATFORM" \
    --restart unless-stopped \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --privileged \
    -e "PKTANA_WEB_PORT=${port}" \
    -p "${port}:8080" \
    -v "${ROOT}/pcaps:/pcaps:rw" \
    "$IMAGE_NAME" \
    sh -c "exec pktana web 8080 -f" >/dev/null

  # Brief health wait
  sleep 1
  if container_running; then
    echo ""
    echo "pktana web is up (Linux container, full feature set)."
    echo "  UI:     http://127.0.0.1:${port}"
    echo "  PCAPs:  mount ./pcaps -> /pcaps inside container"
    echo "  Logs:   ./docker_mac.sh logs"
    echo "  Stop:   ./docker_mac.sh stop"
    echo ""
    echo "Note: capture is inside the container network, not the Mac Wi‑Fi NIC."
  else
    echo "Container failed to start. Try: ./docker_mac.sh logs"
    exit 1
  fi
}

cmd_stop() {
  have_docker
  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    echo "Stopped ${CONTAINER_NAME}"
  else
    echo "Not running."
  fi
}

cmd_restart() {
  local port="${1:-$DEFAULT_PORT}"
  cmd_stop
  cmd_start "$port"
}

cmd_status() {
  have_docker
  echo "Image:     ${IMAGE_NAME}"
  echo "Container: ${CONTAINER_NAME}"
  if container_running; then
    docker ps --filter "name=^${CONTAINER_NAME}$" \
      --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  elif container_exists; then
    echo "Status: stopped"
  else
    echo "Status: not created"
  fi
}

cmd_logs() {
  have_docker
  docker logs -f --tail 200 "$CONTAINER_NAME"
}

cmd_shell() {
  have_docker
  docker exec -it "$CONTAINER_NAME" bash || docker exec -it "$CONTAINER_NAME" sh
}

usage() {
  cat <<EOF
pktana macOS / Docker runner — full Linux pktana via container

Commands:
  start [PORT]   Build (if needed) and run web UI (default port ${DEFAULT_PORT})
  stop           Stop and remove the container
  restart [PORT] Restart
  status         Show container status
  logs           Follow container logs
  shell          Shell into the running container
  build          Rebuild ${IMAGE_NAME} from Dockerfile.web

Env overrides:
  PKTANA_VERSION   (${VERSION})
  PKTANA_IMAGE     (${IMAGE_NAME})
  PKTANA_CONTAINER (${CONTAINER_NAME})
  PKTANA_PORT      (${DEFAULT_PORT})
  PKTANA_PLATFORM  (${PLATFORM})

Example (Mac):
  ./docker_mac.sh start 8080
  open http://127.0.0.1:8080
EOF
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    start)   cmd_start "${1:-}" ;;
    stop)    cmd_stop ;;
    restart) cmd_restart "${1:-}" ;;
    status)  cmd_status ;;
    logs)    cmd_logs ;;
    shell)   cmd_shell ;;
    build)   cmd_build ;;
    pull-or-build) cmd_pull_or_build ;;
    -h|--help|help|"") usage ;;
    *)
      echo "Unknown command: $cmd"
      usage
      exit 1
      ;;
  esac
}

main "$@"
