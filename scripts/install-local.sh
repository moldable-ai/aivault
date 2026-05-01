#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_INSTALL_DIR="$HOME/.local/bin"
if command -v aivault >/dev/null 2>&1; then
  DEFAULT_INSTALL_DIR="$(dirname "$(command -v aivault)")"
fi

INSTALL_DIR="${AIVAULT_LOCAL_BIN_DIR:-$DEFAULT_INSTALL_DIR}"
INSTALL_POSTGRES=1
INSTALL_MOLDABLE=1
MOLDABLE_REPO_DIR="${MOLDABLE_REPO_DIR:-$HOME/moldable}"
RESTART_SHARED=1
SMOKE_TEST=1

usage() {
  cat <<'EOF'
Usage: scripts/install-local.sh [options]

Build and install local release aivault binaries, install bundled providers, and restart daemons.

Options:
  --install-dir <dir>   Directory for aivault/aivaultd symlinks (default: current aivault PATH dir, or ~/.local/bin)
  --no-postgres         Skip building/installing the Postgres provider
  --no-moldable         Skip refreshing bundled aivault binaries in a local Moldable checkout
  --no-shared           Do not restart the shared LaunchAgent/manual shared daemon
  --no-smoke            Skip final status/provider checks
  -h, --help            Show this help

Environment:
  AIVAULT_LOCAL_BIN_DIR  Same as --install-dir
  MOLDABLE_REPO_DIR      Local Moldable checkout to refresh (default: ~/moldable)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --)
      shift
      ;;
    --install-dir)
      if [[ $# -lt 2 ]]; then
        echo "--install-dir requires a value" >&2
        exit 2
      fi
      INSTALL_DIR="$2"
      shift 2
      ;;
    --no-postgres)
      INSTALL_POSTGRES=0
      shift
      ;;
    --no-moldable)
      INSTALL_MOLDABLE=0
      shift
      ;;
    --no-shared)
      RESTART_SHARED=0
      shift
      ;;
    --no-smoke)
      SMOKE_TEST=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

AIVAULT_BIN="$ROOT/target/release/aivault"
AIVAULTD_BIN="$ROOT/target/release/aivaultd"
POSTGRES_PROVIDER_BIN="$ROOT/providers/postgres/target/release/aivault-provider-postgres"

log() {
  printf '\n==> %s\n' "$*"
}

install_moldable_runtime_dir() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    return
  fi

  if [[ ! -f "$dir/aivault" && ! -f "$dir/aivaultd" ]]; then
    return
  fi

  install -m 755 "$AIVAULT_BIN" "$dir/aivault"
  install -m 755 "$AIVAULTD_BIN" "$dir/aivaultd"

  if [[ "$INSTALL_POSTGRES" -eq 1 && -x "$POSTGRES_PROVIDER_BIN" && -d "$dir/providers/postgres" ]]; then
    install -m 755 "$POSTGRES_PROVIDER_BIN" "$dir/providers/postgres/aivault-provider-postgres"
  fi
}

install_moldable_runtime() {
  if [[ "$INSTALL_MOLDABLE" -ne 1 ]]; then
    return
  fi

  if [[ ! -d "$MOLDABLE_REPO_DIR/desktop/src-tauri" ]]; then
    return
  fi

  log "Refreshing bundled aivault runtime in $MOLDABLE_REPO_DIR"
  install_moldable_runtime_dir "$MOLDABLE_REPO_DIR/desktop/src-tauri/resources/aivault"
  install_moldable_runtime_dir "$MOLDABLE_REPO_DIR/desktop/src-tauri/target/debug/aivault"
  install_moldable_runtime_dir "$MOLDABLE_REPO_DIR/desktop/src-tauri/target/release/aivault"
}

log "Building release aivault binaries"
cargo build --release --all-targets

if [[ "$INSTALL_POSTGRES" -eq 1 ]]; then
  log "Building release Postgres provider"
  cargo build --manifest-path "$ROOT/providers/postgres/Cargo.toml" --release
fi

log "Installing symlinks into $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
ln -sf "$AIVAULT_BIN" "$INSTALL_DIR/aivault"
ln -sf "$AIVAULTD_BIN" "$INSTALL_DIR/aivaultd"

if [[ "$INSTALL_POSTGRES" -eq 1 ]]; then
  log "Installing and enabling Postgres provider"
  "$INSTALL_DIR/aivault" provider install postgres --enable --from "$POSTGRES_PROVIDER_BIN" >/dev/null
fi

install_moldable_runtime

log "Restarting per-user aivaultd"
"$INSTALL_DIR/aivault" restart >/dev/null

if [[ "$RESTART_SHARED" -eq 1 && "$(uname -s)" == "Darwin" ]]; then
  SHARED_SERVICE="gui/$(id -u)/com.aivault.aivaultd.shared"
  if launchctl print "$SHARED_SERVICE" >/dev/null 2>&1; then
    log "Restarting shared LaunchAgent aivaultd"
    launchctl kickstart -k "$SHARED_SERVICE"
  elif pgrep -f "aivaultd --shared" >/dev/null 2>&1; then
    log "Replacing manually running shared aivaultd"
    pkill -f "aivaultd --shared" >/dev/null 2>&1 || true
    sleep 0.3
    mkdir -p "$HOME/.aivault/logs"
    nohup "$INSTALL_DIR/aivaultd" --shared >>"$HOME/.aivault/logs/aivaultd.log" 2>>"$HOME/.aivault/logs/aivaultd.err.log" &
  fi
fi

if [[ "$SMOKE_TEST" -eq 1 ]]; then
  log "Smoke testing installed aivault"
  "$INSTALL_DIR/aivault" status
  if [[ "$INSTALL_POSTGRES" -eq 1 ]]; then
    "$INSTALL_DIR/aivault" provider list -v | sed -n '/"id": "postgres"/,/"version"/p'
  fi
fi

log "Local install complete"
printf 'aivault:  %s\n' "$INSTALL_DIR/aivault"
printf 'aivaultd: %s\n' "$INSTALL_DIR/aivaultd"
