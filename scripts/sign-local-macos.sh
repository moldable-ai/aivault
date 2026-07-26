#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  exit 0
fi

find_signing_identity() {
  local configured_identity="${AIVAULT_MACOS_SIGNING_IDENTITY:-${MOLDABLE_MACOS_SIGNING_IDENTITY:-${APPLE_SIGNING_IDENTITY:-}}}"
  if [[ -n "$configured_identity" ]]; then
    printf '%s\n' "$configured_identity"
    return
  fi

  local identities
  identities="$(/usr/bin/security find-identity -v -p codesigning 2>/dev/null || true)"

  local identity
  identity="$(
    printf '%s\n' "$identities" |
      /usr/bin/awk '/"Developer ID Application:/ { print $2; exit }'
  )"
  if [[ -z "$identity" ]]; then
    identity="$(
      printf '%s\n' "$identities" |
        /usr/bin/awk '/"Apple Development:/ { print $2; exit }'
    )"
  fi

  printf '%s\n' "$identity"
}

SIGNING_IDENTITY="$(find_signing_identity)"
if [[ -z "$SIGNING_IDENTITY" ]]; then
  echo "No macOS code-signing identity is available; local aivault artifacts remain unsigned." >&2
  exit 0
fi

BINARIES=(
  "$ROOT/target/release/aivault"
  "$ROOT/target/release/aivaultd"
  "$ROOT/providers/postgres/target/release/aivault-provider-postgres"
)

SIGNED_COUNT=0
for binary in "${BINARIES[@]}"; do
  if [[ ! -x "$binary" ]]; then
    continue
  fi

  /usr/bin/codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "$SIGNING_IDENTITY" \
    "$binary"
  /usr/bin/codesign --verify --strict "$binary"
  SIGNED_COUNT=$((SIGNED_COUNT + 1))
done

if [[ "$SIGNED_COUNT" -eq 0 ]]; then
  echo "No release aivault artifacts were available to sign." >&2
  exit 1
fi

echo "Signed $SIGNED_COUNT local macOS aivault artifact(s)."
