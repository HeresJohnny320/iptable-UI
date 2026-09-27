#!/usr/bin/env sh
set -eu

ARCH="${1:-amd64}"
case "$ARCH" in
  amd64|arm64) ;;
  *) echo "Usage: $0 [amd64|arm64]" >&2; exit 2 ;;
esac

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUTPUT="$ROOT/dist/iptable-ui-linux-$ARCH"

mkdir -p "$ROOT/dist"
cd "$ROOT"
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$OUTPUT" ./cmd/iptable-ui
chmod 755 "$OUTPUT"
printf 'Built %s\n' "$OUTPUT"