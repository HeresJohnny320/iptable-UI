#!/bin/sh
# Installs the latest iptable-ui release as /usr/local/bin/iptable-ui,
# already executable, so it can be started with "iptable-ui".
#
#   curl -fsSL https://raw.githubusercontent.com/HeresJohnny320/iptable-UI/main/install.sh | sh
#
# Run as a normal user, it asks sudo (or doas) only for the final copy.
set -eu

REPO="HeresJohnny320/iptable-UI"
TARGET="${IPTABLE_UI_TARGET:-/usr/local/bin/iptable-ui}"

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

[ "$(uname -s)" = "Linux" ] || fail "iptable-ui runs on Linux only."
if [ "$(id -u)" -eq 0 ]; then
  AS_ROOT=""
elif command -v sudo >/dev/null 2>&1; then
  AS_ROOT="sudo"
elif command -v doas >/dev/null 2>&1; then
  AS_ROOT="doas"
else
  fail "installing to $TARGET needs root, and neither sudo nor doas is installed; run this script as root."
fi

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) fail "unsupported CPU architecture $(uname -m); only amd64 and arm64 builds are published." ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1"; }
  download() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO- "$1"; }
  download() { wget -qO "$2" "$1"; }
else
  fail "curl or wget is required."
fi

# Releases are listed newest first; take the newest one with a build for this CPU.
URL="$(fetch "https://api.github.com/repos/$REPO/releases?per_page=20" |
  grep -o "\"browser_download_url\": *\"[^\"]*/iptable-ui-linux-$ARCH\"" |
  head -n 1 | sed 's/.*"\(https[^"]*\)"/\1/')" || true
[ -n "$URL" ] || fail "no iptable-ui-linux-$ARCH build found at https://github.com/$REPO/releases"

TEMP="$(mktemp)"
trap 'rm -f "$TEMP"' EXIT
echo "Downloading $URL"
download "$URL" "$TEMP"
chmod 0755 "$TEMP"
# 126/127 mean the file cannot run here (wrong CPU or a broken download).
status=0
"$TEMP" --help >/dev/null 2>&1 || status=$?
[ "$status" -ne 126 ] && [ "$status" -ne 127 ] || fail "the downloaded file does not run on this system."
[ -z "$AS_ROOT" ] || echo "Installing to $TARGET needs root; asking $AS_ROOT."
$AS_ROOT mkdir -p "$(dirname "$TARGET")"
$AS_ROOT install -m 0755 "$TEMP" "$TARGET"

echo "Installed $TARGET"
echo "Start it with: iptable-ui   (it asks for sudo when it needs root)"
