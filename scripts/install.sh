#!/bin/sh
# Ceky Resolver — macOS / Linux tek satır kurulum:
#   curl -fsSL https://raw.githubusercontent.com/cekYc/ceky-resolver/main/scripts/install.sh | sh
# Son sürümü indirir ve kalıcı olarak kurar (açılışta arka planda başlar).
set -e

REPO="cekYc/ceky-resolver"

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) echo "✗ Desteklenmeyen işletim sistemi: $(uname -s)"; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  armv7l | armv6l) ARCH=armv7 ;;
  *) echo "✗ Desteklenmeyen işlemci: $(uname -m)"; exit 1 ;;
esac

URL="https://github.com/$REPO/releases/latest/download/ceky-resolver-$OS-$ARCH.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "↓ İndiriliyor: $URL"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TMP/ceky.tar.gz"
else
  wget -qO "$TMP/ceky.tar.gz" "$URL"
fi
tar -xzf "$TMP/ceky.tar.gz" -C "$TMP"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
  echo "🔑 Kurulum için yönetici parolanız istenecek."
fi
# Betik "curl | sh" ile çalıştığında stdin borudur; sudo parolayı terminalden sorsun
if [ -n "$SUDO" ] && [ -r /dev/tty ]; then
  $SUDO "$TMP/ceky-resolver" install < /dev/tty
else
  $SUDO "$TMP/ceky-resolver" install
fi
