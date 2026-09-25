#!/usr/bin/env bash
# Ceky Resolver — tüm platformlar için sürüm paketleri üretir (dist/)
# Kullanım: scripts/build-release.sh 5.0.0
set -euo pipefail

VERSION="${1:-dev}"
cd "$(dirname "$0")/.."
rm -rf dist
mkdir -p dist

TARGETS="windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/armv7"

for target in $TARGETS; do
  os="${target%/*}"
  arch="${target#*/}"
  goarch="$arch"
  goarm=""
  if [ "$arch" = "armv7" ]; then goarch="arm"; goarm="7"; fi

  name="ceky-resolver-$os-$arch"
  work="dist/$name"
  bin="ceky-resolver"
  [ "$os" = "windows" ] && bin="ceky-resolver.exe"
  mkdir -p "$work"

  echo "→ $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$goarch" GOARM="$goarm" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$work/$bin" .
  cp README.md LICENSE "$work/"

  if [ "$os" = "windows" ]; then
    cp packaging/windows/*.cmd "$work/"
    (cd "$work" && zip -q -r "../$name.zip" .)
  else
    tar -czf "dist/$name.tar.gz" -C "$work" .
  fi
  rm -rf "$work"
done

(cd dist && sha256sum * > SHA256SUMS.txt)
echo "✓ Paketler hazır:"
ls -lh dist
