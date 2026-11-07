#!/usr/bin/env bash
# 在 CI / 本机构建 release 目录与 tar.gz
# 用法: ./utils/pack-release.sh [version] [GOARCH]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="${1:-$(tr -d '[:space:]' <"$ROOT/VERSION")}"
VER="${VER#v}"
GOARCH="${2:-amd64}"
GOOS=linux
OUT_NAME="nftforward-v${VER}-linux-${GOARCH}"
OUT_DIR="$ROOT/dist/$OUT_NAME"
BACKEND="$ROOT/project/backend"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{bin,lib,web,utils} "$ROOT/dist"

echo "版本 $VER · ${GOOS}/${GOARCH}"
echo "$VER" >"$OUT_DIR/VERSION"

echo "编译面板…"
(
  cd "$BACKEND"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -ldflags "-s -w -X github.com/gzjacktang/nftforward/internal/version.Version=${VER} -X github.com/gzjacktang/nftforward/internal/version.EngineVersion=${VER}" \
    -o "$OUT_DIR/bin/nft-panel" ./cmd/panel
)

echo "拉取 realm…"
chmod +x "$ROOT/utils/fetch-realm.sh"
"$ROOT/utils/fetch-realm.sh" "$GOARCH" "$OUT_DIR/lib/realm"

install -m 0755 "$ROOT/utils/nftfp" "$OUT_DIR/bin/nftfp"
install -m 0644 "$ROOT/project/frontend/"* "$OUT_DIR/web/"
install -m 0755 "$ROOT/utils/install-release.sh" "$OUT_DIR/utils/install-release.sh"
install -m 0755 "$ROOT/utils/issue-cert.sh" "$OUT_DIR/utils/issue-cert.sh"
install -m 0755 "$ROOT/utils/auto-update.sh" "$OUT_DIR/utils/auto-update.sh"
install -m 0755 "$ROOT/utils/do-update.sh" "$OUT_DIR/utils/do-update.sh"
install -m 0755 "$ROOT/utils/fetch-realm.sh" "$OUT_DIR/utils/fetch-realm.sh"
install -m 0644 "$ROOT/utils/nftfp.service" "$OUT_DIR/utils/nftfp.service"

(
  cd "$ROOT/dist"
  tar -czf "${OUT_NAME}.tar.gz" "$OUT_NAME"
)
echo "产物: $ROOT/dist/${OUT_NAME}.tar.gz"
ls -lh "$ROOT/dist/${OUT_NAME}.tar.gz"
