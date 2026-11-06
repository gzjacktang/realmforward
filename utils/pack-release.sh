#!/usr/bin/env bash
# 在 CI / 本机构建 release 目录与 tar.gz
# 用法: ./utils/pack-release.sh [version] [GOARCH]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="${1:-$(tr -d '[:space:]' <"$ROOT/VERSION")}"
VER="${VER#v}"
GOARCH="${2:-amd64}"
GOOS=linux
OUT_NAME="xdpforward-v${VER}-linux-${GOARCH}"
OUT_DIR="$ROOT/dist/$OUT_NAME"
BACKEND="$ROOT/project/backend"

case "$GOARCH" in
  amd64) BPF_ARCH=x86 ;;
  arm64) BPF_ARCH=arm64 ;;
  *)
    echo "不支持的 GOARCH: $GOARCH" >&2
    exit 1
    ;;
esac

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{bin,lib,web,utils} "$ROOT/dist"

echo "版本 $VER · ${GOOS}/${GOARCH} · BPF ARCH=$BPF_ARCH"
echo "$VER" >"$OUT_DIR/VERSION"

echo "编译面板…"
(
  cd "$BACKEND"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -ldflags "-s -w -X github.com/wuling/xdp-forward-panel/internal/version.Version=${VER} -X github.com/wuling/xdp-forward-panel/internal/version.BPFVersion=${VER}" \
    -o "$OUT_DIR/bin/xdp-panel" ./cmd/panel
)

echo "编译 BPF…"
if ! command -v clang >/dev/null 2>&1; then
  echo "需要 clang 编译 BPF" >&2
  exit 1
fi
make -C "$BACKEND" clean bpf ARCH="$BPF_ARCH"
install -m 0644 "$BACKEND/bpf/xdp_forward.o" "$OUT_DIR/lib/xdp_forward.o"

install -m 0755 "$ROOT/utils/xdp" "$OUT_DIR/bin/xdp"
install -m 0644 "$ROOT/project/frontend/"* "$OUT_DIR/web/"
install -m 0755 "$ROOT/utils/install-release.sh" "$OUT_DIR/utils/install-release.sh"
install -m 0755 "$ROOT/utils/issue-cert.sh" "$OUT_DIR/utils/issue-cert.sh"
install -m 0755 "$ROOT/utils/auto-update.sh" "$OUT_DIR/utils/auto-update.sh"
install -m 0755 "$ROOT/utils/do-update.sh" "$OUT_DIR/utils/do-update.sh"
install -m 0644 "$ROOT/utils/xdp-forward-panel.service" "$OUT_DIR/utils/xdp-forward-panel.service"

(
  cd "$ROOT/dist"
  tar -czf "${OUT_NAME}.tar.gz" "$OUT_NAME"
)
echo "产物: $ROOT/dist/${OUT_NAME}.tar.gz"
ls -lh "$ROOT/dist/${OUT_NAME}.tar.gz"
