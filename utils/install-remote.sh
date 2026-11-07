#!/usr/bin/env bash
# 一键安装：从 GitHub Releases 拉取预编译包（无需 Go / clang）
#   bash <(curl -fsSL https://raw.githubusercontent.com/gzjacktang/nftforward/main/utils/install-remote.sh)
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

REPO="${XFP_GITHUB_REPO:-gzjacktang/nftforward}"
API="https://api.github.com/repos/${REPO}/releases/latest"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl jq tar gzip >/dev/null

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH_TAG=linux-amd64 ;;
  aarch64|arm64) ARCH_TAG=linux-arm64 ;;
  *)
    echo "暂不支持的架构: $ARCH（需要 amd64 或 arm64）" >&2
    exit 1
    ;;
esac

echo "查询最新 Release…"
JSON="$(curl -fsSL "$API")"
TAG="$(printf '%s' "$JSON" | jq -r '.tag_name')"
ASSET_URL="$(printf '%s' "$JSON" | jq -r --arg a "nftforward-${TAG}-${ARCH_TAG}.tar.gz" \
  '.assets[] | select(.name==$a) | .browser_download_url')"

if [[ -z "$ASSET_URL" || "$ASSET_URL" == "null" ]]; then
  ASSET_URL="$(printf '%s' "$JSON" | jq -r --arg a "nftforward-v${TAG#v}-${ARCH_TAG}.tar.gz" \
    '.assets[] | select(.name==$a) | .browser_download_url')"
fi

if [[ -z "$ASSET_URL" || "$ASSET_URL" == "null" ]]; then
  echo "未找到架构 ${ARCH_TAG} 的安装包。Release: $TAG" >&2
  echo "可用资源:" >&2
  printf '%s' "$JSON" | jq -r '.assets[].name' >&2
  exit 1
fi

echo "下载 $ASSET_URL …"
curl -fL --progress-bar "$ASSET_URL" -o "$TMP/pkg.tgz"
mkdir -p "$TMP/pkg"
tar -xzf "$TMP/pkg.tgz" -C "$TMP/pkg"
ROOT="$TMP/pkg"
if [[ ! -x "$ROOT/bin/nft-panel" ]]; then
  ROOT="$(find "$TMP/pkg" -maxdepth 2 -type d -name 'nftforward-*' | head -1)"
fi
[[ -x "$ROOT/bin/nft-panel" ]] || { echo "解压后找不到 bin/nft-panel" >&2; exit 1; }

XFP_KEEP_DATA="${XFP_KEEP_DATA:-0}" bash "$ROOT/utils/install-release.sh"
