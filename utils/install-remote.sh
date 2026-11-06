#!/usr/bin/env bash
# 一键安装入口（在干净的 Debian/Ubuntu VPS 上以 root 执行）
#   bash <(curl -fsSL https://raw.githubusercontent.com/gzjacktang/xdpforward/main/utils/install-remote.sh)
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

REPO_URL="${XFP_REPO:-https://github.com/gzjacktang/xdpforward.git}"
REPO_DIR="${XFP_REPO_DIR:-/opt/xdp-forward-panel}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git ca-certificates curl

rm -rf "$REPO_DIR"
git clone --depth 1 "$REPO_URL" "$REPO_DIR"

install -m 0755 "$REPO_DIR/utils/xdp" /usr/local/bin/xdp
# 走完整安装（编译 BPF/面板、证书、systemd）
bash "$REPO_DIR/utils/install.sh"

echo
echo "管理命令: xdp          # 交互菜单"
echo "          xdp status"
echo "          xdp update"
echo "          xdp passwd"
echo "          xdp cert"
