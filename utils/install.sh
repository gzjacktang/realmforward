#!/usr/bin/env bash
# 默认：从 GitHub Releases 安装预编译包（无需 Go / clang）
# 源码编译（开发用）: XFP_FROM_SOURCE=1 bash utils/install.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

# 生产默认走预编译；仅显式打开才本地编译
if [[ "${XFP_FROM_SOURCE:-0}" != "1" ]]; then
  echo "使用 GitHub Releases 预编译包安装（跳过 Go/clang）…"
  echo "如需本机编译请: XFP_FROM_SOURCE=1 bash $0"
  exec bash "$(cd "$(dirname "$0")" && pwd)/install-remote.sh"
fi

PREFIX="${PREFIX:-/usr/local}"
LIBDIR=/usr/lib/xdp-forward-panel
SHARE=/usr/share/xdp-forward-panel
DATA=/var/lib/xdp-forward-panel
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$REPO_ROOT/project/backend"

# Non-interactive overrides (optional):
#   XFP_TLS_MODE=letsencrypt|zerossl|selfsigned
#   XFP_DOMAIN=...
#   XFP_EMAIL=...
#   XFP_IFACE=eth0
#   XFP_NONINTERACTIVE=1

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y clang llvm make gcc "linux-headers-$(uname -r)" linux-libc-dev \
  libbpf-dev iproute2 ca-certificates curl openssl \
  || apt-get install -y clang llvm make gcc libbpf-dev iproute2 ca-certificates curl openssl

if ! command -v go >/dev/null 2>&1; then
  echo "安装 Go…"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) GOARCH=amd64 ;;
    aarch64|arm64) GOARCH=arm64 ;;
    *) echo "不支持的架构: $ARCH" >&2; exit 1 ;;
  esac
  curl -fsSL "https://go.dev/dl/go1.22.10.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
fi
export PATH="/usr/local/go/bin:${PATH:-}"

mkdir -p "$LIBDIR" "$SHARE/web" "$DATA" "$PREFIX/bin"

echo "编译 BPF…"
make -C "$BACKEND" bpf
install -m 0644 "$BACKEND/bpf/xdp_forward.o" "$LIBDIR/xdp_forward.o"

echo "编译面板…"
if [[ -x "$BACKEND/bin/xdp-panel-linux-amd64" ]]; then
  install -m 0755 "$BACKEND/bin/xdp-panel-linux-amd64" "$PREFIX/bin/xdp-panel"
elif [[ -x "$BACKEND/bin/xdp-panel" ]]; then
  install -m 0755 "$BACKEND/bin/xdp-panel" "$PREFIX/bin/xdp-panel"
else
  make -C "$BACKEND" panel
  install -m 0755 "$BACKEND/bin/xdp-panel" "$PREFIX/bin/xdp-panel"
fi

echo "安装前端…"
install -m 0644 "$REPO_ROOT/project/frontend/"* "$SHARE/web/"

install -m 0755 "$REPO_ROOT/utils/xdp" /usr/local/bin/xdp
install -m 0755 "$REPO_ROOT/utils/issue-cert.sh" /usr/local/sbin/xdp-panel-issue-cert
install -m 0755 "$REPO_ROOT/utils/auto-update.sh" /usr/local/sbin/xdp-panel-auto-update
install -m 0755 "$REPO_ROOT/utils/do-update.sh" /usr/local/sbin/xdp-panel-do-update
mkdir -p /opt/xdp-forward-panel
if [[ "$REPO_ROOT" != /opt/xdp-forward-panel ]]; then
  rsync -a --delete \
    --exclude 'project/backend/bin' \
    --exclude '.git' \
    "$REPO_ROOT"/ /opt/xdp-forward-panel/ 2>/dev/null \
    || cp -a "$REPO_ROOT"/. /opt/xdp-forward-panel/
fi

if [[ ! -f "$DATA/config.json" ]]; then
  cat >"$DATA/config.json" <<EOF
{
  "listen_addr": "0.0.0.0",
  "listen_port": 2888,
  "base_path": "/",
  "data_dir": "$DATA",
  "iface": "${XFP_IFACE:-}",
  "public_host": "${XFP_DOMAIN:-}",
  "tls_mode": "selfsigned",
  "acme_email": "${XFP_EMAIL:-}",
  "snat_port_min": 40000,
  "snat_port_max": 49999,
  "tls_cert_file": "$DATA/tls/cert.pem",
  "tls_key_file": "$DATA/tls/key.pem",
  "update_url": "https://github.com/gzjacktang/xdpforward/releases/latest",
  "auto_update": true,
  "tg_token": "",
  "tg_admin_ids": null,
  "tg_enabled": false,
  "xdp_mode": "auto"
}
EOF
fi

echo
echo "======== TLS 证书 ========"
if [[ -f "$DATA/tls/cert.pem" || -f "$DATA/tls/fullchain.pem" ]] || compgen -G "/etc/letsencrypt/live/*/fullchain.pem" >/dev/null; then
  echo "检测到已有证书，跳过签发（可用 xdp cert 更换）"
elif [[ "${XFP_NONINTERACTIVE:-0}" == "1" ]]; then
  case "${XFP_TLS_MODE:-selfsigned}" in
    letsencrypt|le)
      /usr/local/sbin/xdp-panel-issue-cert letsencrypt "${XFP_DOMAIN:?需要 XFP_DOMAIN}" "${XFP_EMAIL:-}"
      ;;
    zerossl|zero)
      /usr/local/sbin/xdp-panel-issue-cert zerossl "${XFP_DOMAIN:?需要 XFP_DOMAIN}" "${XFP_EMAIL:?ZeroSSL 需要邮箱}"
      ;;
    *)
      /usr/local/sbin/xdp-panel-issue-cert selfsigned "${XFP_DOMAIN:-localhost}"
      ;;
  esac
else
  /usr/local/sbin/xdp-panel-issue-cert prompt
fi

install -m 0644 "$REPO_ROOT/utils/xdp-forward-panel.service" /etc/systemd/system/xdp-forward-panel.service

cat >/etc/systemd/system/xdp-panel-update.service <<'EOF'
[Unit]
Description=XDP Panel auto update
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xdp-panel-auto-update
EOF
cat >/etc/systemd/system/xdp-panel-update.timer <<'EOF'
[Unit]
Description=Daily XDP Panel update check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable xdp-forward-panel.service
systemctl enable --now xdp-panel-update.timer
ufw allow 2888/tcp >/dev/null 2>&1 || true

systemctl restart xdp-forward-panel.service || systemctl start xdp-forward-panel.service
sleep 1
systemctl --no-pager status xdp-forward-panel.service || true

HOST=$(python3 -c "import json;print(json.load(open('$DATA/config.json')).get('public_host') or '<IP>')")
echo
echo "安装完成（源码编译模式）"
echo "面板: https://${HOST}:2888"
echo "管理命令: xdp"
