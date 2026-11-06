#!/usr/bin/env bash
# One-click install for Debian 11+ / Ubuntu 20.04+
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
LIBDIR=/usr/lib/xdp-forward-panel
SHARE=/usr/share/xdp-forward-panel
DATA=/var/lib/xdp-forward-panel
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$REPO_ROOT/project/backend"

# Non-interactive overrides (optional):
#   XFP_TLS_MODE=letsencrypt|selfsigned
#   XFP_DOMAIN=fxhk.jllexs.top
#   XFP_EMAIL=you@example.com
#   XFP_IFACE=eth0
#   XFP_NONINTERACTIVE=1

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y clang llvm make gcc "linux-headers-$(uname -r)" linux-libc-dev \
  libbpf-dev iproute2 ca-certificates curl openssl \
  || apt-get install -y clang llvm make gcc libbpf-dev iproute2 ca-certificates curl openssl

if ! command -v go >/dev/null 2>&1; then
  echo "安装 Go…"
  curl -fsSL https://go.dev/dl/go1.22.10.linux-amd64.tar.gz -o /tmp/go.tgz
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
# keep a copy under /opt for xdp update
mkdir -p /opt/xdp-forward-panel
if [[ "$REPO_ROOT" != /opt/xdp-forward-panel ]]; then
  rsync -a --delete \
    --exclude 'project/backend/bin' \
    --exclude '.git' \
    "$REPO_ROOT"/ /opt/xdp-forward-panel/ 2>/dev/null \
    || cp -a "$REPO_ROOT"/. /opt/xdp-forward-panel/
fi

# seed default config skeleton if missing
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
# 更新重装时若已有证书则跳过，避免打断线上
if [[ -f "$DATA/tls/cert.pem" || -f /etc/letsencrypt/live/*/fullchain.pem ]]; then
  echo "检测到已有证书，跳过签发（可用 xdp cert 更换）"
elif [[ "${XFP_NONINTERACTIVE:-0}" == "1" ]]; then
  case "${XFP_TLS_MODE:-selfsigned}" in
    letsencrypt|le)
      /usr/local/sbin/xdp-panel-issue-cert letsencrypt "${XFP_DOMAIN:?需要 XFP_DOMAIN}" "${XFP_EMAIL:-}"
      ;;
    *)
      /usr/local/sbin/xdp-panel-issue-cert selfsigned "${XFP_DOMAIN:-localhost}"
      ;;
  esac
else
  /usr/local/sbin/xdp-panel-issue-cert prompt
fi

echo "安装 systemd…"
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
MODE=$(python3 -c "import json;print(json.load(open('$DATA/config.json')).get('tls_mode','selfsigned'))")
echo
echo "安装完成。"
echo "面板: https://${HOST}:2888"
echo "证书模式: $MODE"
echo "首次账号密码见: journalctl -u xdp-forward-panel -n 80 --no-pager | grep -i pass"
echo "日常管理: xdp          # 交互菜单（状态/更新/改密/证书/卸载）"
echo "换证:     xdp cert"
