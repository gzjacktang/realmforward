#!/usr/bin/env bash
# 从预编译 release 包安装（不需要 Go / clang）
# 由 install-remote.sh 下载解压后调用，也可在解压目录内手动执行。
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
LIBDIR=/usr/lib/xdp-forward-panel
SHARE=/usr/share/xdp-forward-panel
DATA=/var/lib/xdp-forward-panel

# PKG_ROOT = 解压后的包根目录（含 bin/ lib/ web/ utils/ VERSION）
PKG_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ ! -x "$PKG_ROOT/bin/xdp-panel" ]]; then
  # 兼容：脚本在 utils/ 下，包根是上一级
  PKG_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
if [[ ! -x "$PKG_ROOT/bin/xdp-panel" && -x "$(dirname "$0")/../bin/xdp-panel" ]]; then
  PKG_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi

# Non-interactive overrides:
#   XFP_TLS_MODE=letsencrypt|zerossl|selfsigned
#   XFP_DOMAIN=...
#   XFP_EMAIL=...
#   XFP_IFACE=...
#   XFP_NONINTERACTIVE=1

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

if [[ ! -x "$PKG_ROOT/bin/xdp-panel" ]]; then
  echo "找不到预编译二进制: $PKG_ROOT/bin/xdp-panel" >&2
  exit 1
fi
if [[ ! -f "$PKG_ROOT/lib/xdp_forward.o" ]]; then
  echo "找不到 BPF 对象: $PKG_ROOT/lib/xdp_forward.o" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl openssl iproute2 \
  || apt-get install -y ca-certificates curl openssl iproute2

mkdir -p "$LIBDIR" "$SHARE/web" "$DATA" "$PREFIX/bin" /usr/local/sbin

VER="0.2.0"
[[ -f "$PKG_ROOT/VERSION" ]] && VER="$(tr -d '[:space:]' <"$PKG_ROOT/VERSION")"

echo "安装 XDP Forward Panel v$VER …"
install -m 0755 "$PKG_ROOT/bin/xdp-panel" "$PREFIX/bin/xdp-panel"
install -m 0755 "$PKG_ROOT/bin/xdp" /usr/local/bin/xdp
install -m 0644 "$PKG_ROOT/lib/xdp_forward.o" "$LIBDIR/xdp_forward.o"
install -m 0644 "$PKG_ROOT/web/"* "$SHARE/web/"
install -m 0755 "$PKG_ROOT/utils/issue-cert.sh" /usr/local/sbin/xdp-panel-issue-cert
install -m 0755 "$PKG_ROOT/utils/auto-update.sh" /usr/local/sbin/xdp-panel-auto-update
install -m 0755 "$PKG_ROOT/utils/do-update.sh" /usr/local/sbin/xdp-panel-do-update
install -m 0644 "$PKG_ROOT/utils/xdp-forward-panel.service" /etc/systemd/system/xdp-forward-panel.service

# 缓存包目录，便于排查
mkdir -p /opt/xdp-forward-panel
cp -a "$PKG_ROOT/." /opt/xdp-forward-panel/release/ 2>/dev/null \
  || { mkdir -p /opt/xdp-forward-panel/release && cp -a "$PKG_ROOT"/. /opt/xdp-forward-panel/release/; }
echo "$VER" >/opt/xdp-forward-panel/VERSION

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
else
  # 已有配置：把 update_url 指到 releases（若仍是 git 地址）
  python3 - <<'PY' || true
import json
p="/var/lib/xdp-forward-panel/config.json"
c=json.load(open(p))
u=(c.get("update_url") or "")
if "github.com/gzjacktang/xdpforward.git" in u or u.endswith(".git") or not u:
    c["update_url"]="https://github.com/gzjacktang/xdpforward/releases/latest"
    json.dump(c, open(p,"w"), indent=2, ensure_ascii=False)
PY
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
echo "安装完成 · v$VER"
echo "面板: https://${HOST}:2888"
echo "证书模式: $MODE"
echo "首次密码: journalctl -u xdp-forward-panel -n 80 --no-pager"
echo "管理命令: xdp"
