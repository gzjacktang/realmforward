#!/usr/bin/env bash
# 从预编译 release 包安装（不需要 Go / clang）
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
LIBDIR=/usr/lib/nftfp
SHARE=/usr/share/nftfp
DATA=/var/lib/nftfp
OLD_DATA=/var/lib/xdp-forward-panel

PKG_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

if [[ ! -x "$PKG_ROOT/bin/nft-panel" ]]; then
  echo "找不到预编译二进制: $PKG_ROOT/bin/nft-panel" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl openssl iproute2 nftables \
  || apt-get install -y ca-certificates curl openssl iproute2 nftables

# Stop / disable legacy XDP panel if present
systemctl stop xdp-forward-panel.service 2>/dev/null || true
systemctl disable xdp-forward-panel.service 2>/dev/null || true
systemctl stop xdp-panel-update.timer 2>/dev/null || true
systemctl disable xdp-panel-update.timer 2>/dev/null || true

mkdir -p "$LIBDIR" "$SHARE/web" "$DATA" "$PREFIX/bin" /usr/local/sbin

# Migrate old data once
if [[ ! -f "$DATA/config.json" && -f "$OLD_DATA/config.json" ]]; then
  echo "迁移旧数据 $OLD_DATA → $DATA"
  cp -a "$OLD_DATA/." "$DATA/"
fi

VER="0.3.0"
[[ -f "$PKG_ROOT/VERSION" ]] && VER="$(tr -d '[:space:]' <"$PKG_ROOT/VERSION")"

echo "安装 NFT Forward Panel v$VER …"
install -m 0755 "$PKG_ROOT/bin/nft-panel" "$PREFIX/bin/nft-panel"
install -m 0755 "$PKG_ROOT/bin/nftfp" /usr/local/bin/nftfp
install -m 0644 "$PKG_ROOT/web/"* "$SHARE/web/"
install -m 0755 "$PKG_ROOT/utils/issue-cert.sh" /usr/local/sbin/nftfp-issue-cert
install -m 0755 "$PKG_ROOT/utils/auto-update.sh" /usr/local/sbin/nftfp-auto-update
install -m 0755 "$PKG_ROOT/utils/do-update.sh" /usr/local/sbin/nftfp-do-update
install -m 0644 "$PKG_ROOT/utils/nftfp.service" /etc/systemd/system/nftfp.service

mkdir -p /opt/nftfp
cp -a "$PKG_ROOT/." /opt/nftfp/release/ 2>/dev/null \
  || { mkdir -p /opt/nftfp/release && cp -a "$PKG_ROOT"/. /opt/nftfp/release/; }
echo "$VER" >/opt/nftfp/VERSION

NEED_SETUP=0
HAS_OLD=0
if [[ -f "$DATA/config.json" || -f "$DATA/panel.db" || -d "$DATA/tls" ]]; then
  HAS_OLD=1
fi

if [[ "${XFP_FORCE_SETUP:-0}" == "1" ]]; then
  echo "XFP_FORCE_SETUP=1：清空 $DATA 并重新配置"
  rm -rf "$DATA"
  mkdir -p "$DATA"
  NEED_SETUP=1
elif [[ "$HAS_OLD" == "1" ]]; then
  if [[ "${XFP_KEEP_DATA:-0}" == "1" || "${XFP_NONINTERACTIVE:-0}" == "1" ]]; then
    echo "保留已有数据目录 $DATA"
  else
    echo
    echo "检测到旧配置/数据库/证书：$DATA"
    read -r -p "是否清空并重新进入安装配置？[Y/n]: " wipe_old
    wipe_old="${wipe_old:-Y}"
    if [[ ! "$wipe_old" =~ ^[Nn] ]]; then
      rm -rf "$DATA"
      mkdir -p "$DATA"
      NEED_SETUP=1
      echo "已清空，将重新配置"
    else
      echo "保留旧数据（证书配置将跳过）"
    fi
  fi
else
  NEED_SETUP=1
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
  "tls_cert_file": "$DATA/tls/cert.pem",
  "tls_key_file": "$DATA/tls/key.pem",
  "update_url": "https://github.com/gzjacktang/nftforward/releases/latest",
  "auto_update": true,
  "tg_token": "",
  "tg_admin_ids": null,
  "tg_enabled": false
}
EOF
else
  python3 - <<'PY' || true
import json
p="/var/lib/nftfp/config.json"
c=json.load(open(p))
u=(c.get("update_url") or "")
if "xdpforward" in u or u.endswith(".git") or not u:
    c["update_url"]="https://github.com/gzjacktang/nftforward/releases/latest"
c["data_dir"]="/var/lib/nftfp"
c.pop("snat_port_min", None)
c.pop("snat_port_max", None)
c.pop("xdp_mode", None)
c.pop("csum_safe", None)
c.pop("csum_fast", None)
json.dump(c, open(p,"w"), indent=2, ensure_ascii=False)
PY
fi

echo
echo "======== TLS 证书 ========"
HAS_CERT=0
if [[ -f "$DATA/tls/cert.pem" || -f "$DATA/tls/fullchain.pem" ]] || compgen -G "/etc/letsencrypt/live/*/fullchain.pem" >/dev/null; then
  HAS_CERT=1
fi

if [[ "$NEED_SETUP" == "1" || "$HAS_CERT" != "1" ]]; then
  if [[ "${XFP_NONINTERACTIVE:-0}" == "1" ]]; then
    case "${XFP_TLS_MODE:-selfsigned}" in
      letsencrypt|le)
        /usr/local/sbin/nftfp-issue-cert letsencrypt "${XFP_DOMAIN:?需要 XFP_DOMAIN}" "${XFP_EMAIL:-}"
        ;;
      zerossl|zero)
        /usr/local/sbin/nftfp-issue-cert zerossl "${XFP_DOMAIN:?需要 XFP_DOMAIN}" "${XFP_EMAIL:?ZeroSSL 需要邮箱}"
        ;;
      *)
        /usr/local/sbin/nftfp-issue-cert selfsigned "${XFP_DOMAIN:-localhost}"
        ;;
    esac
  else
    /usr/local/sbin/nftfp-issue-cert prompt
  fi
else
  echo "检测到已有证书，跳过签发（可用 nftfp cert 更换）"
fi

cat >/etc/systemd/system/nftfp-update.service <<'EOF'
[Unit]
Description=NFT Forward Panel auto update
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nftfp-auto-update
EOF
cat >/etc/systemd/system/nftfp-update.timer <<'EOF'
[Unit]
Description=Daily NFT Forward Panel update check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable nftfp.service
systemctl enable --now nftfp-update.timer
ufw allow 2888/tcp >/dev/null 2>&1 || true

systemctl restart nftfp.service || systemctl start nftfp.service
sleep 1
systemctl --no-pager status nftfp.service || true

HOST=$(python3 -c "import json;print(json.load(open('$DATA/config.json')).get('public_host') or '<IP>')")
MODE=$(python3 -c "import json;print(json.load(open('$DATA/config.json')).get('tls_mode','selfsigned'))")
echo
echo "安装完成 · v$VER"
echo "面板: https://${HOST}:2888"
echo "证书模式: $MODE"
echo "首次密码: journalctl -u nftfp -n 80 --no-pager"
echo "管理命令: nftfp"
