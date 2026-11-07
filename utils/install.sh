#!/usr/bin/env bash
# 从本仓库源码安装（开发用）。生产请用 install-remote.sh / nftfp install。
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$REPO_ROOT/project/backend"
PREFIX="${PREFIX:-/usr/local}"
LIBDIR=/usr/lib/nftfp
SHARE=/usr/share/nftfp
DATA=/var/lib/nftfp

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl openssl iproute2 nftables \
  || apt-get install -y ca-certificates curl openssl iproute2 nftables

# stop legacy
systemctl stop xdp-forward-panel.service 2>/dev/null || true
systemctl disable xdp-forward-panel.service 2>/dev/null || true

VER="$(tr -d '[:space:]' <"$REPO_ROOT/VERSION")"
(
  cd "$BACKEND"
  CGO_ENABLED=0 go build \
    -ldflags "-s -w -X github.com/gzjacktang/nftforward/internal/version.Version=${VER} -X github.com/gzjacktang/nftforward/internal/version.EngineVersion=${VER}" \
    -o bin/nft-panel ./cmd/panel
)

mkdir -p "$LIBDIR" "$SHARE/web" "$DATA" "$PREFIX/bin" /usr/local/sbin /opt/nftfp
install -m 0755 "$BACKEND/bin/nft-panel" "$PREFIX/bin/nft-panel"
install -m 0755 "$REPO_ROOT/utils/nftfp" /usr/local/bin/nftfp
install -m 0644 "$REPO_ROOT/project/frontend/"* "$SHARE/web/"
install -m 0755 "$REPO_ROOT/utils/issue-cert.sh" /usr/local/sbin/nftfp-issue-cert
install -m 0755 "$REPO_ROOT/utils/auto-update.sh" /usr/local/sbin/nftfp-auto-update
install -m 0755 "$REPO_ROOT/utils/do-update.sh" /usr/local/sbin/nftfp-do-update
install -m 0644 "$REPO_ROOT/utils/nftfp.service" /etc/systemd/system/nftfp.service
echo "$VER" >/opt/nftfp/VERSION
rsync -a --exclude .git --exclude dist --exclude .ref-flux-panel "$REPO_ROOT"/ /opt/nftfp/ 2>/dev/null \
  || cp -a "$REPO_ROOT"/. /opt/nftfp/

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
  "tg_enabled": false
}
EOF
fi

/usr/local/sbin/nftfp-issue-cert selfsigned "${XFP_DOMAIN:-localhost}" || true

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
systemctl restart nftfp.service || systemctl start nftfp.service
systemctl --no-pager status nftfp.service || true
echo "安装完成 · 管理命令: nftfp"
