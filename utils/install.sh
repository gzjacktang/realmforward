#!/usr/bin/env bash
# 从本仓库源码安装（开发用）。生产请用 install-remote.sh / realmfp install。
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$REPO_ROOT/project/backend"
PREFIX="${PREFIX:-/usr/local}"
LIBDIR=/usr/lib/realmfp
SHARE=/usr/share/realmfp
DATA=/var/lib/realmfp

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
    -ldflags "-s -w -X github.com/gzjacktang/realmforward/internal/version.Version=${VER} -X github.com/gzjacktang/realmforward/internal/version.EngineVersion=${VER}" \
    -o bin/realm-panel ./cmd/panel
)

mkdir -p "$LIBDIR" "$SHARE/web" "$DATA" "$PREFIX/bin" /usr/local/sbin /opt/realmfp
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
chmod +x "$REPO_ROOT/utils/fetch-realm.sh"
"$REPO_ROOT/utils/fetch-realm.sh" "$GOARCH" "$LIBDIR/realm"
install -m 0755 "$LIBDIR/realm" /usr/local/bin/realm
pkill -x realm 2>/dev/null || true
nft delete table ip nftfp 2>/dev/null || true
install -m 0755 "$BACKEND/bin/realm-panel" "$PREFIX/bin/realm-panel"
install -m 0755 "$REPO_ROOT/utils/realmfp" /usr/local/bin/realmfp
install -m 0644 "$REPO_ROOT/project/frontend/"* "$SHARE/web/"
install -m 0755 "$REPO_ROOT/utils/issue-cert.sh" /usr/local/sbin/realmfp-issue-cert
install -m 0755 "$REPO_ROOT/utils/auto-update.sh" /usr/local/sbin/realmfp-auto-update
install -m 0755 "$REPO_ROOT/utils/do-update.sh" /usr/local/sbin/realmfp-do-update
install -m 0644 "$REPO_ROOT/utils/realmfp.service" /etc/systemd/system/realmfp.service
echo "$VER" >/opt/realmfp/VERSION
rsync -a --exclude .git --exclude dist --exclude .ref-flux-panel "$REPO_ROOT"/ /opt/realmfp/ 2>/dev/null \
  || cp -a "$REPO_ROOT"/. /opt/realmfp/

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
  "update_url": "https://github.com/gzjacktang/realmforward/releases/latest",
  "auto_update": true,
  "tg_enabled": false
}
EOF
fi

/usr/local/sbin/realmfp-issue-cert selfsigned "${XFP_DOMAIN:-localhost}" || true

cat >/etc/systemd/system/realmfp-update.service <<'EOF'
[Unit]
Description=Realm Forward Panel auto update
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/realmfp-auto-update
EOF
cat >/etc/systemd/system/realmfp-update.timer <<'EOF'
[Unit]
Description=Daily Realm Forward Panel update check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable realmfp.service
systemctl enable --now realmfp-update.timer
systemctl restart realmfp.service || systemctl start realmfp.service
systemctl --no-pager status realmfp.service || true
echo "安装完成 · 管理命令: realmfp"
