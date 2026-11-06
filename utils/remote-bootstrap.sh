#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y clang llvm make gcc "linux-headers-$(uname -r)" linux-libc-dev \
  libbpf-dev iproute2 ca-certificates curl
PREFIX=/usr/local
LIBDIR=/usr/lib/xdp-forward-panel
SHARE=/usr/share/xdp-forward-panel
DATA=/var/lib/xdp-forward-panel
BACKEND=/opt/xdp-forward-panel/project/backend
mkdir -p "$LIBDIR" "$SHARE/web" "$DATA" "$PREFIX/bin" "$BACKEND/bin"
echo "编译 BPF…"
make -C "$BACKEND" bpf
install -m 0644 "$BACKEND/bpf/xdp_forward.o" "$LIBDIR/xdp_forward.o"
install -m 0755 "$BACKEND/bin/xdp-panel-linux-amd64" "$PREFIX/bin/xdp-panel"
install -m 0644 /opt/xdp-forward-panel/project/frontend/* "$SHARE/web/"
if [[ ! -f "$DATA/config.json" ]]; then
  cat >"$DATA/config.json" <<'EOF'
{
  "listen_addr": "0.0.0.0",
  "listen_port": 2888,
  "base_path": "/",
  "data_dir": "/var/lib/xdp-forward-panel",
  "iface": "eth0",
  "public_host": "jpbc.ccbg.cc",
  "snat_port_min": 40000,
  "snat_port_max": 49999,
  "tls_cert_file": "/var/lib/xdp-forward-panel/tls/cert.pem",
  "tls_key_file": "/var/lib/xdp-forward-panel/tls/key.pem",
  "update_url": "",
  "auto_update": true,
  "tg_token": "",
  "tg_admin_ids": null,
  "tg_enabled": false,
  "xdp_mode": "auto"
}
EOF
fi
install -m 0644 /opt/xdp-forward-panel/utils/xdp-forward-panel.service /etc/systemd/system/xdp-forward-panel.service
install -m 0755 /opt/xdp-forward-panel/utils/auto-update.sh /usr/local/sbin/xdp-panel-auto-update
systemctl daemon-reload
systemctl enable xdp-forward-panel.service
ufw allow 2888/tcp || true
nft add table inet xfp 2>/dev/null || true
nft 'add chain inet xfp input { type filter hook input priority 0 ; policy accept ; }' 2>/dev/null || true
nft add rule inet xfp input tcp dport 2888 accept 2>/dev/null || true
systemctl restart xdp-forward-panel.service
sleep 2
systemctl --no-pager --full status xdp-forward-panel.service || true
journalctl -u xdp-forward-panel -n 50 --no-pager || true
ss -lntup | grep 2888 || true
