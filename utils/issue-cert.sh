#!/usr/bin/env bash
# Issue or renew TLS cert for XDP Forward Panel.
# Modes: letsencrypt | zerossl | selfsigned | prompt
set -euo pipefail

DATA="${DATA:-/var/lib/xdp-forward-panel}"
CFG="$DATA/config.json"
MODE="${1:-}"          # letsencrypt | zerossl | selfsigned | ""
DOMAIN="${2:-}"
EMAIL="${3:-}"

need_root() {
  [[ "$(id -u)" -eq 0 ]] || { echo "请使用 root 运行" >&2; exit 1; }
}

read_cfg() {
  python3 - <<'PY'
import json,os
p="/var/lib/xdp-forward-panel/config.json"
if not os.path.exists(p):
    print("")
    raise SystemExit
c=json.load(open(p))
print(c.get("public_host",""))
print(c.get("tls_mode","selfsigned"))
print(c.get("acme_email",""))
print(c.get("tls_cert_file",""))
print(c.get("tls_key_file",""))
PY
}

write_cfg() {
  local mode="$1" domain="$2" email="$3" cert="$4" key="$5"
  python3 - <<PY
import json, os
p="$CFG"
os.makedirs(os.path.dirname(p), exist_ok=True)
c={}
if os.path.exists(p):
    c=json.load(open(p))
c["tls_mode"]="$mode"
c["public_host"]="$domain"
c["acme_email"]="$email"
c["tls_cert_file"]="$cert"
c["tls_key_file"]="$key"
json.dump(c, open(p,"w"), indent=2, ensure_ascii=False)
print("updated", p)
PY
}

issue_selfsigned() {
  local domain="$1"
  local certdir="$DATA/tls"
  mkdir -p "$certdir"
  local cert="$certdir/cert.pem" key="$certdir/key.pem"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 365 -nodes \
    -keyout "$key" -out "$cert" \
    -subj "/O=XDP Forward Panel/CN=${domain:-xdp-forward-panel}" \
    -addext "subjectAltName=DNS:${domain:-localhost},IP:127.0.0.1" 2>/dev/null \
  || openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout "$key" -out "$cert" \
    -subj "/O=XDP Forward Panel/CN=${domain:-xdp-forward-panel}"
  chmod 600 "$key"
  write_cfg "selfsigned" "$domain" "" "$cert" "$key"
  echo "已生成自签证书: $cert"
}

issue_letsencrypt() {
  local domain="$1" email="$2"
  [[ -n "$domain" ]] || { echo "Let's Encrypt 需要域名" >&2; exit 1; }

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y certbot >/dev/null

  # HTTP-01 needs :80 free
  if ss -lnt | grep -q ':80 '; then
    echo "错误: 80 端口被占用，无法用 standalone 申请证书。" >&2
    echo "请先释放 80，或改用 DNS 验证。" >&2
    exit 1
  fi
  ufw allow 80/tcp >/dev/null 2>&1 || true

  local args=(certonly --standalone --non-interactive --agree-tos --preferred-challenges http
    -d "$domain" --keep-until-expiring)
  if [[ -n "$email" ]]; then
    args+=(--email "$email")
  else
    args+=(--register-unsafely-without-email)
  fi

  echo "正在向 Let's Encrypt 申请证书: $domain …"
  certbot "${args[@]}"

  local live="/etc/letsencrypt/live/$domain"
  [[ -f "$live/fullchain.pem" && -f "$live/privkey.pem" ]] || {
    echo "证书文件未找到: $live" >&2
    exit 1
  }

  write_cfg "letsencrypt" "$domain" "$email" "$live/fullchain.pem" "$live/privkey.pem"

  # renew deploy hook
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/xdp-forward-panel.sh <<'HOOK'
#!/bin/bash
systemctl try-reload-or-restart xdp-forward-panel.service 2>/dev/null || systemctl restart xdp-forward-panel.service 2>/dev/null || true
HOOK
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/xdp-forward-panel.sh

  echo "Let's Encrypt 证书就绪: $live/fullchain.pem"
}

ensure_acme_sh() {
  if [[ -x "$HOME/.acme.sh/acme.sh" ]]; then
    return 0
  fi
  if [[ -x /root/.acme.sh/acme.sh ]]; then
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y curl cron socat >/dev/null
  local mail="${1:-admin@localhost}"
  curl -fsSL https://get.acme.sh | sh -s email="$mail"
}

acme_bin() {
  if [[ -x /root/.acme.sh/acme.sh ]]; then
    echo /root/.acme.sh/acme.sh
  else
    echo "$HOME/.acme.sh/acme.sh"
  fi
}

issue_zerossl() {
  local domain="$1" email="$2"
  [[ -n "$domain" ]] || { echo "ZeroSSL 需要域名" >&2; exit 1; }
  [[ -n "$email" ]] || { echo "ZeroSSL 需要邮箱（用于账号注册）" >&2; exit 1; }

  if ss -lnt | grep -q ':80 '; then
    echo "错误: 80 端口被占用，无法用 standalone 申请证书。" >&2
    exit 1
  fi
  ufw allow 80/tcp >/dev/null 2>&1 || true

  ensure_acme_sh "$email"
  local ACME
  ACME="$(acme_bin)"

  echo "正在向 ZeroSSL 申请证书: $domain …"
  "$ACME" --set-default-ca --server zerossl >/dev/null
  "$ACME" --register-account -m "$email" >/dev/null 2>&1 || true
  "$ACME" --issue --standalone -d "$domain" --keylength ec-256 --force

  local certdir="$DATA/tls"
  mkdir -p "$certdir"
  local cert="$certdir/fullchain.pem" key="$certdir/key.pem"
  "$ACME" --install-cert -d "$domain" --ecc \
    --fullchain-file "$cert" \
    --key-file "$key" \
    --reloadcmd "systemctl try-reload-or-restart xdp-forward-panel.service 2>/dev/null || systemctl restart xdp-forward-panel.service 2>/dev/null || true"

  chmod 600 "$key"
  write_cfg "zerossl" "$domain" "$email" "$cert" "$key"
  echo "ZeroSSL 证书就绪: $cert"
}

prompt_and_issue() {
  echo
  echo "======== TLS 证书设置 ========"
  echo "1) Let's Encrypt 免费证书（推荐，需公网域名且 80 端口可达）"
  echo "2) ZeroSSL 免费证书（需域名 + 邮箱，80 端口可达）"
  echo "3) 自签证书（浏览器会提示不受信任）"
  local choice
  read -r -p "请选择 [1/2/3] (默认 1): " choice
  choice="${choice:-1}"

  local domain email
  case "$choice" in
    1)
      read -r -p "域名 (例如 fxhk.jllexs.top): " domain
      read -r -p "邮箱 (可留空): " email
      issue_letsencrypt "$domain" "$email"
      ;;
    2)
      read -r -p "域名 (例如 fxhk.jllexs.top): " domain
      read -r -p "邮箱 (必填): " email
      issue_zerossl "$domain" "$email"
      ;;
    *)
      read -r -p "域名或主机名 (可留空，默认 localhost): " domain
      domain="${domain:-localhost}"
      issue_selfsigned "$domain"
      ;;
  esac
}

need_root
mkdir -p "$DATA"

case "$MODE" in
  letsencrypt|le)
    DOMAIN="${DOMAIN:-$(read_cfg | sed -n '1p')}"
    EMAIL="${EMAIL:-$(read_cfg | sed -n '3p')}"
    issue_letsencrypt "$DOMAIN" "$EMAIL"
    ;;
  zerossl|zero)
    DOMAIN="${DOMAIN:-$(read_cfg | sed -n '1p')}"
    EMAIL="${EMAIL:-$(read_cfg | sed -n '3p')}"
    issue_zerossl "$DOMAIN" "$EMAIL"
    ;;
  selfsigned|self)
    DOMAIN="${DOMAIN:-$(read_cfg | sed -n '1p')}"
    DOMAIN="${DOMAIN:-localhost}"
    issue_selfsigned "$DOMAIN"
    ;;
  ""|prompt)
    prompt_and_issue
    ;;
  *)
    echo "用法: $0 [letsencrypt|zerossl|selfsigned|prompt] [domain] [email]" >&2
    exit 1
    ;;
esac
