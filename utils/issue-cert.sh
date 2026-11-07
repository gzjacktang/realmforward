#!/usr/bin/env bash
# Issue or renew TLS cert for Realm Forward Panel.
# Modes: letsencrypt | zerossl | selfsigned | prompt
set -euo pipefail

DATA="${DATA:-/var/lib/realmfp}"
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
p="/var/lib/realmfp/config.json"
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
domain="$domain"
# Don't persist localhost as public_host — status/UI would show a useless URL.
if domain and domain not in ("localhost", "127.0.0.1"):
    c["public_host"]=domain
elif c.get("public_host") in ("localhost", "127.0.0.1", None, ""):
    c["public_host"]=""
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
    -subj "/O=Realm Forward Panel/CN=${domain:-realmfp}" \
    -addext "subjectAltName=DNS:${domain:-localhost},IP:127.0.0.1" 2>/dev/null \
  || openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout "$key" -out "$cert" \
    -subj "/O=Realm Forward Panel/CN=${domain:-realmfp}"
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
  cat >/etc/letsencrypt/renewal-hooks/deploy/realmfp.sh <<'HOOK'
#!/bin/bash
systemctl try-reload-or-restart realmfp.service 2>/dev/null || systemctl restart realmfp.service 2>/dev/null || true
HOOK
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/realmfp.sh

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
    --reloadcmd "systemctl try-reload-or-restart realmfp.service 2>/dev/null || systemctl restart realmfp.service 2>/dev/null || true"

  chmod 600 "$key"
  write_cfg "zerossl" "$domain" "$email" "$cert" "$key"
  echo "ZeroSSL 证书就绪: $cert"
}

# Wire an already-issued cert into panel config. Returns 0 if panel now has a usable cert+key.
adopt_existing() {
  python3 - <<'PY'
import json, os, re, glob, subprocess

CFG = "/var/lib/realmfp/config.json"
DATA = "/var/lib/realmfp"
c = {}
if os.path.exists(CFG):
    c = json.load(open(CFG))

def dns_of(path):
    if not os.path.isfile(path):
        return ""
    try:
        out = subprocess.check_output(
            ["openssl", "x509", "-in", path, "-noout", "-ext", "subjectAltName"],
            stderr=subprocess.DEVNULL, text=True,
        )
        for m in re.finditer(r"DNS:\s*([^,\s]+)", out):
            n = m.group(1).strip()
            if n and n not in ("localhost",) and not re.fullmatch(r"[0-9.]+", n):
                return n
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["openssl", "x509", "-in", path, "-noout", "-subject"],
            stderr=subprocess.DEVNULL, text=True,
        )
        m = re.search(r"CN\s*=\s*([^,/]+)", out)
        if m:
            n = m.group(1).strip()
            if n not in ("localhost", "realmfp", "127.0.0.1") and not re.fullmatch(r"[0-9.]+", n):
                return n
    except Exception:
        pass
    return ""

def usable(cert, key):
    return bool(cert and key and os.path.isfile(cert) and os.path.isfile(key))

def save(mode, domain, cert, key):
    c["tls_mode"] = mode
    c["tls_cert_file"] = cert
    c["tls_key_file"] = key
    if domain and domain not in ("localhost", "127.0.0.1"):
        c["public_host"] = domain
    elif c.get("public_host") in ("localhost", "127.0.0.1", None, ""):
        c["public_host"] = ""
    os.makedirs(os.path.dirname(CFG), exist_ok=True)
    json.dump(c, open(CFG, "w"), indent=2, ensure_ascii=False)
    print(f"已挂载证书到面板: mode={mode} domain={c.get('public_host') or '(无)'} cert={cert}")

want = (c.get("public_host") or os.environ.get("XFP_DOMAIN") or "").strip()
cur_cert = c.get("tls_cert_file") or ""
cur_key = c.get("tls_key_file") or ""
cur_mode = (c.get("tls_mode") or "selfsigned").lower()

# Prefer Let's Encrypt live certs over leftover self-signed panel files.
candidates = []
for live in sorted(glob.glob("/etc/letsencrypt/live/*/fullchain.pem")):
    domain = os.path.basename(os.path.dirname(live))
    if domain.startswith("."):
        continue
    key = os.path.join(os.path.dirname(live), "privkey.pem")
    if usable(live, key):
        candidates.append(("letsencrypt", domain, live, key))

full = os.path.join(DATA, "tls", "fullchain.pem")
pkey = os.path.join(DATA, "tls", "key.pem")
if usable(full, pkey):
    domain = dns_of(full) or want
    mode = "zerossl" if cur_mode in ("zerossl", "zero") else "custom"
    candidates.append((mode, domain, full, pkey))

# Already wired to a public-CA / custom cert: just sync domain and keep.
if usable(cur_cert, cur_key) and cur_mode not in ("selfsigned", "self", ""):
    domain = dns_of(cur_cert) or want
    if domain and not c.get("public_host"):
        save(cur_mode, domain, cur_cert, cur_key)
    else:
        if domain and c.get("public_host") in ("", "localhost", "127.0.0.1"):
            save(cur_mode, domain, cur_cert, cur_key)
        else:
            print(f"面板已使用证书: {cur_cert}")
    raise SystemExit(0)

# Prefer LE matching wanted domain, else first LE, else panel fullchain.
picked = None
if want:
    for item in candidates:
        if item[0] == "letsencrypt" and item[1] == want:
            picked = item
            break
if picked is None:
    for item in candidates:
        if item[0] == "letsencrypt":
            picked = item
            break
if picked is None and candidates:
    picked = candidates[0]

if picked:
    mode, domain, cert, key = picked
    domain = domain or dns_of(cert) or want
    save(mode, domain, cert, key)
    raise SystemExit(0)

# Fall back to existing self-signed under data dir if present.
ss_cert = os.path.join(DATA, "tls", "cert.pem")
ss_key = os.path.join(DATA, "tls", "key.pem")
if usable(ss_cert, ss_key):
    domain = dns_of(ss_cert) or want
    save("selfsigned", domain, ss_cert, ss_key)
    raise SystemExit(0)

if usable(cur_cert, cur_key):
    domain = dns_of(cur_cert) or want
    save(cur_mode or "selfsigned", domain, cur_cert, cur_key)
    raise SystemExit(0)

print("未找到可挂载的已有证书")
raise SystemExit(1)
PY
}

prompt_and_issue() {
  # Reuse certs already on this machine before asking to issue again.
  if adopt_existing; then
    return 0
  fi
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
      read -r -p "域名: " domain
      read -r -p "邮箱 (可留空): " email
      issue_letsencrypt "$domain" "$email"
      ;;
    2)
      read -r -p "域名: " domain
      read -r -p "邮箱 (必填): " email
      issue_zerossl "$domain" "$email"
      ;;
    *)
      read -r -p "域名或主机名 (可留空): " domain
      issue_selfsigned "${domain:-}"
      ;;
  esac
}

need_root
mkdir -p "$DATA"

case "$MODE" in
  adopt|use-existing)
    adopt_existing || exit 1
    ;;
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
    [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]] && DOMAIN=""
    issue_selfsigned "$DOMAIN"
    ;;
  ""|prompt)
    prompt_and_issue
    ;;
  *)
    echo "用法: $0 [adopt|letsencrypt|zerossl|selfsigned|prompt] [domain] [email]" >&2
    exit 1
    ;;
esac
