#!/usr/bin/env bash
# Download zhboner/realm binary for linux/$GOARCH into OUT path.
# Usage: fetch-realm.sh <amd64|arm64> <output-file>
set -euo pipefail

ARCH="${1:?arch}"
OUT="${2:?output}"
REPO="${REALM_GITHUB_REPO:-zhboner/realm}"
TAG="${REALM_TAG:-}"

case "$ARCH" in
  amd64|x86_64) TRIPLE=x86_64-unknown-linux-gnu ;;
  arm64|aarch64) TRIPLE=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

api="https://api.github.com/repos/${REPO}/releases/latest"
if [[ -n "$TAG" ]]; then
  [[ "$TAG" == v* ]] || TAG="v${TAG}"
  api="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

json="$(curl -fsSL "$api")"
tag="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
# Prefer tar.gz then zip
url=""
for name in \
  "realm-${TRIPLE}.tar.gz" \
  "realm-${tag}-${TRIPLE}.tar.gz" \
  "realm-${TRIPLE}.zip" \
  "realm-${tag#v}-${TRIPLE}.tar.gz"
do
  cand="$(printf '%s' "$json" | python3 -c 'import json,sys; name=sys.argv[1]; d=json.load(sys.stdin); print(next((a["browser_download_url"] for a in d["assets"] if a["name"]==name), ""))' "$name")"
  if [[ -n "$cand" ]]; then
    url="$cand"
    break
  fi
done
if [[ -z "$url" ]]; then
  echo "realm asset not found for $TRIPLE; available:" >&2
  printf '%s' "$json" | python3 -c 'import json,sys; [print(a["name"]) for a in json.load(sys.stdin)["assets"]]' >&2
  exit 1
fi

echo "下载 realm $tag → $url"
curl -fL --progress-bar "$url" -o "$TMP/pkg"
mkdir -p "$TMP/out"
case "$url" in
  *.zip) unzip -q "$TMP/pkg" -d "$TMP/out" ;;
  *) tar -xzf "$TMP/pkg" -C "$TMP/out" ;;
esac
bin="$(find "$TMP/out" -type f -name realm | head -1)"
[[ -n "$bin" ]] || { echo "archive missing realm binary" >&2; exit 1; }
install -m 0755 "$bin" "$OUT"
echo "realm → $OUT"
