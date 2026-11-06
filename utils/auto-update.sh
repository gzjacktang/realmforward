#!/usr/bin/env bash
# Timer 触发：若开启 auto_update，则走 xdp update（从 GitHub 拉源码重装）。
set -euo pipefail
CFG=/var/lib/xdp-forward-panel/config.json
[[ -f "$CFG" ]] || exit 0
python3 - <<'PY' || exit 0
import json,sys
c=json.load(open("/var/lib/xdp-forward-panel/config.json"))
sys.exit(0 if c.get("auto_update") else 1)
PY
if [[ -x /usr/local/bin/xdp ]]; then
  export XFP_REPO
  XFP_REPO="$(python3 -c "import json;print(json.load(open('$CFG')).get('update_url') or 'https://github.com/gzjacktang/xdpforward.git')")"
  /usr/local/bin/xdp update
else
  echo "xdp CLI 不存在，跳过自动更新" >&2
fi
