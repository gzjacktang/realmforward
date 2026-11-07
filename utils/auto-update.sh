#!/usr/bin/env bash
# Timer 触发：若开启 auto_update，则走 nftfp update。
set -euo pipefail
CFG=/var/lib/nftfp/config.json
[[ -f "$CFG" ]] || exit 0
python3 - <<'PY' || exit 0
import json,sys
c=json.load(open("/var/lib/nftfp/config.json"))
sys.exit(0 if c.get("auto_update") else 1)
PY
if [[ -x /usr/local/bin/nftfp ]]; then
  /usr/local/bin/nftfp update
else
  echo "nftfp CLI 不存在，跳过自动更新" >&2
fi
