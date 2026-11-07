#!/usr/bin/env bash
# Timer 触发：若开启 auto_update，则走 realmfp update。
set -euo pipefail
CFG=/var/lib/realmfp/config.json
[[ -f "$CFG" ]] || exit 0
python3 - <<'PY' || exit 0
import json,sys
c=json.load(open("/var/lib/realmfp/config.json"))
sys.exit(0 if c.get("auto_update") else 1)
PY
if [[ -x /usr/local/bin/realmfp ]]; then
  /usr/local/bin/realmfp update
else
  echo "realmfp CLI 不存在，跳过自动更新" >&2
fi
