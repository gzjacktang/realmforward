#!/usr/bin/env bash
# 脱离面板进程执行更新（systemd-run 调用），写入状态供 Web 轮询。
set -euo pipefail

DATA="${XFP_DATA:-/var/lib/realmfp}"
STATUS="$DATA/update-status.json"
LOG="$DATA/update.log"
mkdir -p "$DATA"

from_ver="$(tr -d '[:space:]' </opt/realmfp/VERSION 2>/dev/null || true)"
[[ -n "$from_ver" ]] || from_ver="$(/usr/local/bin/realm-panel -version 2>/dev/null | head -1 || echo unknown)"

want_tag="${1:-}"

write_status() {
  local state="$1" err="${2:-}"
  local to_ver
  to_ver="$(tr -d '[:space:]' </opt/realmfp/VERSION 2>/dev/null || echo "")"
  python3 - "$STATUS" "$state" "$from_ver" "$to_ver" "$err" "$want_tag" <<'PY'
import json,sys,time,os
path,state,frm,to,err,tag=sys.argv[1:7]
prev={}
if os.path.exists(path):
  try: prev=json.load(open(path))
  except Exception: prev={}
now=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
obj={
  "state": state,
  "from_version": frm or prev.get("from_version") or "",
  "to_version": to or "",
  "want_tag": tag or "",
  "error": err or "",
  "started_at": prev.get("started_at") or now,
  "finished_at": now if state in ("ok","fail") else "",
  "log_path": "/var/lib/realmfp/update.log",
}
if state=="running":
  obj["started_at"]=now
  obj["finished_at"]=""
json.dump(obj, open(path,"w"), indent=2, ensure_ascii=False)
print(json.dumps(obj, ensure_ascii=False))
PY
}

: >"$LOG"
write_status running
{
  echo "==== $(date -u +%Y-%m-%dT%H:%M:%SZ) update start from=${from_ver} want=${want_tag:-latest} ===="
  if [[ ! -x /usr/local/bin/realmfp ]]; then
    echo "ERROR: /usr/local/bin/realmfp 不存在" >&2
    write_status fail "realmfp CLI 不存在"
    exit 1
  fi
  set +e
  if [[ -n "$want_tag" ]]; then
    /usr/local/bin/realmfp update "$want_tag"
  else
    /usr/local/bin/realmfp update
  fi
  rc=$?
  set -e
  echo "==== exit=$rc ===="
  if [[ $rc -eq 0 ]]; then
    write_status ok
  else
    write_status fail "realmfp update 退出码 $rc"
    exit "$rc"
  fi
} >>"$LOG" 2>&1
