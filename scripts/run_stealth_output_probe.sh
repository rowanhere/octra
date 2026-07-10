#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/outputs"
mkdir -p "$OUT"

RPC_URL="${RPC_URL:-https://octra.network/rpc}"
FROM_EPOCH="${FROM_EPOCH:-0}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
LINKS_JSON="${LINKS_JSON:-$OUT/sender_stealth_claim_links.json}"
OUT_JSON="$OUT/stealth_output_probe.json"
OUT_TXT="$OUT/stealth_output_probe.txt"

if [[ ! -f "$LINKS_JSON" ]]; then
  echo "missing $LINKS_JSON; run scripts/run_sender_history_components.sh first" >&2
  exit 1
fi

python3 - "$RPC_URL" "$FROM_EPOCH" "$TIMEOUT_SECONDS" "$LINKS_JSON" "$OUT_JSON" "$OUT_TXT" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

rpc_url, from_epoch_s, timeout_s, links_s, out_json_s, out_txt_s = sys.argv[1:7]
from_epoch = int(from_epoch_s)
timeout = int(float(timeout_s))
links_path = Path(links_s)
out_json = Path(out_json_s)
out_txt = Path(out_txt_s)

def rpc_call(method, params, req_id):
    body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}, separators=(",", ":")).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "rowanhere-octra-stealth-output-probe/1.0"},
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return {
                "ok": True,
                "http_status": resp.status,
                "elapsed_ms": round((time.time() - started) * 1000),
                "bytes": len(raw),
                "response": json.loads(raw.decode("utf-8", "replace")),
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return {"ok": False, "http_status": exc.code, "elapsed_ms": round((time.time() - started) * 1000), "bytes": len(raw), "error": raw.decode("utf-8", "replace")[:2000]}
    except Exception as exc:
        return {"ok": False, "elapsed_ms": round((time.time() - started) * 1000), "error": repr(exc)}

links = json.loads(links_path.read_text(encoding="utf-8"))
wanted = {}
for item in links.get("unclaimed_stealth_sends", []):
    cp = str(item.get("claim_pub", "")).lower()
    if cp:
        wanted[cp] = item
for item in links.get("links", []):
    cp = str(item.get("claim_pub", "")).lower()
    if cp:
        wanted[cp] = item

call = rpc_call("octra_stealthOutputs", [from_epoch], 1)
result = call.get("response", {}).get("result") if isinstance(call.get("response"), dict) else None
outputs = []
if isinstance(result, dict):
    outputs = result.get("outputs") or []
elif isinstance(result, list):
    outputs = result

matches = []
key_counts = {}
for out in outputs:
    if not isinstance(out, dict):
        continue
    for k in out.keys():
        key_counts[k] = key_counts.get(k, 0) + 1
    cp = str(out.get("claim_pub", "")).lower()
    if cp in wanted:
        compact = {}
        for k, v in out.items():
            s = str(v)
            compact[k] = s if len(s) <= 180 else s[:180]
        compact["matched_sender_item"] = wanted[cp]
        matches.append(compact)

doc = {
    "rpc_url": rpc_url,
    "from_epoch": from_epoch,
    "call": {k: call.get(k) for k in ("ok", "http_status", "elapsed_ms", "bytes", "error")},
    "output_count": len(outputs),
    "output_key_counts": key_counts,
    "wanted_claim_pubs": sorted(wanted.keys()),
    "matches": matches,
}
out_json.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    f"rpc_url={rpc_url}",
    f"from_epoch={from_epoch}",
    f"http={call.get('http_status', 'no_http')} bytes={call.get('bytes', 0)} elapsed_ms={call.get('elapsed_ms')} ok={call.get('ok')}",
    f"output_count={len(outputs)}",
    "output_keys=" + ",".join(sorted(key_counts)),
    f"wanted_claim_pubs={len(wanted)}",
    f"matches={len(matches)}",
]
for m in matches:
    sender_item = m.get("matched_sender_item", {})
    fields = [
        f"claim_pub={str(m.get('claim_pub',''))[:16]}",
        f"id={m.get('id', '')}",
        f"claimed={m.get('claimed', '')}",
        f"sender_offset={sender_item.get('stealth_offset', sender_item.get('claim_offset', ''))}",
        f"sender_layer={sender_item.get('stealth_layer', sender_item.get('claim_layer', ''))}",
    ]
    for optional in ("claim_tx", "claim_tx_hash", "spent_tx", "spent_by", "owner", "recipient", "to", "created_tx", "tx_hash", "epoch"):
        if optional in m:
            fields.append(f"{optional}={str(m[optional])[:32]}")
    lines.append("match " + " ".join(fields))

out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
print(f"wrote {out_json}")
print(f"wrote {out_txt}")
PY

