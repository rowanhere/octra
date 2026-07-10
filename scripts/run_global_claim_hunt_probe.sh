#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/outputs"
mkdir -p "$OUT"

RPC_URL="${RPC_URL:-https://octra.network/rpc}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-45}"
STEALTH_JSON="${STEALTH_JSON:-$OUT/stealth_output_probe.json}"
MAX_CALLS="${MAX_CALLS:-40}"
RECENT_LIMIT="${RECENT_LIMIT:-100}"
RECENT_PAGES="${RECENT_PAGES:-20}"
RECENT_OFFSET_START="${RECENT_OFFSET_START:-0}"
DELAY_SECONDS="${DELAY_SECONDS:-0.05}"
OUT_JSON="$OUT/global_claim_hunt_probe.json"
OUT_TXT="$OUT/global_claim_hunt_probe.txt"

if [[ ! -f "$STEALTH_JSON" ]]; then
  echo "missing $STEALTH_JSON; run scripts/run_stealth_output_probe.sh first" >&2
  exit 1
fi

python3 - "$RPC_URL" "$TIMEOUT_SECONDS" "$STEALTH_JSON" "$MAX_CALLS" "$RECENT_LIMIT" "$RECENT_PAGES" "$RECENT_OFFSET_START" "$DELAY_SECONDS" "$OUT_JSON" "$OUT_TXT" <<'PY'
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

rpc_url, timeout_s, stealth_s, max_calls_s, recent_limit_s, recent_pages_s, recent_offset_start_s, delay_s, out_json_s, out_txt_s = sys.argv[1:11]
timeout = int(float(timeout_s))
max_calls = int(max_calls_s)
recent_limit = int(recent_limit_s)
recent_pages = int(recent_pages_s)
recent_offset_start = int(recent_offset_start_s)
delay = float(delay_s)
stealth_path = Path(stealth_s)
out_json = Path(out_json_s)
out_txt = Path(out_txt_s)
domain = b"OCTRA_CLAIM_BIND_V1"

def rpc_call(method, params, req_id):
    body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}, separators=(",", ":")).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "rowanhere-octra-global-claim-hunt/1.0"},
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                parsed = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                parsed = raw.decode("utf-8", "replace")[:2000]
            return {"ok": True, "http_status": resp.status, "elapsed_ms": round((time.time() - started) * 1000), "bytes": len(raw), "response": parsed}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return {"ok": False, "http_status": exc.code, "elapsed_ms": round((time.time() - started) * 1000), "bytes": len(raw), "error": raw.decode("utf-8", "replace")[:2000]}
    except Exception as exc:
        return {"ok": False, "elapsed_ms": round((time.time() - started) * 1000), "error": repr(exc)}

def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)

def first_value_for_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for value in obj.values():
            found = first_value_for_key(value, key)
            if found not in (None, ""):
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = first_value_for_key(value, key)
            if found not in (None, ""):
                return found
    return None

def parse_encrypted_data(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value[:1] in "{[":
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}

def txs_from_response(resp):
    root = resp.get("result") if isinstance(resp, dict) else resp
    txs = []
    for obj in walk(root):
        if not isinstance(obj, dict):
            continue
        if isinstance(obj.get("transactions"), list):
            txs.extend(x for x in obj["transactions"] if isinstance(x, dict))
        if isinstance(obj.get("txs"), list):
            txs.extend(x for x in obj["txs"] if isinstance(x, dict))
        if any(k in obj for k in ("tx_hash", "hash")) and any(k in obj for k in ("op_type", "encrypted_data")):
            txs.append(obj)
    seen = set()
    out = []
    for tx in txs:
        key = str(tx.get("tx_hash") or tx.get("hash") or id(tx))
        if key in seen:
            continue
        seen.add(key)
        out.append(tx)
    return out

stealth_doc = json.loads(stealth_path.read_text(encoding="utf-8"))
wanted = {}
for m in stealth_doc.get("matches", []):
    cp = str(m.get("claim_pub", "")).lower()
    if cp:
        wanted[cp] = m

methods = [
    ("octra_recentTransactions", [[recent_limit, recent_offset_start + i * recent_limit] for i in range(recent_pages)]),
    ("octra_transactions", [[100, 0], [50, 0], []]),
    ("octra_recentTransactions", [[100], [50], []]),
    ("octra_latestTransactions", [[100], [50], []]),
    ("octra_allTransactions", [[100, 0], [50, 0], []]),
    ("octra_transactionsRecent", [[100], [50], []]),
    ("transactions", [[100, 0], [50, 0], []]),
    ("recentTransactions", [[100], [50], []]),
    ("latestTransactions", [[100], [50], []]),
    ("octra_blocks", [[10], []]),
    ("octra_latestBlocks", [[10], []]),
]

calls = []
matches = []
claims_seen = []
claim_op_rows = 0
claim_debug = []
op_counts = {}
epoch_min = None
epoch_max = None
req_id = 1

for method, param_sets in methods:
    for params in param_sets:
        if len(calls) >= max_calls:
            break
        call = rpc_call(method, params, req_id)
        req_id += 1
        txs = txs_from_response(call.get("response"))
        calls.append({k: call.get(k) for k in ("ok", "http_status", "elapsed_ms", "bytes", "error")} | {"method": method, "params": params, "tx_count": len(txs), "response_preview": json.dumps(call.get("response"), sort_keys=True)[:500] if call.get("response") is not None else ""})
        for tx in txs:
            op = str(tx.get("op_type") or tx.get("type") or "")
            if op:
                op_counts[op] = op_counts.get(op, 0) + 1
            try:
                epoch = int(tx.get("epoch") if tx.get("epoch") is not None else tx.get("epoch_id"))
                epoch_min = epoch if epoch_min is None else min(epoch_min, epoch)
                epoch_max = epoch if epoch_max is None else max(epoch_max, epoch)
            except Exception:
                pass
            ed = parse_encrypted_data(tx.get("encrypted_data"))
            secret_hex = first_value_for_key(ed, "claim_secret")
            if secret_hex in (None, ""):
                secret_hex = first_value_for_key(tx, "claim_secret")
            if op == "claim":
                claim_op_rows += 1
                if len(claim_debug) < 20:
                    enc_preview = tx.get("encrypted_data")
                    if isinstance(enc_preview, str):
                        enc_preview = enc_preview[:500]
                    claim_debug.append({
                        "from": tx.get("from") or tx.get("address"),
                        "tx_hash": tx.get("tx_hash") or tx.get("hash"),
                        "keys": sorted(tx.keys()),
                        "encrypted_data_preview": enc_preview,
                        "parsed_encrypted_keys": sorted(ed.keys()) if isinstance(ed, dict) else [],
                        "secret_found": bool(secret_hex),
                    })
            if op != "claim" and not secret_hex:
                continue
            from_addr = str(tx.get("from") or tx.get("address") or "")
            if not from_addr.startswith("oct"):
                continue
            try:
                secret = bytes.fromhex(str(secret_hex))
            except Exception:
                continue
            if len(secret) != 32:
                continue
            claim_pub = hashlib.sha256(secret + from_addr.encode("utf-8") + domain).hexdigest()
            item = {
                "from": from_addr,
                "tx_hash": tx.get("tx_hash") or tx.get("hash"),
                "output_id": ed.get("output_id"),
                "derived_claim_pub": claim_pub,
                "method": method,
            }
            claims_seen.append(item)
            if claim_pub in wanted:
                item["matched_stealth_output"] = wanted[claim_pub]
                matches.append(item)
        time.sleep(delay)
    if len(calls) >= max_calls:
        break

doc = {
    "rpc_url": rpc_url,
    "wanted_claim_pubs": sorted(wanted),
    "call_count": len(calls),
    "recent_limit": recent_limit,
    "recent_pages": recent_pages,
    "recent_offset_start": recent_offset_start,
    "epoch_min": epoch_min,
    "epoch_max": epoch_max,
    "op_counts": op_counts,
    "claim_op_rows": claim_op_rows,
    "claim_secret_rows_seen": len(claims_seen),
    "claim_debug": claim_debug,
    "matches": matches,
    "calls": calls,
}
out_json.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    f"rpc_url={rpc_url}",
    f"wanted_claim_pubs={len(wanted)}",
    f"call_count={len(calls)}",
    f"recent_limit={recent_limit}",
    f"recent_pages={recent_pages}",
    f"recent_offset_start={recent_offset_start}",
    f"epoch_min={epoch_min}",
    f"epoch_max={epoch_max}",
    "op_counts=" + json.dumps(op_counts, sort_keys=True),
    f"claim_op_rows={claim_op_rows}",
    f"claim_secret_rows_seen={len(claims_seen)}",
    f"matches={len(matches)}",
]
for item in claim_debug[:10]:
    lines.append(
        "claim_sample "
        f"tx={str(item.get('tx_hash'))[:16]} from={item.get('from')} "
        f"secret_found={item.get('secret_found')} keys={','.join(item.get('keys', []))} "
        f"parsed_keys={','.join(item.get('parsed_encrypted_keys', []))} "
        f"edata={str(item.get('encrypted_data_preview'))[:220].replace(chr(10), ' ')}"
    )
for call in calls:
    if call.get("tx_count") or (call.get("bytes", 0) > 150 and "method not found" not in call.get("response_preview", "").lower()):
        lines.append(
            f"call method={call['method']} params={json.dumps(call['params'])} "
            f"http={call.get('http_status','no_http')} bytes={call.get('bytes',0)} tx_count={call.get('tx_count',0)} "
            f"preview={call.get('response_preview','')[:240]}"
        )
for m in matches:
    st = m.get("matched_stealth_output", {})
    lines.append(
        f"match claim_tx={str(m.get('tx_hash'))[:16]} claimer={m.get('from')} output_id={m.get('output_id')} "
        f"stealth_tx={str(st.get('tx_hash'))[:16]} claim_pub={m.get('derived_claim_pub')[:16]}"
    )

out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
print(f"wrote {out_json}")
print(f"wrote {out_txt}")
PY
