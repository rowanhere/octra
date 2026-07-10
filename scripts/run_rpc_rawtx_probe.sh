#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/outputs"
mkdir -p "$OUT"

TARGET_ADDR="${TARGET_ADDR:-octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ}"
SENDER_ADDR="${SENDER_ADDR:-oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb}"
TX_HASH="${TX_HASH:-ad1af0cf96a12105bb112b0f3f7275e8fbd713e2f6966d886f5ec2c04e514898}"
RPC_URL="${RPC_URL:-https://octra.network/rpc}"
DELAY_SECONDS="${DELAY_SECONDS:-2.0}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
OUT_JSON="${OUT_JSON:-$OUT/rpc_rawtx_probe.json}"
OUT_TXT="${OUT_TXT:-$OUT/rpc_rawtx_probe_summary.txt}"

python3 - "$TARGET_ADDR" "$SENDER_ADDR" "$TX_HASH" "$RPC_URL" "$DELAY_SECONDS" "$TIMEOUT_SECONDS" "$OUT_JSON" "$OUT_TXT" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

target, sender, tx_hash, rpc_url, delay_s, timeout_s, out_json, out_txt = sys.argv[1:9]
delay = float(delay_s)
timeout = int(float(timeout_s))

def rpc_call(method, params, req_id):
    body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}, separators=(",", ":")).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "rowanhere-octra-rawtx-probe/1.0"},
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", "replace")
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = text
            return {"ok": True, "http_status": resp.status, "elapsed_ms": round((time.time() - started) * 1000), "bytes": len(raw), "response": parsed}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return {"ok": False, "http_status": exc.code, "elapsed_ms": round((time.time() - started) * 1000), "bytes": len(raw), "error": raw.decode("utf-8", "replace")[:4096]}
    except Exception as exc:
        return {"ok": False, "elapsed_ms": round((time.time() - started) * 1000), "error": repr(exc)}

methods = [
    ("octra_account", [sender, 20]),
    ("octra_balance", [sender]),
    ("octra_publicKey", [sender]),
    ("octra_viewPubkey", [sender]),
    ("octra_pvacPubkey", [sender]),
    ("octra_encryptedCipher", [sender]),
    ("octra_transactionsByAddress", [sender, 10, 0]),
    ("octra_transaction", [tx_hash]),
    ("octra_transactionRaw", [tx_hash]),
    ("octra_rawTransaction", [tx_hash]),
    ("octra_getTransaction", [tx_hash]),
    ("octra_getRawTransaction", [tx_hash]),
    ("transaction", [tx_hash]),
    ("rawTransaction", [tx_hash]),
]

doc = {
    "target_addr": target,
    "sender_addr": sender,
    "tx_hash": tx_hash,
    "rpc_url": rpc_url,
    "started_utc": datetime.now(timezone.utc).isoformat(),
    "calls": [],
    "analysis": {},
}

for i, (method, params) in enumerate(methods, 1):
    call = rpc_call(method, params, i)
    doc["calls"].append({"method": method, "params": params, **call})
    if i != len(methods):
        time.sleep(delay)

doc["finished_utc"] = datetime.now(timezone.utc).isoformat()

interesting = []
for call in doc["calls"]:
    resp = call.get("response")
    if isinstance(resp, dict) and "result" in resp:
        result = resp["result"]
        if isinstance(result, dict):
            keys = sorted(result.keys())
            call["result_keys"] = keys
            for key in ("signature", "public_key", "message", "encrypted_data", "raw", "tx", "transaction"):
                value = result.get(key)
                if value not in (None, "", [], {}):
                    interesting.append({"method": call["method"], "key": key, "value_preview": str(value)[:240]})
        elif result not in (None, "", [], {}):
            interesting.append({"method": call["method"], "key": "result", "value_preview": str(result)[:240]})
doc["analysis"]["interesting_nonempty_fields"] = interesting

with open(out_json, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")

lines = [
    f"target={target}",
    f"sender={sender}",
    f"tx_hash={tx_hash}",
    f"rpc_url={rpc_url}",
]
for call in doc["calls"]:
    resp = call.get("response")
    detail = "ok"
    if isinstance(resp, dict) and "error" in resp:
        detail = json.dumps(resp["error"], sort_keys=True)
    elif call.get("error"):
        detail = call["error"]
    elif call.get("result_keys"):
        detail = "keys=" + ",".join(call["result_keys"])
    if len(detail) > 260:
        detail = detail[:260]
    lines.append(f"{call['method']} {json.dumps(call['params'], separators=(',', ':'))}: http={call.get('http_status', 'no_http')} bytes={call.get('bytes', 0)} elapsed_ms={call.get('elapsed_ms')} {detail.replace(chr(10), ' ')}")
lines.append("analysis=" + json.dumps(doc["analysis"], sort_keys=True))

with open(out_txt, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print("\n".join(lines))
print(f"wrote {out_json}")
print(f"wrote {out_txt}")
PY
