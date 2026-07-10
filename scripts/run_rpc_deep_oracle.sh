#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/outputs"
mkdir -p "$OUT"

TARGET_ADDR="${TARGET_ADDR:-octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ}"
RPC_URL="${RPC_URL:-https://octra.network/rpc}"
DELAY_SECONDS="${DELAY_SECONDS:-2.0}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
IN_JSON="${IN_JSON:-$OUT/rpc_oracle.json}"
OUT_JSON="${OUT_JSON:-$OUT/rpc_deep_oracle.json}"
OUT_TXT="${OUT_TXT:-$OUT/rpc_deep_oracle_summary.txt}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

python3 - "$TARGET_ADDR" "$RPC_URL" "$DELAY_SECONDS" "$TIMEOUT_SECONDS" "$IN_JSON" "$OUT_JSON" "$OUT_TXT" <<'PY'
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

addr, rpc_url, delay_s, timeout_s, in_json, out_json, out_txt = sys.argv[1:8]
delay = float(delay_s)
timeout = int(float(timeout_s))

def rpc_call(method, params, req_id):
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "rowanhere-octra-hfhe-deep-oracle/1.0",
        },
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
            return {
                "ok": True,
                "http_status": resp.status,
                "elapsed_ms": round((time.time() - started) * 1000),
                "bytes": len(raw),
                "response": parsed,
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return {
            "ok": False,
            "http_status": exc.code,
            "elapsed_ms": round((time.time() - started) * 1000),
            "bytes": len(raw),
            "error": raw.decode("utf-8", "replace")[:4096],
        }
    except Exception as exc:
        return {"ok": False, "elapsed_ms": round((time.time() - started) * 1000), "error": repr(exc)}

def walk(obj):
    if isinstance(obj, dict):
        for value in obj.values():
            yield from walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from walk(value)
    else:
        yield obj

def extract_hashes(obj):
    hashes = []
    seen = set()
    for value in walk(obj):
        if not isinstance(value, str):
            continue
        for h in re.findall(r"\b[a-fA-F0-9]{64}\b", value):
            h = h.lower()
            if h not in seen:
                seen.add(h)
                hashes.append(h)
    return hashes

def result_of(call):
    resp = call.get("response")
    if isinstance(resp, dict):
        return resp.get("result")
    return None

seed = {}
try:
    with open(in_json, "r", encoding="utf-8") as f:
        seed = json.load(f)
except FileNotFoundError:
    seed = {"warning": f"{in_json} not found; run run_rpc_oracle.sh first for richer expansion"}

hashes = extract_hashes(seed)

methods = [
    ("octra_account", [addr, 100]),
    ("octra_transactionsByAddress", [addr, 1, 0]),
    ("octra_transactionsByAddress", [addr, 5, 0]),
    ("octra_transactionsByAddress", [addr, 50, 0]),
    ("octra_tokensByAddress", [addr]),
    ("octra_pvacStatus", [addr]),
    ("octra_pvacPubkey", [addr]),
    ("octra_viewPubkey", [addr]),
    ("octra_encryptedCipher", [addr]),
]

for h in hashes[:20]:
    methods.append(("octra_transaction", [h]))

doc = {
    "target_addr": addr,
    "rpc_url": rpc_url,
    "input_json": in_json,
    "started_utc": datetime.now(timezone.utc).isoformat(),
    "delay_seconds": delay,
    "hashes_from_input": hashes,
    "calls": [],
    "analysis": {},
}

for i, (method, params) in enumerate(methods, 1):
    call = rpc_call(method, params, i)
    doc["calls"].append({"method": method, "params": params, **call})
    if i != len(methods):
        time.sleep(delay)

doc["finished_utc"] = datetime.now(timezone.utc).isoformat()

all_json = {"seed": seed, "deep": doc}
all_hashes = extract_hashes(all_json)
doc["analysis"]["unique_hash_like_values"] = len(all_hashes)
doc["analysis"]["expanded_transaction_hashes"] = hashes[:20]

for call in doc["calls"]:
    if call["method"] == "octra_transactionsByAddress":
        result = result_of(call)
        if isinstance(result, dict):
            for key in ("transactions", "txs", "items"):
                if isinstance(result.get(key), list):
                    doc["analysis"][f"tx_page_{call['params'][1]}_{call['params'][2]}_count"] = len(result[key])
                    doc["analysis"][f"tx_page_{call['params'][1]}_{call['params'][2]}_keys"] = sorted(result.keys())
                    break
        elif isinstance(result, list):
            doc["analysis"][f"tx_page_{call['params'][1]}_{call['params'][2]}_count"] = len(result)
    if call["method"] in ("octra_viewPubkey", "octra_pvacPubkey", "octra_encryptedCipher"):
        result = result_of(call)
        if isinstance(result, dict):
            doc["analysis"][call["method"] + "_keys"] = sorted(result.keys())
        elif isinstance(result, str):
            doc["analysis"][call["method"] + "_string_len"] = len(result)

with open(out_json, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")

lines = []
lines.append(f"target={addr}")
lines.append(f"rpc_url={rpc_url}")
lines.append(f"hashes_from_input={len(hashes)}")
for call in doc["calls"]:
    status = call.get("http_status", "no_http")
    detail = "ok"
    resp = call.get("response")
    if isinstance(resp, dict) and "error" in resp:
        detail = json.dumps(resp["error"], sort_keys=True)
    elif call.get("error"):
        detail = call["error"]
    if len(detail) > 220:
        detail = detail[:220]
    lines.append(f"{call['method']} {json.dumps(call['params'], separators=(',', ':'))}: http={status} bytes={call.get('bytes', 0)} elapsed_ms={call.get('elapsed_ms')} {detail.replace(chr(10), ' ')}")
lines.append("analysis=" + json.dumps(doc["analysis"], sort_keys=True))

with open(out_txt, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print("\n".join(lines))
print(f"wrote {out_json}")
print(f"wrote {out_txt}")
PY
