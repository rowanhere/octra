#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/outputs"
mkdir -p "$OUT"

TARGET_ADDR="${TARGET_ADDR:-octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ}"
RPC_URL="${RPC_URL:-https://octra.network/rpc}"
DELAY_SECONDS="${DELAY_SECONDS:-2.0}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
OUT_JSON="${OUT_JSON:-$OUT/rpc_oracle.json}"
OUT_TXT="${OUT_TXT:-$OUT/rpc_oracle_summary.txt}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

python3 - "$TARGET_ADDR" "$RPC_URL" "$DELAY_SECONDS" "$TIMEOUT_SECONDS" "$OUT_JSON" "$OUT_TXT" <<'PY'
import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

addr, rpc_url, delay_s, timeout_s, out_json, out_txt = sys.argv[1:7]
delay = float(delay_s)
timeout = int(float(timeout_s))

methods = [
    ("octra_account", [addr, 20]),
    ("octra_balance", [addr]),
    ("octra_publicKey", [addr]),
    ("octra_viewPubkey", [addr]),
    ("octra_pvacPubkey", [addr]),
    ("octra_encryptedCipher", [addr]),
    ("octra_transactionsByAddress", [addr, 50, 0]),
]

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    pad = 0
    for b in raw:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "1")

def derive_octra_address(pub_b64: str):
    try:
        pk = base64.b64decode(pub_b64, validate=True)
    except Exception as exc:
        return {"ok": False, "error": f"base64 decode failed: {exc}"}
    if len(pk) != 32:
        return {"ok": False, "error": f"decoded public key length is {len(pk)}, expected 32"}
    digest = hashlib.sha256(pk).digest()
    body = b58encode(digest)
    if len(body) < 44:
        body = body.rjust(44, "1")
    return {"ok": True, "address": "oct" + body, "sha256_hex": digest.hex()}

def rpc_call(method, params, req_id):
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params,
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "rowanhere-octra-hfhe-oracle/1.0",
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
                parsed = None
            return {
                "ok": True,
                "http_status": resp.status,
                "elapsed_ms": round((time.time() - started) * 1000),
                "bytes": len(raw),
                "response": parsed if parsed is not None else text,
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
        return {
            "ok": False,
            "elapsed_ms": round((time.time() - started) * 1000),
            "error": repr(exc),
        }

doc = {
    "target_addr": addr,
    "rpc_url": rpc_url,
    "started_utc": datetime.now(timezone.utc).isoformat(),
    "delay_seconds": delay,
    "calls": [],
    "analysis": {},
}

for i, (method, params) in enumerate(methods, 1):
    result = rpc_call(method, params, i)
    doc["calls"].append({"method": method, "params": params, **result})
    if i != len(methods):
        time.sleep(delay)

doc["finished_utc"] = datetime.now(timezone.utc).isoformat()

by_method = {c["method"]: c for c in doc["calls"]}
pub_resp = by_method.get("octra_publicKey", {}).get("response")
if isinstance(pub_resp, dict) and "result" in pub_resp:
    result = pub_resp["result"]
    if isinstance(result, str):
        doc["analysis"]["public_key_address_check"] = derive_octra_address(result)
    elif isinstance(result, dict):
        for key in ("public_key", "pubkey", "publicKey", "pub_b64"):
            if isinstance(result.get(key), str):
                doc["analysis"]["public_key_address_check"] = derive_octra_address(result[key])
                break

tx_resp = by_method.get("octra_transactionsByAddress", {}).get("response")
if isinstance(tx_resp, dict) and "result" in tx_resp:
    txs = tx_resp["result"]
    if isinstance(txs, list):
        doc["analysis"]["transaction_count_returned"] = len(txs)
    elif isinstance(txs, dict):
        for key in ("transactions", "txs", "items"):
            if isinstance(txs.get(key), list):
                doc["analysis"]["transaction_count_returned"] = len(txs[key])
                break

with open(out_json, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")

lines = []
lines.append(f"target={addr}")
lines.append(f"rpc_url={rpc_url}")
for call in doc["calls"]:
    status = call.get("http_status", "no_http")
    err = call.get("error", "")
    response = call.get("response")
    rpc_error = ""
    if isinstance(response, dict) and "error" in response:
        rpc_error = json.dumps(response["error"], sort_keys=True)
    detail = rpc_error or (err[:180].replace("\n", " ") if err else "ok")
    lines.append(f"{call['method']}: http={status} bytes={call.get('bytes', 0)} elapsed_ms={call.get('elapsed_ms')} {detail}")
if doc["analysis"]:
    lines.append("analysis=" + json.dumps(doc["analysis"], sort_keys=True))
with open(out_txt, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print("\n".join(lines))
print(f"wrote {out_json}")
print(f"wrote {out_txt}")
PY
