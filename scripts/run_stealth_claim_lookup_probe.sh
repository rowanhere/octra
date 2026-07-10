#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/outputs"
mkdir -p "$OUT"

RPC_URL="${RPC_URL:-https://octra.network/rpc}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
STEALTH_JSON="${STEALTH_JSON:-$OUT/stealth_output_probe.json}"
OUT_JSON="$OUT/stealth_claim_lookup_probe.json"
OUT_TXT="$OUT/stealth_claim_lookup_probe.txt"

if [[ ! -f "$STEALTH_JSON" ]]; then
  echo "missing $STEALTH_JSON; run scripts/run_stealth_output_probe.sh first" >&2
  exit 1
fi

python3 - "$RPC_URL" "$TIMEOUT_SECONDS" "$STEALTH_JSON" "$OUT_JSON" "$OUT_TXT" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

rpc_url, timeout_s, stealth_s, out_json_s, out_txt_s = sys.argv[1:6]
timeout = int(float(timeout_s))
stealth_path = Path(stealth_s)
out_json = Path(out_json_s)
out_txt = Path(out_txt_s)

def rpc_call(method, params, req_id):
    body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}, separators=(",", ":")).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "rowanhere-octra-stealth-claim-lookup/1.0"},
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

doc_in = json.loads(stealth_path.read_text(encoding="utf-8"))
matches = doc_in.get("matches", [])
targets = []
for m in matches:
    if str(m.get("claimed", "")) != "1":
        continue
    targets.append({
        "id": m.get("id"),
        "claim_pub": m.get("claim_pub"),
        "tx_hash": m.get("tx_hash"),
    })

if not targets:
    raise SystemExit("no claimed matched stealth outputs in input")

methods = [
    ("octra_stealthOutput", "id_int"),
    ("octra_stealthOutput", "id_str"),
    ("octra_stealthOutputById", "id_int"),
    ("octra_stealthOutputById", "id_str"),
    ("octra_stealthClaim", "id_int"),
    ("octra_stealthClaim", "id_str"),
    ("octra_stealthClaimByOutput", "id_int"),
    ("octra_stealthClaimByOutput", "id_str"),
    ("octra_stealthOutputClaim", "id_int"),
    ("octra_stealthOutputClaim", "id_str"),
    ("octra_stealthClaimByPub", "claim_pub"),
    ("octra_stealthOutputByClaimPub", "claim_pub"),
    ("octra_transactionsByStealthOutput", "id_int"),
    ("octra_transactionsByStealthOutput", "id_str"),
]

calls = []
req_id = 1
for target in targets:
    for method, mode in methods:
        if mode == "id_int":
            try:
                param = int(str(target["id"]))
            except Exception:
                continue
        elif mode == "id_str":
            param = str(target["id"])
        elif mode == "claim_pub":
            param = target.get("claim_pub")
            if not param:
                continue
        else:
            continue
        call = rpc_call(method, [param], req_id)
        req_id += 1
        calls.append({"target": target, "method": method, "mode": mode, "params": [param], **call})
        time.sleep(0.05)

interesting = []
for call in calls:
    resp = call.get("response")
    text = json.dumps(resp, sort_keys=True) if isinstance(resp, (dict, list)) else str(resp)
    lower = text.lower()
    method_missing = "method not found" in lower or '"code": -32601' in lower
    empty = text in ("null", "{}", "[]", '""') or '"result": null' in lower
    if call.get("ok") and not method_missing and not empty and call.get("bytes", 0) > 120:
        interesting.append(call)

doc = {
    "rpc_url": rpc_url,
    "target_count": len(targets),
    "call_count": len(calls),
    "interesting_count": len(interesting),
    "calls": calls,
}
out_json.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    f"rpc_url={rpc_url}",
    f"target_count={len(targets)}",
    f"call_count={len(calls)}",
    f"interesting_count={len(interesting)}",
]
for call in interesting[:50]:
    resp = call.get("response")
    preview = json.dumps(resp, sort_keys=True) if isinstance(resp, (dict, list)) else str(resp)
    preview = preview.replace("\n", " ")[:500]
    lines.append(
        f"interesting id={call['target'].get('id')} method={call['method']} mode={call['mode']} "
        f"http={call.get('http_status', 'no_http')} bytes={call.get('bytes', 0)} {preview}"
    )
if not interesting:
    sample = calls[:10]
    for call in sample:
        resp = call.get("response")
        preview = json.dumps(resp, sort_keys=True) if isinstance(resp, (dict, list)) else str(resp or call.get("error", ""))
        preview = preview.replace("\n", " ")[:240]
        lines.append(
            f"sample id={call['target'].get('id')} method={call['method']} mode={call['mode']} "
            f"http={call.get('http_status', 'no_http')} bytes={call.get('bytes', 0)} {preview}"
        )

out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
print(f"wrote {out_json}")
print(f"wrote {out_txt}")
PY

