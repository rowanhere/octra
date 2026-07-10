#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/work"
OUT="$ROOT/outputs"
BUILD="$ROOT/build"
WEBCLI="$WORK/webcli"
HIST="$OUT/history_ciphers"
mkdir -p "$WORK" "$OUT" "$BUILD" "$HIST"
find "$HIST" -maxdepth 1 -type f -name '*.bin' -delete

SENDER_ADDR="${SENDER_ADDR:-oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb}"
RPC_URL="${RPC_URL:-https://octra.network/rpc}"
LIMIT="${LIMIT:-10}"
PAGES="${PAGES:-5}"
OFFSET_START="${OFFSET_START:-0}"
DELAY_SECONDS="${DELAY_SECONDS:-2.0}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-45}"

if [[ ! -d "$WEBCLI/.git" ]]; then
  git clone https://github.com/octra-labs/webcli.git "$WEBCLI"
else
  git -C "$WEBCLI" fetch --all --prune
  git -C "$WEBCLI" reset --hard origin/main
fi

python3 - "$SENDER_ADDR" "$RPC_URL" "$LIMIT" "$PAGES" "$OFFSET_START" "$DELAY_SECONDS" "$TIMEOUT_SECONDS" "$OUT" "$HIST" <<'PY'
import base64
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sender, rpc_url, limit_s, pages_s, offset_s, delay_s, timeout_s, out_s, hist_s = sys.argv[1:10]
limit = int(limit_s)
pages = int(pages_s)
offset_start = int(offset_s)
delay = float(delay_s)
timeout = int(float(timeout_s))
out = Path(out_s)
hist = Path(hist_s)

def rpc_call(method, params, req_id):
    body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}, separators=(",", ":")).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "rowanhere-octra-history-components/1.0"},
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", "replace")
            return {
                "ok": True,
                "http_status": resp.status,
                "elapsed_ms": round((time.time() - started) * 1000),
                "bytes": len(raw),
                "response": json.loads(text),
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return {"ok": False, "http_status": exc.code, "elapsed_ms": round((time.time() - started) * 1000), "bytes": len(raw), "error": raw.decode("utf-8", "replace")[:1000]}
    except Exception as exc:
        return {"ok": False, "elapsed_ms": round((time.time() - started) * 1000), "error": repr(exc)}

def decode_bytes(value):
    s = str(value).strip()
    if "|" in s:
        s = s.rsplit("|", 1)[-1].strip()
    elif "," in s:
        s = s.rsplit(",", 1)[-1].strip()
    compact = "".join(s.split())
    if compact.startswith("0x"):
        compact = compact[2:]
    if len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try:
            return bytes.fromhex(compact), "hex"
        except Exception:
            pass
    padded = compact + ("=" * ((4 - len(compact) % 4) % 4))
    for label, fn in (
        ("base64_strict", lambda x: base64.b64decode(x, validate=True)),
        ("base64_relaxed", lambda x: base64.b64decode(x, validate=False)),
        ("base64_urlsafe", lambda x: base64.urlsafe_b64decode(x)),
    ):
        try:
            raw = fn(padded)
            if raw:
                return raw, label
        except Exception:
            pass
    raise ValueError("could not decode field")

def write_blob(name, value):
    raw, enc = decode_bytes(value)
    path = out / name
    path.write_bytes(raw)
    return {"path": str(path), "encoding": enc, "raw_len": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def result_of(call):
    resp = call.get("response")
    if isinstance(resp, dict):
        return resp.get("result")
    return None

def parse_encrypted_data(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {"_raw": value}
    if isinstance(value, dict):
        return value
    return {}

def find_cipher_fields(obj, path="root"):
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}"
            key_l = str(key).lower()
            if isinstance(value, str):
                v = value.strip()
                looks_hfhe = "hfhe_" in v[:64].lower() or "hfhe_v1|" in v.lower()
                looks_cipher_key = "cipher" in key_l and len(v) > 100
                looks_wrapped_blob = len(v) > 1000 and ("|" in v[:64] or v.startswith(("PVAC", "pvac")))
                if looks_hfhe or looks_cipher_key or looks_wrapped_blob:
                    found.append((child_path, value))
                elif len(v) > 0 and v[0] in "{[":
                    try:
                        parsed = json.loads(v)
                    except Exception:
                        parsed = None
                    if parsed is not None:
                        found.extend(find_cipher_fields(parsed, child_path))
            elif isinstance(value, (dict, list)):
                found.extend(find_cipher_fields(value, child_path))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            found.extend(find_cipher_fields(value, f"{path}[{i}]"))
    return found

def compact_value(value, max_len=96):
    if value in (None, "", [], {}):
        return ""
    s = str(value)
    return s if len(s) <= max_len else s[:max_len]

def tx_amount_raw(tx):
    value = tx.get("amount_raw")
    if value in (None, ""):
        value = tx.get("amount")
    return compact_value(value)

def encrypted_meta(ed):
    if not isinstance(ed, dict):
        return {}
    keys = (
        "version", "output_id", "claim_pub", "claim_secret", "stealth_tag",
        "eph_pub", "enc_amount", "commitment", "amount_commitment",
    )
    return {k: compact_value(ed.get(k)) for k in keys if compact_value(ed.get(k))}

doc = {
    "sender_addr": sender,
    "rpc_url": rpc_url,
    "limit": limit,
    "pages": pages,
    "offset_start": offset_start,
    "started_utc": datetime.now(timezone.utc).isoformat(),
    "calls": [],
    "cipher_files": [],
}

req_id = 1
for method, params in (
    ("octra_pvacPubkey", [sender]),
    ("octra_encryptedCipher", [sender]),
):
    call = rpc_call(method, params, req_id)
    req_id += 1
    doc["calls"].append({"method": method, "params": params, "ok": call.get("ok"), "http_status": call.get("http_status"), "elapsed_ms": call.get("elapsed_ms"), "bytes": call.get("bytes"), "error": call.get("error")})
    res = result_of(call)
    if method == "octra_pvacPubkey" and isinstance(res, dict) and res.get("pvac_pubkey"):
        doc["pvac_pubkey"] = write_blob("sender_pvac_pubkey.bin", res["pvac_pubkey"])
    if method == "octra_encryptedCipher" and isinstance(res, dict) and res.get("cipher"):
        doc["current_cipher_type"] = res.get("cipher_type")
        doc["current_cipher"] = write_blob("sender_current_cipher.bin", res["cipher"])
    time.sleep(delay)

for page in range(pages):
    offset = offset_start + page * limit
    call = rpc_call("octra_transactionsByAddress", [sender, limit, offset], req_id)
    req_id += 1
    res = result_of(call)
    page_meta = {"method": "octra_transactionsByAddress", "params": [sender, limit, offset], "ok": call.get("ok"), "http_status": call.get("http_status"), "elapsed_ms": call.get("elapsed_ms"), "bytes": call.get("bytes"), "error": call.get("error")}
    txs = []
    if isinstance(res, dict):
        page_meta.update({k: res.get(k) for k in ("count", "total", "has_more", "rejected")})
        txs = res.get("transactions") or []
    doc["calls"].append(page_meta)
    for local_i, tx in enumerate(txs):
        if not isinstance(tx, dict):
            continue
        tx_hash = str(tx.get("tx_hash") or tx.get("hash") or f"offset{offset + local_i}")
        op_type = str(tx.get("op_type") or tx.get("type") or "tx")
        ed = parse_encrypted_data(tx.get("encrypted_data"))
        emeta = encrypted_meta(ed)
        for field, value in find_cipher_fields(ed, "encrypted_data"):
            try:
                raw, enc = decode_bytes(value)
            except Exception as exc:
                doc["cipher_files"].append({"tx_hash": tx_hash, "op_type": op_type, "field": field, "decode_error": str(exc), "encoded_len": len(str(value))})
                continue
            safe_op = re.sub(r"[^A-Za-z0-9_.-]+", "_", op_type)[:32]
            safe_field = re.sub(r"[^A-Za-z0-9_.-]+", "_", field)[-64:]
            name = f"{offset + local_i:08d}_{safe_op}_{tx_hash[:12]}_{safe_field}.bin"
            path = hist / name
            path.write_bytes(raw)
            doc["cipher_files"].append({
                "path": str(path),
                "tx_hash": tx_hash,
                "op_type": op_type,
                "field": field,
                "offset": offset + local_i,
                "encoding": enc,
                "encoded_len": len(str(value)),
                "raw_len": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "amount_raw": tx_amount_raw(tx),
                "from": compact_value(tx.get("from")),
                "to": compact_value(tx.get("to") or tx.get("to_")),
                "timestamp": compact_value(tx.get("timestamp")),
                "encrypted_meta": emeta,
            })
    if page + 1 < pages:
        time.sleep(delay)

doc["finished_utc"] = datetime.now(timezone.utc).isoformat()
summary_path = out / "sender_history_components.json"
summary_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    f"sender={sender}",
    f"rpc_url={rpc_url}",
    f"limit={limit}",
    f"pages={pages}",
    f"offset_start={offset_start}",
    f"cipher_files={len([x for x in doc['cipher_files'] if not x.get('decode_error')])}",
]
if "pvac_pubkey" in doc:
    lines.append(f"pvac_pubkey_raw_len={doc['pvac_pubkey']['raw_len']} sha256={doc['pvac_pubkey']['sha256']}")
if "current_cipher" in doc:
    lines.append(f"current_cipher_type={doc.get('current_cipher_type')} raw_len={doc['current_cipher']['raw_len']} sha256={doc['current_cipher']['sha256']}")
for call in doc["calls"]:
    lines.append(f"{call['method']} {json.dumps(call['params'], separators=(',', ':'))}: http={call.get('http_status', 'no_http')} bytes={call.get('bytes', 0)} elapsed_ms={call.get('elapsed_ms')} count={call.get('count', '')} total={call.get('total', '')} has_more={call.get('has_more', '')}")
for item in doc["cipher_files"][:80]:
    if item.get("decode_error"):
        lines.append(f"decode_error offset={item.get('offset')} field={item.get('field')} error={item.get('decode_error')}")
    else:
        lines.append(f"cipher offset={item['offset']} op={item['op_type']} field={item['field']} raw_len={item['raw_len']} sha256={item['sha256']} file={Path(item['path']).name}")

(out / "sender_history_components_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
print(f"wrote {summary_path}")
PY

if [[ ! -s "$OUT/sender_pvac_pubkey.bin" || ! -s "$OUT/sender_current_cipher.bin" ]]; then
  echo "missing decoded sender PVAC pubkey/current cipher; inspect $OUT/sender_history_components_summary.txt" >&2
  exit 1
fi

g++ -std=c++17 -O2 -march=native \
  -I"$WEBCLI/pvac/include" \
  -I"$WEBCLI/pvac" \
  "$ROOT/probes/webcli_cipher_oracle.cpp" \
  -o "$BUILD/webcli_cipher_oracle"

mapfile -t CIPHERS < <(find "$HIST" -maxdepth 1 -type f -name '*.bin' | sort)
if [[ "${#CIPHERS[@]}" -eq 0 ]]; then
  echo "no historical cipher blobs extracted; wrote $OUT/sender_history_components_summary.txt" >&2
  exit 0
fi

"$BUILD/webcli_cipher_oracle" \
  "$OUT/sender_pvac_pubkey.bin" \
  "${CIPHERS[@]}" \
  "$OUT/sender_current_cipher.bin" \
  | tee "$OUT/sender_history_component_scan.txt"

python3 - "$OUT/sender_history_components.json" "$OUT/sender_history_component_scan.txt" "$OUT" <<'PY'
import csv
import json
import re
import sys
from pathlib import Path

doc_path = Path(sys.argv[1])
scan_path = Path(sys.argv[2])
out = Path(sys.argv[3])

doc = json.loads(doc_path.read_text(encoding="utf-8"))
by_file = {}
for item in doc.get("cipher_files", []):
    path = item.get("path")
    if path and not item.get("decode_error"):
        by_file[Path(path).name] = item

rx = re.compile(
    r"^component_match source=(?P<source>\S+) target=(?P<target>\S+) "
    r"start_layer=(?P<start>\d+) layers=(?P<layers>\d+) edges=(?P<edges>\d+) "
    r"sign=(?P<sign>[+-]) public_nums=(?P<public_nums>.*)$"
)

rows = []
for line in scan_path.read_text(encoding="utf-8", errors="replace").splitlines():
    m = rx.match(line)
    if not m:
        continue
    d = m.groupdict()
    meta = by_file.get(d["source"], {})
    start = int(d["start"])
    layers = int(d["layers"])
    rows.append({
        "start_layer": start,
        "end_layer": start + layers - 1,
        "sign": d["sign"],
        "layers": layers,
        "edges": int(d["edges"]),
        "source_file": d["source"],
        "op_type": meta.get("op_type", ""),
        "field": meta.get("field", ""),
        "offset": meta.get("offset", ""),
        "tx_hash": meta.get("tx_hash", ""),
        "amount_raw": meta.get("amount_raw", ""),
        "from": meta.get("from", ""),
        "to": meta.get("to", ""),
        "timestamp": meta.get("timestamp", ""),
        "output_id": meta.get("encrypted_meta", {}).get("output_id", ""),
        "claim_pub": meta.get("encrypted_meta", {}).get("claim_pub", ""),
        "claim_secret": meta.get("encrypted_meta", {}).get("claim_secret", ""),
        "stealth_tag": meta.get("encrypted_meta", {}).get("stealth_tag", ""),
        "enc_amount": meta.get("encrypted_meta", {}).get("enc_amount", ""),
        "eph_pub": meta.get("encrypted_meta", {}).get("eph_pub", ""),
        "sha256": meta.get("sha256", ""),
        "public_nums": d["public_nums"],
    })

rows.sort(key=lambda r: r["start_layer"])
covered = set()
for row in rows:
    covered.update(range(row["start_layer"], row["end_layer"] + 1))

max_layer = max(covered) if covered else -1
missing_layers = [i for i in range(max_layer + 1) if i not in covered]
missing_windows = []
for i in range(0, max_layer + 1, 2):
    if i not in covered or i + 1 not in covered:
        missing_windows.append(f"{i}-{i+1}")

csv_path = out / "sender_component_ledger.csv"
with csv_path.open("w", newline="", encoding="utf-8") as f:
    fieldnames = [
        "start_layer", "end_layer", "sign", "layers", "edges", "offset",
        "op_type", "field", "amount_raw", "from", "to", "timestamp",
        "output_id", "claim_pub", "claim_secret", "stealth_tag", "enc_amount", "eph_pub",
        "tx_hash", "sha256",
        "source_file", "public_nums",
    ]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})

op_counts = {}
sign_counts = {}
for row in rows:
    op_counts[row["op_type"]] = op_counts.get(row["op_type"], 0) + 1
    sign_counts[row["sign"]] = sign_counts.get(row["sign"], 0) + 1

lines = [
    f"sender={doc.get('sender_addr', '')}",
    f"component_rows={len(rows)}",
    f"covered_layers={len(covered)}",
    f"max_layer={max_layer}",
    "missing_layers=" + (",".join(map(str, missing_layers)) if missing_layers else "none"),
    "missing_windows=" + (",".join(missing_windows) if missing_windows else "none"),
    "op_counts=" + json.dumps(op_counts, sort_keys=True),
    "sign_counts=" + json.dumps(sign_counts, sort_keys=True),
    "",
    "layer_range sign offset op_type field amount_raw to output_id claim_pub/secret tx_hash",
]
for row in rows:
    link = row["claim_pub"] or row["claim_secret"] or row["stealth_tag"] or ""
    lines.append(
        f"{row['start_layer']:02d}-{row['end_layer']:02d} {row['sign']} "
        f"{row['offset']} {row['op_type']} {row['field']} "
        f"{row['amount_raw']} {row['to']} {row['output_id']} "
        f"{str(link)[:16]} {str(row['tx_hash'])[:16]}"
    )

txt_path = out / "sender_component_ledger.txt"
txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"wrote {txt_path}")
print(f"wrote {csv_path}")
print("\n".join(lines[:9]))
PY
