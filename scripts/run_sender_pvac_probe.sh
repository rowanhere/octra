#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/work"
OUT="$ROOT/outputs"
BUILD="$ROOT/build"
WEBCLI="$WORK/webcli"
IN_JSON="${IN_JSON:-$OUT/rpc_rawtx_probe.json}"
mkdir -p "$WORK" "$OUT" "$BUILD"

if [[ ! -f "$IN_JSON" ]]; then
  echo "missing $IN_JSON; run scripts/run_rpc_rawtx_probe.sh first" >&2
  exit 1
fi

if [[ ! -d "$WEBCLI/.git" ]]; then
  git clone https://github.com/octra-labs/webcli.git "$WEBCLI"
else
  git -C "$WEBCLI" fetch --all --prune
  git -C "$WEBCLI" reset --hard origin/main
fi

python3 - "$IN_JSON" "$OUT" <<'PY'
import base64
import hashlib
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
out = Path(sys.argv[2])
doc = json.loads(src.read_text(encoding="utf-8"))

def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from walk(value)

sender_pub = None
view_pub = None
pvac_pk = None
cipher = None
cipher_type = None

for obj in walk(doc):
    if obj.get("method") == "octra_publicKey":
        res = obj.get("response", {}).get("result", {})
        sender_pub = res.get("public_key") or sender_pub
    if obj.get("method") == "octra_viewPubkey":
        res = obj.get("response", {}).get("result", {})
        view_pub = res.get("view_pubkey") or view_pub
    if obj.get("method") == "octra_pvacPubkey":
        res = obj.get("response", {}).get("result", {})
        pvac_pk = res.get("pvac_pubkey") or pvac_pk
    if obj.get("method") == "octra_encryptedCipher":
        res = obj.get("response", {}).get("result", {})
        cipher = res.get("cipher") or cipher
        cipher_type = res.get("cipher_type") or cipher_type

def decode_bytes(value):
    s = str(value).strip()
    for sep in (",", ":", "|"):
        if sep in s and not s.startswith("PVAC"):
            tail = s.rsplit(sep, 1)[-1].strip()
            if len(tail) > 16:
                s = tail
    compact = "".join(s.split())
    if compact.startswith("0x"):
        compact = compact[2:]
    if len(compact) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in compact):
        try:
            return bytes.fromhex(compact), "hex"
        except Exception:
            pass
    padded = compact + ("=" * ((4 - len(compact) % 4) % 4))
    attempts = [
        ("base64_strict", lambda x: base64.b64decode(x, validate=True)),
        ("base64_relaxed", lambda x: base64.b64decode(x, validate=False)),
        ("base64_urlsafe", lambda x: base64.urlsafe_b64decode(x)),
    ]
    errors = []
    for label, fn in attempts:
        try:
            raw = fn(padded)
            if raw:
                return raw, label
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    raise ValueError("; ".join(errors))

def decode_field(name, value):
    if value is None:
        return None
    try:
        raw, encoding = decode_bytes(value)
    except Exception as exc:
        return {
            "field": name,
            "decode_error": str(exc),
            "value_len": len(str(value)),
            "value_prefix": str(value)[:80],
        }
    path = out / f"sender_{name}.bin"
    path.write_bytes(raw)
    return {
        "field": name,
        "encoding": encoding,
        "encoded_len": len(str(value)),
        "raw_len": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "prefix_hex": raw[:16].hex(),
        "path": str(path),
    }

summary = {
    "source": str(src),
    "cipher_type": cipher_type,
    "fields": [
        decode_field("public_key", sender_pub),
        decode_field("view_pubkey", view_pub),
        decode_field("pvac_pubkey", pvac_pk),
        decode_field("cipher", cipher),
    ],
}
summary["fields"] = [x for x in summary["fields"] if x]
(out / "sender_pvac_extract.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

if [[ ! -s "$OUT/sender_pvac_pubkey.bin" || ! -s "$OUT/sender_cipher.bin" ]]; then
  echo "sender PVAC pubkey or cipher did not decode; inspect $OUT/sender_pvac_extract.json"
  exit 1
fi

cat > "$BUILD/sender_pvac_probe.cpp" <<'CPP'
#include <pvac/pvac.hpp>
#include "pvac_serialize.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace pvac;
namespace fs = std::filesystem;

static std::vector<uint8_t> read_all(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("open failed: " + p.string());
    in.seekg(0, std::ios::end);
    auto n = in.tellg();
    if (n < 0) throw std::runtime_error("size failed: " + p.string());
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> out((size_t)n);
    if (!out.empty()) in.read((char*)out.data(), n);
    if (!in) throw std::runtime_error("read failed: " + p.string());
    return out;
}

static bool zero(Fp x) {
    return x.lo == 0 && x.hi == 0;
}

static Fp signed_term(const PubKey& pk, const Edge& e, size_t slot) {
    Fp x = fp_mul(e.w[slot], pk.powg_B[e.idx]);
    return sgn_val(e.ch) > 0 ? x : fp_neg(x);
}

static Fp public_num(const PubKey& pk, const Cipher& c, uint32_t layer, size_t slot) {
    Fp acc = layer == 0 && !c.c0.empty() ? c.c0[slot] : fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != layer) continue;
        acc = fp_add(acc, signed_term(pk, e, slot));
    }
    return acc;
}

static void print_fp_short(const char* label, Fp x) {
    std::cout << label << "=" << std::hex << std::setw(16) << std::setfill('0') << x.lo
              << ":" << std::setw(16) << (x.hi & MASK63) << std::dec << std::setfill(' ') << "\n";
}

int main(int argc, char** argv) {
    try {
        fs::path out = argc > 1 ? fs::path(argv[1]) : fs::path("outputs");
        auto pkb = read_all(out / "sender_pvac_pubkey.bin");
        auto ctb = read_all(out / "sender_cipher.bin");
        PubKey pk = pvac_ser::deserialize_pubkey(pkb.data(), pkb.size());
        Cipher ct = pvac_ser::deserialize_cipher(ctb.data(), ctb.size());

        std::cout << "pk_raw_bytes=" << pkb.size() << "\n";
        std::cout << "cipher_raw_bytes=" << ctb.size() << "\n";
        std::cout << "pk_B=" << pk.prm.B << " m=" << pk.prm.m_bits << " n=" << pk.prm.n_bits
                  << " lpn_n=" << pk.prm.lpn_n << " lpn_t=" << pk.prm.lpn_t
                  << " tau=" << pk.prm.lpn_tau_num << "/" << pk.prm.lpn_tau_den << "\n";
        std::cout << "cipher_compatible=" << is_cipher_compatible_with_pubkey(pk, ct) << "\n";
        std::cout << "cipher_slots=" << ct.slots << " layers=" << ct.L.size() << " edges=" << ct.E.size()
                  << " c0=" << ct.c0.size() << "\n";

        size_t base = 0, prod = 0, pc_entries = 0, missing_pc = 0, pc_identity = 0;
        size_t public_zero_layers = 0;
        std::set<std::array<uint8_t, 32>> pcs;
        RistrettoPoint I = rist_identity();
        for (size_t i = 0; i < ct.L.size(); ++i) {
            const auto& L = ct.L[i];
            if (L.rule == RRule::BASE) ++base;
            if (L.rule == RRule::PROD) ++prod;
            if (L.PC.empty()) ++missing_pc;
            pc_entries += L.PC.size();
            for (const auto& pc : L.PC) {
                if (pc == I) ++pc_identity;
                pcs.insert(pc);
            }
            if (ct.slots > 0 && zero(public_num(pk, ct, (uint32_t)i, 0))) ++public_zero_layers;
        }
        std::cout << "base_layers=" << base << " product_layers=" << prod
                  << " pc_entries=" << pc_entries << " missing_pc_layers=" << missing_pc
                  << " pc_identity=" << pc_identity << " pc_duplicates=" << (pc_entries - pcs.size())
                  << " public_zero_layers_slot0=" << public_zero_layers << "\n";

        std::map<uint32_t, size_t> edge_by_layer;
        std::map<uint16_t, size_t> idx_count;
        size_t plus = 0, minus = 0, bad_sigma = 0;
        for (const auto& e : ct.E) {
            edge_by_layer[e.layer_id]++;
            idx_count[e.idx]++;
            if (e.ch == SGN_P) ++plus;
            if (e.ch == SGN_M) ++minus;
            if (e.s.nbits != (uint64_t)pk.prm.m_bits) ++bad_sigma;
        }
        std::cout << "sign_plus=" << plus << " sign_minus=" << minus << " bad_sigma=" << bad_sigma
                  << " idx_unique=" << idx_count.size() << "\n";
        for (size_t i = 0; i < ct.L.size() && i < 12; ++i) {
            std::cout << "layer[" << i << "] rule=" << (ct.L[i].rule == RRule::BASE ? "base" : "prod")
                      << " edges=" << edge_by_layer[(uint32_t)i] << " pc=" << ct.L[i].PC.size();
            if (ct.L[i].rule == RRule::PROD) std::cout << " parents=" << ct.L[i].pa << "," << ct.L[i].pb;
            std::cout << "\n";
            if (ct.slots > 0) print_fp_short("  public_num_slot0", public_num(pk, ct, (uint32_t)i, 0));
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error=" << e.what() << "\n";
        return 1;
    }
}
CPP

g++ -std=c++17 -O2 -march=native \
  -I"$WEBCLI/pvac/include" \
  -I"$WEBCLI/pvac" \
  "$BUILD/sender_pvac_probe.cpp" \
  -o "$BUILD/sender_pvac_probe"

"$BUILD/sender_pvac_probe" "$OUT" | tee "$OUT/sender_pvac_probe.txt"
