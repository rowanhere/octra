#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <pvac/pvac.hpp>
#include <pvac/core/pvac_compress.hpp>

namespace pvac_ser {

static constexpr uint8_t MAGIC[4] = {'P', 'V', 'A', 'C'};
static constexpr uint8_t VERSION = 0x03;
static constexpr uint8_t TAG_CIPHER = 0;
static constexpr uint8_t TAG_PUBKEY = 1;
static constexpr uint8_t MAX_TAG = 6;
static constexpr uint64_t MAX_BITVEC_BITS = 1ULL << 20;

struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool failed = false;
    char error[128]{};

    Reader(const uint8_t* data, size_t len) : p(data), end(data + len) {}

    void fail(const char* msg) {
        if (!failed) {
            failed = true;
            std::snprintf(error, sizeof(error), "%s", msg);
        }
    }

    void need(size_t n) {
        if (!failed && p + n > end) fail("pvac_ser: truncated");
    }

    size_t remaining() const { return (size_t)(end - p); }

    void check_count(size_t count, size_t elem_bytes) {
        if (failed) return;
        if (elem_bytes && count > remaining() / elem_bytes) fail("pvac_ser: count exceeds remaining");
        if (count > (1ULL << 24)) fail("pvac_ser: count exceeds maximum");
    }

    uint8_t u8() { need(1); return failed ? 0 : *p++; }
    uint16_t u16() { need(2); if (failed) return 0; uint16_t v = p[0] | ((uint16_t)p[1] << 8); p += 2; return v; }
    uint32_t u32() { need(4); if (failed) return 0; uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= ((uint32_t)p[i]) << (8 * i); p += 4; return v; }
    uint64_t u64() { need(8); if (failed) return 0; uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i); p += 8; return v; }
    int32_t i32() { return (int32_t)u32(); }
    double f64() { uint64_t bits = u64(); double v; std::memcpy(&v, &bits, 8); return v; }

    void raw(uint8_t* out, size_t n) {
        need(n);
        if (failed) { std::memset(out, 0, n); return; }
        std::memcpy(out, p, n);
        p += n;
    }

    pvac::Fp fp() {
        uint64_t lo = u64();
        uint64_t hi = u64() & pvac::MASK63;
        return pvac::Fp{lo, hi};
    }

    pvac::RistrettoPoint rist_point() {
        pvac::RistrettoPoint pt;
        raw(pt.data(), 32);
        if (!failed) {
            pvac::ExtPoint decoded;
            if (!pvac::rist_decode(decoded, pt)) fail("pvac_ser: invalid Ristretto point");
        }
        return pt;
    }

    pvac::BitVec bitvec() {
        pvac::BitVec bv;
        bv.nbits = u64();
        size_t nw = u64();
        if (!failed && bv.nbits > MAX_BITVEC_BITS) fail("pvac_ser: bitvec too large");
        check_count(nw, 8);
        size_t expected = (size_t)((bv.nbits + 63) / 64);
        if (!failed && nw != expected) fail("pvac_ser: bitvec word count mismatch");
        if (failed) return bv;
        bv.w.resize(nw);
        for (size_t i = 0; i < nw; ++i) bv.w[i] = u64();
        return bv;
    }

    uint8_t header(uint8_t expected) {
        uint8_t m[4];
        raw(m, 4);
        if (failed) return 0;
        if (std::memcmp(m, MAGIC, 4) != 0) { fail("pvac_ser: bad magic"); return 0; }
        uint8_t ver = u8();
        if (ver != VERSION) { fail("pvac_ser: bad version"); return 0; }
        uint8_t tag = u8();
        if (tag > MAX_TAG || tag != expected) { fail("pvac_ser: wrong type tag"); return 0; }
        return ver;
    }
};

inline pvac::Params read_params(Reader& r) {
    pvac::Params prm;
    prm.B = r.i32();
    prm.m_bits = r.i32();
    prm.n_bits = r.i32();
    prm.h_col_wt = r.i32();
    prm.x_col_wt = r.i32();
    prm.err_wt = r.i32();
    prm.noise_entropy_bits = r.f64();
    prm.tuple2_fraction = r.f64();
    prm.depth_slope_bits = r.f64();
    prm.edge_budget = r.u64();
    prm.lpn_n = r.i32();
    prm.lpn_t = r.i32();
    prm.lpn_tau_num = r.i32();
    prm.lpn_tau_den = r.i32();
    return prm;
}

inline pvac::Layer read_layer(Reader& r) {
    pvac::Layer L{};
    L.rule = (pvac::RRule)r.u8();
    if (L.rule == pvac::RRule::BASE) {
        L.seed.ztag = r.u64();
        L.seed.nonce.lo = r.u64();
        L.seed.nonce.hi = r.u64();
    } else {
        L.pa = r.u32();
        L.pb = r.u32();
    }
    size_t nPC = r.u64();
    r.check_count(nPC, 32);
    if (!r.failed) {
        L.PC.resize(nPC);
        for (size_t i = 0; i < nPC; ++i) L.PC[i] = r.rist_point();
    }
    return L;
}

inline pvac::Edge read_edge(Reader& r) {
    pvac::Edge e;
    e.layer_id = r.u32();
    e.idx = r.u16();
    e.ch = r.u8();
    size_t nw = r.u64();
    r.check_count(nw, 16);
    if (!r.failed) {
        e.w.resize(nw);
        for (size_t i = 0; i < nw; ++i) e.w[i] = r.fp();
    }
    e.s = r.bitvec();
    return e;
}

inline void validate_cipher_structure(const pvac::Cipher& c) {
    if (c.slots == 0) throw std::runtime_error("pvac_ser: zero slots");
    if (!c.c0.empty() && c.c0.size() != c.slots) throw std::runtime_error("pvac_ser: c0/slots mismatch");
    for (size_t i = 0; i < c.L.size(); ++i) {
        const auto& L = c.L[i];
        if (L.rule != pvac::RRule::BASE && L.rule != pvac::RRule::PROD) throw std::runtime_error("pvac_ser: bad layer rule");
        if (L.rule == pvac::RRule::PROD && (L.pa >= i || L.pb >= i)) throw std::runtime_error("pvac_ser: bad product parent");
        if (!L.PC.empty() && L.PC.size() != c.slots) throw std::runtime_error("pvac_ser: PC/slots mismatch");
    }
    for (const auto& e : c.E) {
        if (e.layer_id >= c.L.size()) throw std::runtime_error("pvac_ser: edge layer out of range");
        if (e.ch != pvac::SGN_P && e.ch != pvac::SGN_M) throw std::runtime_error("pvac_ser: bad edge sign");
        if (e.w.size() != c.slots) throw std::runtime_error("pvac_ser: edge slots mismatch");
    }
}

inline pvac::Cipher deserialize_cipher(const uint8_t* data, size_t len) {
    Reader r(data, len);
    r.header(TAG_CIPHER);
    pvac::Cipher c;
    c.slots = r.u64();
    size_t nL = r.u64();
    r.check_count(nL, 8);
    if (!r.failed) {
        c.L.resize(nL);
        for (size_t i = 0; i < nL; ++i) c.L[i] = read_layer(r);
    }
    size_t nc = r.u64();
    r.check_count(nc, 16);
    if (!r.failed) {
        c.c0.resize(nc);
        for (size_t i = 0; i < nc; ++i) c.c0[i] = r.fp();
    }
    size_t nE = r.u64();
    r.check_count(nE, 8);
    if (!r.failed) {
        c.E.resize(nE);
        for (size_t i = 0; i < nE; ++i) c.E[i] = read_edge(r);
    }
    if (r.failed) throw std::runtime_error(r.error);
    validate_cipher_structure(c);
    return c;
}

inline void validate_pubkey_structure(const pvac::PubKey& pk) {
    if (pk.prm.B <= 0 || pk.prm.m_bits <= 0 || pk.prm.n_bits <= 0) throw std::runtime_error("pvac_ser: bad params");
    if (pk.H.size() != (size_t)pk.prm.n_bits) throw std::runtime_error("pvac_ser: H count mismatch");
    if (pk.ubk.perm.size() != (size_t)pk.prm.m_bits || pk.ubk.inv.size() != (size_t)pk.prm.m_bits) throw std::runtime_error("pvac_ser: UBK mismatch");
    if (pk.powg_B.size() != (size_t)pk.prm.B) throw std::runtime_error("pvac_ser: powg_B mismatch");
    for (const auto& h : pk.H) {
        if (h.nbits != (uint64_t)pk.prm.m_bits) throw std::runtime_error("pvac_ser: H bit length mismatch");
    }
}

inline pvac::PubKey deserialize_pubkey_raw(const uint8_t* data, size_t len) {
    Reader r(data, len);
    r.header(TAG_PUBKEY);
    pvac::PubKey pk;
    pk.prm = read_params(r);
    pk.canon_tag = r.u64();
    size_t nH = r.u64();
    r.check_count(nH, 8);
    if (!r.failed) {
        pk.H.resize(nH);
        for (size_t i = 0; i < nH; ++i) pk.H[i] = r.bitvec();
    }
    size_t np = r.u64();
    r.check_count(np, 4);
    if (!r.failed) {
        pk.ubk.perm.resize(np);
        for (size_t i = 0; i < np; ++i) pk.ubk.perm[i] = r.i32();
    }
    size_t ni = r.u64();
    r.check_count(ni, 4);
    if (!r.failed) {
        pk.ubk.inv.resize(ni);
        for (size_t i = 0; i < ni; ++i) pk.ubk.inv[i] = r.i32();
    }
    r.raw(pk.H_digest.data(), 32);
    pk.omega_B = r.fp();
    size_t ng = r.u64();
    r.check_count(ng, 16);
    if (!r.failed) {
        pk.powg_B.resize(ng);
        for (size_t i = 0; i < ng; ++i) pk.powg_B[i] = r.fp();
    }
    if (r.failed) throw std::runtime_error(r.error);
    validate_pubkey_structure(pk);
    return pk;
}

inline pvac::PubKey deserialize_pubkey(const uint8_t* data, size_t len) {
    if (pvac::compress::is_packed(data, len)) {
        auto raw = pvac::compress::unpack(data, len);
        return deserialize_pubkey_raw(raw.data(), raw.size());
    }
    return deserialize_pubkey_raw(data, len);
}

}

