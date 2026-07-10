#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <vector>

using namespace pvac;
namespace fs = std::filesystem;

static constexpr std::array<uint8_t, 16> MAGIC = {
    'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
};

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

static uint64_t take_u64(const std::vector<uint8_t>& b, size_t& p) {
    if (p + 8 > b.size()) throw std::runtime_error("truncated bundle");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)b[p++] << (8 * i);
    return v;
}

static std::vector<Cipher> read_bundle(const std::vector<uint8_t>& b) {
    if (b.size() < MAGIC.size() || !std::equal(MAGIC.begin(), MAGIC.end(), b.begin()))
        throw std::runtime_error("bad bundle magic");
    size_t p = MAGIC.size();
    uint64_t count = take_u64(b, p);
    if (count == 0 || count > 4096) throw std::runtime_error("bad cipher count");
    std::vector<Cipher> cts;
    cts.reserve((size_t)count);
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t n = take_u64(b, p);
        if (!n || n > b.size() - p) throw std::runtime_error("bad cipher length");
        cts.push_back(pvac_ser::deserialize_cipher(b.data() + p, (size_t)n));
        p += (size_t)n;
    }
    if (p != b.size()) throw std::runtime_error("trailing bundle bytes");
    return cts;
}

static bool zero(Fp x) {
    return x.lo == 0 && x.hi == 0;
}

static Fp public_num_slot0(const PubKey& pk, const Cipher& c, uint32_t layer) {
    Fp acc = layer == 0 && !c.c0.empty() ? c.c0[0] : fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != layer) continue;
        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
    }
    return acc;
}

static int r2_zero_pairs(const PubKey& pk, const Cipher& c, uint32_t layer) {
    std::vector<const Edge*> edges;
    for (const auto& e : c.E) {
        if (e.layer_id == layer) edges.push_back(&e);
    }

    int hits = 0;
    for (size_t i = 0; i < edges.size(); ++i) {
        for (size_t j = i + 1; j < edges.size(); ++j) {
            const Edge& a = *edges[i];
            const Edge& b = *edges[j];
            if (a.ch == b.ch) continue;
            Fp x = fp_mul(a.w[0], pk.powg_B[a.idx]);
            Fp y = fp_mul(b.w[0], pk.powg_B[b.idx]);
            if (sgn_val(a.ch) < 0) x = fp_neg(x);
            if (sgn_val(b.ch) < 0) y = fp_neg(y);
            if (zero(fp_add(x, y))) ++hits;
        }
    }
    return hits;
}

static int top_bit(const BitVec& v) {
    for (int i = (int)v.w.size() - 1; i >= 0; --i) {
        uint64_t x = v.w[(size_t)i];
        if (x) return i * 64 + 63 - __builtin_clzll(x);
    }
    return -1;
}

static int gf2_rank(std::vector<BitVec> cols, size_t bits) {
    std::vector<BitVec> basis(bits);
    std::vector<uint8_t> used(bits, 0);
    int rank = 0;
    for (auto& col : cols) {
        BitVec x = col;
        for (;;) {
            int p = top_bit(x);
            if (p < 0) break;
            if (!used[(size_t)p]) {
                basis[(size_t)p] = x;
                used[(size_t)p] = 1;
                ++rank;
                break;
            }
            x.xor_with(basis[(size_t)p]);
        }
    }
    return rank;
}

int main() {
    auto pk_blob = read_all("pk.bin");
    auto ct_blob = read_all("secret.ct");
    PubKey pk = pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
    auto cts = read_bundle(ct_blob);

    std::cout << "m_bits=" << pk.prm.m_bits << "\n";
    std::cout << "n_bits=" << pk.prm.n_bits << "\n";
    std::cout << "B=" << pk.prm.B << "\n";
    std::cout << "ciphertexts=" << cts.size() << "\n";
    std::cout << "max_plaintext_bytes=" << (cts.empty() ? 0 : (cts.size() - 1) * 15) << "\n";
    std::cout << "h_rank=" << gf2_rank(pk.H, (size_t)pk.prm.m_bits) << "\n";

    size_t total_edges = 0;
    size_t total_base_layers = 0;
    size_t non_two_base = 0;
    size_t public_zero_layers = 0;
    int total_r2_zero_pairs = 0;
    bool compatible = true;
    bool duplicate_seed = false;
    std::set<std::tuple<uint64_t, uint64_t, uint64_t>> seeds;

    for (size_t i = 0; i < cts.size(); ++i) {
        const Cipher& c = cts[i];
        compatible = compatible && is_cipher_compatible_with_pubkey(pk, c);
        total_edges += c.E.size();
        std::map<uint32_t, size_t> by_layer;
        for (const auto& e : c.E) ++by_layer[e.layer_id];

        size_t bases = 0;
        size_t zeros = 0;
        int r2_hits = 0;
        for (size_t l = 0; l < c.L.size(); ++l) {
            if (c.L[l].rule != RRule::BASE) continue;
            ++bases;
            auto seed = std::make_tuple(c.L[l].seed.ztag, c.L[l].seed.nonce.lo, c.L[l].seed.nonce.hi);
            if (!seeds.insert(seed).second) duplicate_seed = true;
            if (zero(public_num_slot0(pk, c, (uint32_t)l))) ++zeros;
            r2_hits += r2_zero_pairs(pk, c, (uint32_t)l);
        }

        total_base_layers += bases;
        if (bases != 2) ++non_two_base;
        public_zero_layers += zeros;
        total_r2_zero_pairs += r2_hits;

        std::cout << "ct[" << i << "] layers=" << c.L.size()
                  << " bases=" << bases
                  << " edges=" << c.E.size()
                  << " public_zero=" << zeros
                  << " r2_zero_pairs=" << r2_hits << "\n";
        for (const auto& [layer, count] : by_layer) {
            std::cout << "  layer[" << layer << "].edges=" << count << "\n";
        }
    }

    std::cout << "compatible=" << compatible << "\n";
    std::cout << "total_edges=" << total_edges << "\n";
    std::cout << "total_base_layers=" << total_base_layers << "\n";
    std::cout << "non_two_base_ciphers=" << non_two_base << "\n";
    std::cout << "public_zero_base_layers=" << public_zero_layers << "\n";
    std::cout << "r2_zero_pairs=" << total_r2_zero_pairs << "\n";
    std::cout << "duplicate_base_seed=" << duplicate_seed << "\n";
}

