#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
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

static bool eq(Fp a, Fp b) {
    return a.lo == b.lo && a.hi == b.hi;
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

static uint64_t fp_fingerprint(Fp x) {
    return x.lo ^ (x.hi * 0x9e3779b97f4a7c15ull);
}

static int parity(const BitVec& v) {
    int out = 0;
    for (uint64_t w : v.w) out ^= (__builtin_popcountll(w) & 1);
    return out;
}

static int entropy_n2(int B, double noise_bits, double tuple2_fraction, int depth, double depth_slope_bits) {
    double cap = noise_bits + depth_slope_bits * std::max(0, depth);
    double c2 = 2.0 * std::log2((double)B);
    int q2 = std::max(0, (int)std::floor(cap * tuple2_fraction / std::max(1e-6, c2)));
    double c3 = 3.0 * std::log2((double)B);
    int q3 = std::max(0, (int)std::floor(cap * (1.0 - tuple2_fraction) / std::max(1e-6, c3)));
    if (q2 + q3 == 1) q3 > 0 ? ++q3 : ++q2;
    return q2;
}

static int entropy_n3(int B, double noise_bits, double tuple2_fraction, int depth, double depth_slope_bits) {
    double cap = noise_bits + depth_slope_bits * std::max(0, depth);
    double c2 = 2.0 * std::log2((double)B);
    int q2 = std::max(0, (int)std::floor(cap * tuple2_fraction / std::max(1e-6, c2)));
    double c3 = 3.0 * std::log2((double)B);
    int q3 = std::max(0, (int)std::floor(cap * (1.0 - tuple2_fraction) / std::max(1e-6, c3)));
    if (q2 + q3 == 1) q3 > 0 ? ++q3 : ++q2;
    return q3;
}

int main() {
    auto pkb = read_all("pk.bin");
    auto ctb = read_all("secret.ct");
    PubKey pk = pvac_ser::deserialize_pubkey(pkb.data(), pkb.size());
    auto cts = read_bundle(ctb);

    std::cout << "== artifact ==\n";
    std::cout << "ciphertexts=" << cts.size() << "\n";
    if (cts.size() > 1) {
        size_t blocks = cts.size() - 1;
        std::cout << "payload_blocks=" << blocks << "\n";
        std::cout << "plaintext_len_min=" << ((blocks - 1) * 15 + 1) << "\n";
        std::cout << "plaintext_len_max=" << (blocks * 15) << "\n";
    }
    std::cout << "params_B=" << pk.prm.B << " m=" << pk.prm.m_bits << " n=" << pk.prm.n_bits << "\n";
    std::cout << "params_noise=" << pk.prm.noise_entropy_bits
              << " tuple2=" << pk.prm.tuple2_fraction
              << " slope=" << pk.prm.depth_slope_bits << "\n";

    bool any_c0_nonzero = false;
    bool any_prod = false;
    bool any_missing_pc = false;
    bool duplicate_seed = false;
    bool duplicate_public_num = false;
    bool duplicate_edge_term = false;
    size_t total_pc = 0;
    size_t total_edges = 0;
    size_t sigma_even = 0;
    size_t sigma_odd = 0;
    std::set<std::tuple<uint64_t, uint64_t, uint64_t>> seeds;
    std::set<uint64_t> pub_nums;
    std::set<uint64_t> edge_terms;
    std::map<uint16_t, size_t> idx_hist;
    std::map<uint8_t, size_t> sign_hist;

    std::cout << "\n== ciphertexts ==\n";
    for (size_t ci = 0; ci < cts.size(); ++ci) {
        const Cipher& c = cts[ci];
        if (!c.c0.empty()) {
            for (const auto& x : c.c0) any_c0_nonzero = any_c0_nonzero || !zero(x);
        }

        size_t bases = 0;
        size_t pcs = 0;
        size_t missing_pc = 0;
        std::cout << "ct=" << ci << " slots=" << c.slots
                  << " layers=" << c.L.size()
                  << " edges=" << c.E.size();

        for (size_t li = 0; li < c.L.size(); ++li) {
            const Layer& L = c.L[li];
            if (L.rule == RRule::BASE) {
                ++bases;
                auto seed = std::make_tuple(L.seed.ztag, L.seed.nonce.lo, L.seed.nonce.hi);
                if (!seeds.insert(seed).second) duplicate_seed = true;
                Fp n0 = public_num(pk, c, (uint32_t)li, 0);
                uint64_t fp = fp_fingerprint(n0);
                if (!pub_nums.insert(fp).second) duplicate_public_num = true;
                std::cout << " layer" << li << "_num_zero=" << zero(n0);
                std::cout << " layer" << li << "_num_fp=" << std::hex << fp << std::dec;
            } else {
                any_prod = true;
            }
            pcs += L.PC.size();
            if (L.PC.size() != c.slots) ++missing_pc;
        }

        for (const auto& e : c.E) {
            ++idx_hist[e.idx];
            ++sign_hist[e.ch];
            total_edges++;
            if (parity(e.s)) ++sigma_odd; else ++sigma_even;
            Fp t = signed_term(pk, e, 0);
            uint64_t fp = fp_fingerprint(t);
            if (!edge_terms.insert(fp).second) duplicate_edge_term = true;
        }

        total_pc += pcs;
        any_missing_pc = any_missing_pc || missing_pc != 0;
        int d0 = ci == 0 ? 0 : (int)ci + 1;
        int n2 = entropy_n2(pk.prm.B, pk.prm.noise_entropy_bits, pk.prm.tuple2_fraction, d0, pk.prm.depth_slope_bits);
        int n3 = entropy_n3(pk.prm.B, pk.prm.noise_entropy_bits, pk.prm.tuple2_fraction, d0, pk.prm.depth_slope_bits);
        std::cout << " bases=" << bases
                  << " pc_entries=" << pcs
                  << " missing_pc_layers=" << missing_pc
                  << " expected_depth_hint=" << d0
                  << " expected_noise_n2=" << n2
                  << " expected_noise_n3=" << n3
                  << "\n";
    }

    size_t idx_min = SIZE_MAX;
    size_t idx_max = 0;
    for (const auto& [idx, count] : idx_hist) {
        idx_min = std::min(idx_min, count);
        idx_max = std::max(idx_max, count);
    }

    std::cout << "\n== aggregate ==\n";
    std::cout << "total_edges=" << total_edges << "\n";
    std::cout << "total_pc_entries=" << total_pc << "\n";
    std::cout << "any_c0_nonzero=" << any_c0_nonzero << "\n";
    std::cout << "any_product_layers=" << any_prod << "\n";
    std::cout << "any_missing_pc=" << any_missing_pc << "\n";
    std::cout << "duplicate_seed=" << duplicate_seed << "\n";
    std::cout << "duplicate_public_num_fingerprint=" << duplicate_public_num << "\n";
    std::cout << "duplicate_edge_term_fingerprint=" << duplicate_edge_term << "\n";
    std::cout << "sigma_even=" << sigma_even << " sigma_odd=" << sigma_odd << "\n";
    std::cout << "sign_plus=" << sign_hist[SGN_P] << " sign_minus=" << sign_hist[SGN_M] << "\n";
    std::cout << "idx_unique=" << idx_hist.size() << " idx_min_count=" << idx_min << " idx_max_count=" << idx_max << "\n";

    std::cout << "\n== read ==\n";
    std::cout << "If any_missing_pc=0, each base layer still has a Pedersen commitment to R^-1, but it is hiding.\n";
    std::cout << "A useful next attack needs to break that hiding, recover PRF/LPN masks, or find an external oracle.\n";
}
