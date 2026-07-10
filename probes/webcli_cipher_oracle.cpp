#include <pvac/pvac.hpp>
#include "pvac_serialize.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace pvac;
namespace fs = std::filesystem;

struct LoadedCipher {
    fs::path path;
    size_t raw_bytes = 0;
    Cipher cipher;
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

static Fp signed_term(const PubKey& pk, const Edge& e) {
    Fp x = fp_mul(e.w[0], pk.powg_B[e.idx]);
    return sgn_val(e.ch) > 0 ? x : fp_neg(x);
}

static Fp public_num(const PubKey& pk, const Cipher& c, uint32_t layer) {
    Fp acc = layer == 0 && !c.c0.empty() ? c.c0[0] : fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id == layer) acc = fp_add(acc, signed_term(pk, e));
    }
    return acc;
}

static bool fp_zero(Fp x) {
    return x.lo == 0 && x.hi == 0;
}

static bool fp_eq(const Fp& a, const Fp& b) {
    return a.lo == b.lo && ((a.hi ^ b.hi) & MASK63) == 0;
}

static std::string fp_hex(Fp x) {
    std::ostringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << x.lo
       << ":" << std::setw(16) << (x.hi & MASK63);
    return ss.str();
}

static bool rcom_candidate_match(const PubKey& pk, const Cipher& c, uint32_t layer, Fp candidate_share) {
    if (fp_zero(candidate_share)) return false;
    Fp n = public_num(pk, c, layer);
    if (fp_zero(n)) return false;
    Fp r = fp_mul(n, fp_inv(candidate_share));
    const Layer& L = c.L[layer];
    auto digest = compute_R_com_base(pk.canon_tag, L.seed.ztag, L.seed.nonce.lo, L.seed.nonce.hi, {r});
    return digest == L.R_com;
}

static void print_fp(const char* label, Fp x) {
    std::cout << label << "="
              << std::hex << std::setw(16) << std::setfill('0') << x.lo
              << ":" << std::setw(16) << (x.hi & MASK63)
              << std::dec << std::setfill(' ') << "\n";
}

static std::vector<uint64_t> parse_candidates() {
    std::vector<uint64_t> out = {0, 1, 1000, 1000000, 500000000000ULL};
    const char* env = std::getenv("PVAC_CANDIDATES");
    if (!env || !*env) return out;
    std::string s(env);
    size_t pos = 0;
    while (pos < s.size()) {
        size_t next = s.find(',', pos);
        std::string tok = s.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        try {
            size_t used = 0;
            unsigned long long v = std::stoull(tok, &used, 10);
            if (used == tok.size()) out.push_back(static_cast<uint64_t>(v));
        } catch (...) {
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static bool bitvec_eq(const BitVec& a, const BitVec& b) {
    return a.nbits == b.nbits && a.w == b.w;
}

static bool layer_eq_at_offset(const Layer& src, const Layer& dst, uint32_t off) {
    if (src.rule != dst.rule) return false;
    if (src.seed.ztag != dst.seed.ztag) return false;
    if (src.seed.nonce.lo != dst.seed.nonce.lo || src.seed.nonce.hi != dst.seed.nonce.hi) return false;
    if (src.R_com != dst.R_com) return false;
    if (src.PC != dst.PC) return false;
    if (src.rule == RRule::PROD) {
        if (dst.pa != src.pa + off || dst.pb != src.pb + off) return false;
    }
    return true;
}

static bool edge_eq_at_offset(const Edge& src, const Edge& dst, uint32_t off, bool negated) {
    if (dst.layer_id != src.layer_id + off) return false;
    if (src.idx != dst.idx || src.ch != dst.ch) return false;
    if (src.w.size() != dst.w.size()) return false;
    for (size_t i = 0; i < src.w.size(); ++i) {
        Fp expected = negated ? fp_neg(src.w[i]) : src.w[i];
        if (!fp_eq(expected, dst.w[i])) return false;
    }
    return bitvec_eq(src.s, dst.s);
}

static std::vector<const Edge*> edges_for_window(const Cipher& c, uint32_t start, uint32_t count) {
    std::vector<const Edge*> out;
    uint32_t end = start + count;
    for (const auto& e : c.E) {
        if (e.layer_id >= start && e.layer_id < end) out.push_back(&e);
    }
    return out;
}

static bool component_match_at(const Cipher& src, const Cipher& dst, uint32_t start, bool negated) {
    if (src.slots != dst.slots) return false;
    if (start + src.L.size() > dst.L.size()) return false;
    for (size_t i = 0; i < src.L.size(); ++i) {
        if (!layer_eq_at_offset(src.L[i], dst.L[start + i], start)) return false;
    }

    auto dst_edges = edges_for_window(dst, start, static_cast<uint32_t>(src.L.size()));
    if (src.E.size() != dst_edges.size()) return false;
    for (size_t i = 0; i < src.E.size(); ++i) {
        if (!edge_eq_at_offset(src.E[i], *dst_edges[i], start, negated)) return false;
    }
    return true;
}

static void scan_component_windows(const PubKey& pk, const std::vector<LoadedCipher>& loaded) {
    std::cout << "\ncomponent_window_scan\n";
    size_t hits = 0;
    for (size_t si = 0; si < loaded.size(); ++si) {
        const auto& src = loaded[si].cipher;
        if (src.L.empty()) continue;
        for (size_t di = 0; di < loaded.size(); ++di) {
            if (si == di) continue;
            const auto& dst = loaded[di].cipher;
            if (dst.L.size() < src.L.size()) continue;
            uint32_t max_start = static_cast<uint32_t>(dst.L.size() - src.L.size());
            for (uint32_t start = 0; start <= max_start; ++start) {
                bool pos = component_match_at(src, dst, start, false);
                bool neg = component_match_at(src, dst, start, true);
                if (!pos && !neg) continue;
                ++hits;
                std::cout << "component_match source=" << loaded[si].path.filename().string()
                          << " target=" << loaded[di].path.filename().string()
                          << " start_layer=" << start
                          << " layers=" << src.L.size()
                          << " edges=" << src.E.size()
                          << " sign=" << (pos ? "+" : "-")
                          << " public_nums=";
                for (size_t li = 0; li < src.L.size(); ++li) {
                    if (li) std::cout << ",";
                    std::cout << fp_hex(public_num(pk, src, static_cast<uint32_t>(li)));
                }
                std::cout << "\n";
            }
        }
    }
    std::cout << "component_window_hits=" << hits << "\n";
}

int main(int argc, char** argv) {
    try {
        if (argc < 3) {
            std::cerr << "usage: " << argv[0] << " sender_pvac_pubkey.bin cipher.bin...\n";
            return 2;
        }
        auto pkb = read_all(argv[1]);
        PubKey pk = pvac_ser::deserialize_pubkey(pkb.data(), pkb.size());
        std::vector<uint64_t> candidates = parse_candidates();
        std::vector<LoadedCipher> loaded;

        std::cout << "pk_B=" << pk.prm.B << " m=" << pk.prm.m_bits << " n=" << pk.prm.n_bits << "\n";
        std::cout << "rcom_candidates=" << candidates.size() << "\n";
        for (int ai = 2; ai < argc; ++ai) {
            fs::path path = argv[ai];
            std::vector<uint8_t> ctb;
            Cipher c;
            try {
                ctb = read_all(path);
                c = pvac_ser::deserialize_cipher(ctb.data(), ctb.size());
            } catch (const std::exception& e) {
                std::cout << "\nfile=" << path.filename().string() << " load_error=" << e.what() << "\n";
                continue;
            }
            loaded.push_back({path, ctb.size(), c});
            std::cout << "\nfile=" << path.filename().string() << " raw_bytes=" << ctb.size() << "\n";
            std::cout << "compatible=" << is_cipher_compatible_with_pubkey(pk, c)
                      << " slots=" << c.slots << " layers=" << c.L.size()
                      << " edges=" << c.E.size() << " c0=" << c.c0.size() << "\n";
            size_t base = 0, prod = 0, pc = 0, missing_pc = 0, public_zero = 0;
            for (size_t i = 0; i < c.L.size(); ++i) {
                if (c.L[i].rule == RRule::BASE) ++base;
                if (c.L[i].rule == RRule::PROD) ++prod;
                pc += c.L[i].PC.size();
                if (c.L[i].PC.empty()) ++missing_pc;
                if (fp_zero(public_num(pk, c, (uint32_t)i))) ++public_zero;
            }
            std::cout << "base_layers=" << base << " product_layers=" << prod
                      << " pc_entries=" << pc << " missing_pc_layers=" << missing_pc
                      << " public_zero_layers=" << public_zero << "\n";
            for (size_t i = 0; i < c.L.size(); ++i) {
                std::cout << "layer[" << i << "] rule=" << (c.L[i].rule == RRule::BASE ? "base" : "prod")
                          << " pc=" << c.L[i].PC.size() << " ";
                print_fp("public_num", public_num(pk, c, (uint32_t)i));
                for (uint64_t cand : candidates) {
                    Fp x = fp_from_u64(cand);
                    bool pos = rcom_candidate_match(pk, c, (uint32_t)i, x);
                    bool neg = cand == 0 ? false : rcom_candidate_match(pk, c, (uint32_t)i, fp_neg(x));
                    if (pos || neg) {
                        std::cout << "  direct_rcom_hit layer=" << i << " candidate=" << cand
                                  << " sign=" << (pos ? "+" : "-") << "\n";
                    }
                }
            }
        }
        scan_component_windows(pk, loaded);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error=" << e.what() << "\n";
        return 1;
    }
}
