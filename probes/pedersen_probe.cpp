#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
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
        cts.push_back(pvac_ser::deserialize_cipher(b.data() + p, (size_t)n));
        p += (size_t)n;
    }
    return cts;
}

static bool same(const RistrettoPoint& a, const RistrettoPoint& b) {
    return a == b;
}

static void print_hex(const char* label, const RistrettoPoint& p) {
    std::cout << label << "=";
    for (uint8_t b : p) {
        static const char* hex = "0123456789abcdef";
        std::cout << hex[b >> 4] << hex[b & 15];
    }
    std::cout << "\n";
}

int main(int argc, char** argv) {
    int scan_limit = 20000;
    if (argc > 1) scan_limit = std::max(1, std::atoi(argv[1]));

    RistrettoPoint G = rist_G();
    RistrettoPoint H = rist_H();
    RistrettoPoint I = rist_identity();
    ExtPoint tmp;

    std::cout << "scan_limit=" << scan_limit << "\n";
    print_hex("G", G);
    print_hex("H", H);
    print_hex("I", I);
    std::cout << "G_decodes=" << rist_decode(tmp, G) << "\n";
    std::cout << "H_decodes=" << rist_decode(tmp, H) << "\n";
    std::cout << "I_decodes=" << rist_decode(tmp, I) << "\n";
    std::cout << "G_is_identity=" << same(G, I) << "\n";
    std::cout << "H_is_identity=" << same(H, I) << "\n";
    std::cout << "G_eq_H=" << same(G, H) << "\n";

    RistrettoPoint lG = rist_scalarmul(G, Scalar{{SC_L[0], SC_L[1], SC_L[2], SC_L[3]}});
    RistrettoPoint lH = rist_scalarmul(H, Scalar{{SC_L[0], SC_L[1], SC_L[2], SC_L[3]}});
    std::cout << "lG_is_identity=" << same(lG, I) << "\n";
    std::cout << "lH_is_identity=" << same(lH, I) << "\n";

    int h_as_small_g = -1;
    RistrettoPoint acc = I;
    for (int k = 0; k <= scan_limit; ++k) {
        if (same(acc, H)) {
            h_as_small_g = k;
            break;
        }
        acc = rist_add(acc, G);
    }
    std::cout << "H_small_log_base_G=" << h_as_small_g << "\n";

    int g_as_small_h = -1;
    acc = I;
    for (int k = 0; k <= scan_limit; ++k) {
        if (same(acc, G)) {
            g_as_small_h = k;
            break;
        }
        acc = rist_add(acc, H);
    }
    std::cout << "G_small_log_base_H=" << g_as_small_h << "\n";

    if (fs::exists("secret.ct")) {
        auto cts = read_bundle(read_all("secret.ct"));
        size_t pc_total = 0;
        size_t pc_invalid = 0;
        size_t pc_identity = 0;
        size_t pc_dupe = 0;
        std::vector<RistrettoPoint> pcs;
        for (const auto& c : cts) {
            for (const auto& l : c.L) {
                for (const auto& pc : l.PC) {
                    ++pc_total;
                    if (!rist_decode(tmp, pc)) ++pc_invalid;
                    if (same(pc, I)) ++pc_identity;
                    if (std::find(pcs.begin(), pcs.end(), pc) != pcs.end()) ++pc_dupe;
                    pcs.push_back(pc);
                }
            }
        }
        std::cout << "artifact_pc_total=" << pc_total << "\n";
        std::cout << "artifact_pc_invalid=" << pc_invalid << "\n";
        std::cout << "artifact_pc_identity=" << pc_identity << "\n";
        std::cout << "artifact_pc_duplicates=" << pc_dupe << "\n";
    }
}
