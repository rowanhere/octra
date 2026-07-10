#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PVAC="$ROOT/work/pvac_hfhe_cpp"
OUT="$ROOT/outputs"
BUILD="$ROOT/build/upstream"
mkdir -p "$OUT" "$BUILD"

if [[ ! -d "$PVAC/.git" ]]; then
  echo "Run bash run_all.sh first."
  exit 2
fi

echo "compile test_simd_attack"
g++ -std=c++17 -O3 -march=native -I"$PVAC/include" \
  "$PVAC/tests/test_simd_attack.cpp" \
  -o "$BUILD/test_simd_attack"

echo "run test_simd_attack"
"$BUILD/test_simd_attack" | tee "$OUT/long_simd.txt"

