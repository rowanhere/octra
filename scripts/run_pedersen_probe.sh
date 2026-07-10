#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PVAC="$ROOT/work/pvac_hfhe_cpp"
CHAL="$ROOT/work/hfhe-challenge"
OUT="$ROOT/outputs"
BUILD="$ROOT/build"
SCAN_LIMIT="${1:-200000}"
mkdir -p "$OUT" "$BUILD"

if [[ ! -d "$PVAC/.git" || ! -d "$CHAL/.git" ]]; then
  echo "Run bash run_all.sh first."
  exit 2
fi

echo "compile pedersen_probe"
g++ -std=c++17 -O3 -march=native \
  -I"$PVAC/include" \
  "$ROOT/probes/pedersen_probe.cpp" \
  -o "$BUILD/pedersen_probe"

echo "run pedersen_probe scan_limit=$SCAN_LIMIT"
(
  cd "$CHAL"
  "$BUILD/pedersen_probe" "$SCAN_LIMIT"
) | tee "$OUT/pedersen_probe.txt"

