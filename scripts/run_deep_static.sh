#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PVAC="$ROOT/work/pvac_hfhe_cpp"
CHAL="$ROOT/work/hfhe-challenge"
OUT="$ROOT/outputs"
BUILD="$ROOT/build"
mkdir -p "$OUT" "$BUILD"

if [[ ! -d "$PVAC/.git" || ! -d "$CHAL/.git" ]]; then
  echo "Run bash run_all.sh first."
  exit 2
fi

echo "compile deep_static_probe"
g++ -std=c++17 -O3 -march=native \
  -I"$PVAC/include" \
  "$ROOT/probes/deep_static_probe.cpp" \
  -o "$BUILD/deep_static_probe"

echo "run deep_static_probe"
(
  cd "$CHAL"
  "$BUILD/deep_static_probe"
) | tee "$OUT/deep_static_probe.txt"

