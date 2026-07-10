#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PVAC="$ROOT/work/pvac_hfhe_cpp"
BUILD="$ROOT/build/upstream"
mkdir -p "$BUILD"

tests=(
  test_plaintext_oracle
  test_public_zero_oracle
  bounty_r2_attack
  test_public_linear_invariants
  test_rcomless_fold
)

src_for() {
  case "$1" in
    bounty_r2_attack) echo "$PVAC/tests/bounty_r2_attack.cpp" ;;
    *) echo "$PVAC/tests/$1.cpp" ;;
  esac
}

echo "pvac_head=$(git -C "$PVAC" rev-parse HEAD)"
echo "building ${#tests[@]} tests"

for t in "${tests[@]}"; do
  src="$(src_for "$t")"
  echo "compile $t"
  g++ -std=c++17 -O3 -march=native -I"$PVAC/include" "$src" -o "$BUILD/$t"
done

echo "running tests"
for t in "${tests[@]}"; do
  echo "===== $t ====="
  timeout 20m "$BUILD/$t"
  echo "exit=$?"
done

