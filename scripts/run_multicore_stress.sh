#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PVAC="$ROOT/work/pvac_hfhe_cpp"
BUILD="$ROOT/build/upstream"
OUT="$ROOT/outputs/multicore_stress_logs"
source "$ROOT/scripts/lib_jobs.sh"
JOBS_USED="$(job_count)"
mkdir -p "$BUILD" "$OUT"

if [[ ! -d "$PVAC/.git" ]]; then
  echo "Run bash run_all.sh first."
  exit 2
fi

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

compile_one() {
  local t="$1"
  local src
  src="$(src_for "$t")"
  g++ -std=c++17 -O3 -march=native -I"$PVAC/include" "$src" -o "$BUILD/$t" >"$OUT/$t.compile.log" 2>&1
}

echo "jobs=$JOBS_USED"
echo "prebuilding stress tests"
for t in "${tests[@]}"; do
  run_limited "$JOBS_USED" compile_one "$t"
done
wait_all

echo "launching $JOBS_USED independent stress jobs"
run_stress_job() {
  local id="$1"
  local t="${tests[$(( id % ${#tests[@]} ))]}"
  {
    echo "job=$id test=$t start=$(date -u --iso-8601=seconds)"
    timeout 20m "$BUILD/$t"
    echo "job=$id test=$t exit=$? end=$(date -u --iso-8601=seconds)"
  } >"$OUT/job_$id.log" 2>&1
}

for ((i = 0; i < JOBS_USED; ++i)); do
  run_limited "$JOBS_USED" run_stress_job "$i"
done
wait_all

for ((i = 0; i < JOBS_USED; ++i)); do
  cat "$OUT/job_$i.log"
done

echo "multicore stress passed"
