#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$ROOT/work"
OUT="$ROOT/outputs"
BUILD="$ROOT/build"

mkdir -p "$WORK" "$OUT" "$BUILD"

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"
}

{
  echo "host=$(hostname)"
  echo "date_utc=$(date -u --iso-8601=seconds)"
  echo "nproc=$(nproc)"
  echo "gcc=$({ gcc --version || true; } | head -n 1)"
  echo "g++=$({ g++ --version || true; } | head -n 1)"
} > "$OUT/run_summary.txt"

log "cloning/updating challenge"
if [[ ! -d "$WORK/hfhe-challenge/.git" ]]; then
  git clone https://github.com/octra-labs/hfhe-challenge.git "$WORK/hfhe-challenge"
else
  git -C "$WORK/hfhe-challenge" fetch --all --prune
  git -C "$WORK/hfhe-challenge" reset --hard origin/main
fi

COMMIT="$(tr -d '\r\n ' < "$WORK/hfhe-challenge/pvac_commit.txt")"
echo "challenge_head=$(git -C "$WORK/hfhe-challenge" rev-parse HEAD)" >> "$OUT/run_summary.txt"
echo "pvac_commit=$COMMIT" >> "$OUT/run_summary.txt"

log "cloning/updating pinned pvac_hfhe_cpp"
if [[ ! -d "$WORK/pvac_hfhe_cpp/.git" ]]; then
  git clone https://github.com/octra-labs/pvac_hfhe_cpp.git "$WORK/pvac_hfhe_cpp"
else
  git -C "$WORK/pvac_hfhe_cpp" fetch --all --prune
fi
git -C "$WORK/pvac_hfhe_cpp" checkout "$COMMIT"

log "building artifact_probe"
g++ -std=c++17 -O3 -march=native \
  -I"$WORK/pvac_hfhe_cpp/include" \
  "$ROOT/probes/artifact_probe.cpp" \
  -o "$BUILD/artifact_probe"

log "running artifact_probe"
(
  cd "$WORK/hfhe-challenge"
  "$BUILD/artifact_probe"
) | tee "$OUT/artifact_probe.txt"

log "running selected upstream regressions"
bash "$ROOT/scripts/run_upstream_regressions.sh" | tee "$OUT/upstream_regressions.txt"

{
  echo
  echo "artifact_probe_exit=0"
  echo "upstream_regressions_exit=0"
  echo "done_utc=$(date -u --iso-8601=seconds)"
} >> "$OUT/run_summary.txt"

log "done. outputs are in $OUT"

