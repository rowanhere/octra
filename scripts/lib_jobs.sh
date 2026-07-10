#!/usr/bin/env bash

cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  else
    getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
  fi
}

job_count() {
  local detected
  detected="$(cpu_count)"
  if [[ -n "${JOBS:-}" && "$JOBS" =~ ^[0-9]+$ && "$JOBS" -gt 0 ]]; then
    echo "$JOBS"
  else
    echo "$detected"
  fi
}

run_limited() {
  local max_jobs="$1"
  shift
  while (( "$(jobs -rp | wc -l)" >= max_jobs )); do
    sleep 0.2
  done
  "$@" &
}

wait_all() {
  local rc=0
  local pid
  for pid in $(jobs -rp); do
    if ! wait "$pid"; then
      rc=1
    fi
  done
  return "$rc"
}

