# Octra HFHE Probe Runner

Small Ubuntu/GCC runner for the current `octra-labs/hfhe-challenge` package.

## VPS commands

```bash
sudo apt update
sudo apt install -y git build-essential coreutils
git clone https://github.com/rowanhere/octra.git
cd octra
bash run_all.sh
```

When it finishes, send back:

```bash
cat outputs/run_summary.txt
cat outputs/artifact_probe.txt
cat outputs/upstream_regressions.txt
cat outputs/multicore_stress.txt
```

By default it uses `nproc` parallel jobs where possible. To cap or override CPU use:

```bash
JOBS=32 bash run_all.sh
```

Optional longer run:

```bash
bash scripts/run_long_simd.sh
cat outputs/long_simd.txt
```

## What this does

- Clones the official challenge repo.
- Clones `octra-labs/pvac_hfhe_cpp` and checks out the commit named by the challenge.
- Builds a read-only artifact probe against the pinned implementation.
- Runs cheap known-regression probes for the patched oracle/zero/R2/public-linear classes.
