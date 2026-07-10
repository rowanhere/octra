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

Deeper static artifact inspection:

```bash
bash scripts/run_deep_static.sh
cat outputs/deep_static_probe.txt
```

Pedersen/Ristretto sanity probe:

```bash
bash scripts/run_pedersen_probe.sh
cat outputs/pedersen_probe.txt
```

Low-rate public RPC/oracle sweep:

```bash
bash scripts/run_rpc_oracle.sh
cat outputs/rpc_oracle_summary.txt
```

If the default public RPC rate-limits the VPS too, retry with a longer delay:

```bash
DELAY_SECONDS=10 bash scripts/run_rpc_oracle.sh
```

Expand the public RPC/oracle data into transaction and PVAC metadata:

```bash
bash scripts/run_rpc_deep_oracle.sh
cat outputs/rpc_deep_oracle_summary.txt
```

Probe the funding sender and raw-transaction method variants:

```bash
bash scripts/run_rpc_rawtx_probe.sh
cat outputs/rpc_rawtx_probe_summary.txt
```

Extract and statically inspect the funding sender's PVAC key/cipher:

```bash
bash scripts/run_sender_pvac_probe.sh
cat outputs/sender_pvac_probe.txt
```

## What this does

- Clones the official challenge repo.
- Clones `octra-labs/pvac_hfhe_cpp` and checks out the commit named by the challenge.
- Builds a read-only artifact probe against the pinned implementation.
- Runs cheap known-regression probes for the patched oracle/zero/R2/public-linear classes.
