# syntax=docker/dockerfile:1
#
# Turnkey PoR prover image for external agents — UNIFIED CPU/GPU (auto-detecting).
#
# Runs anywhere with a single `docker run` (no Rust/RISC0 build, no source). It bakes the
# prebuilt `prover` plus BOTH r0vm servers (CPU + CUDA) and picks one at runtime:
#   * add `--gpus all` on a host with a usable NVIDIA GPU (>= 16 GB free VRAM) -> CUDA r0vm
#   * anything else (no GPU, no --gpus, small/*unusable* GPU) -> CPU r0vm, same as before
# The choice is made by entrypoint.sh via gpu-preflight (real driver probe + free-VRAM check,
# NOT nvidia-smi). See entrypoint.sh for overrides (POR_PROVER_BACKEND, POR_MIN_VRAM_GB).
#
#   # CPU (unchanged UX):
#   docker run --rm -e POR_PRIVATE_KEY=<hex> ghcr.io/drgora/por-prover:latest \
#     --verifier <url> --agent-id <id> --threshold <wei> --chain-id 1
#   # GPU:
#   docker run --rm --gpus all -e POR_PRIVATE_KEY=<hex> ghcr.io/drgora/por-prover:latest ...
#   # See which backend a host would use, without proving:
#   docker run --rm --gpus all ghcr.io/drgora/por-prover:latest --print-backend
#
# The `prover` (and its embedded guest image_id) is UNCHANGED vs the old CPU image, so proofs
# are byte-identical and the marketplace vkHash is unaffected — GPU only makes them faster.
# Binaries are staged by ./build.sh (git-ignored). Base stays debian:trixie-slim: the CUDA
# r0vm links cudart statically and needs only libcuda.so.1 (injected by --gpus), so no bulky
# CUDA base is required; all baked binaries require glibc <= 2.41 (build.sh guards this).

# -- stage 1: compile the GPU preflight probe (plain C, no CUDA toolkit) on the SAME libc as
#    the runtime, so it can't have a glibc mismatch. It dlopen()s libcuda at runtime.
FROM debian:trixie-slim AS probe-builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY gpu_preflight.c /tmp/gpu_preflight.c
RUN cc -O2 -o /gpu-preflight /tmp/gpu_preflight.c -ldl

# -- stage 2: runtime
FROM debian:trixie-slim

# curl: the prover shells out for every JSON-RPC call. libssl3/libgomp1/libstdc++6: TLS +
# rayon/openmp + C++ runtime. The CUDA r0vm's extra needs (libcuda.so.1, libnvidia-ml.so.1)
# are injected by the NVIDIA container runtime with `--gpus`, not installed here.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl libssl3 libstdc++6 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Prover + both r0vm servers + the probe + the selector. The prover finds its server via
# RISC0_SERVER_PATH (set by entrypoint.sh); r0vm -> r0vm-cpu symlink covers any bare `r0vm`.
COPY prover      /usr/local/bin/prover
COPY r0vm-cpu    /usr/local/bin/r0vm-cpu
COPY r0vm-cuda   /usr/local/bin/r0vm-cuda
COPY --from=probe-builder /gpu-preflight /usr/local/bin/gpu-preflight
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/prover /usr/local/bin/r0vm-cpu /usr/local/bin/r0vm-cuda \
             /usr/local/bin/gpu-preflight /usr/local/bin/entrypoint.sh \
    && ln -s r0vm-cpu /usr/local/bin/r0vm

# Only consulted when `--gpus` is used; harmless otherwise. compute=libcuda, utility=NVML.
ENV NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility

# entrypoint.sh selects the backend, then exec's `prover` with the args after the image name.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
