# syntax=docker/dockerfile:1
#
# Turnkey PoR *prover* image for external agents. Bakes the prebuilt `prover`
# binary (whose embedded guest image_id must equal the deployed verifier's) into a
# slim Debian runtime, so an agent runs a proof with a single `docker run` — no
# Rust/RISC0 build, no source checkout.
#
#   docker run --rm \
#     -e POR_PRIVATE_KEY=<32B hex> \
#     -e NOTARY_ADDR=hayabusa.proxy.rlwy.net:43686 \
#     ghcr.io/drgora/por-prover:latest \
#     --verifier https://verifier-production-d672.up.railway.app \
#     --agent-id <id> --threshold <wei> --chain-id 1
#
# The binary is staged into this directory by ../prover/build.sh (git-ignored, never
# committed) — it is built on the host with RISC0_USE_DOCKER=1 so its image_id is the
# reproducible, marketplace-registered one. Base = debian:trixie-slim (glibc 2.41) to
# match the host the binary is built on, same as deploy/railway/Dockerfile.runtime.
FROM debian:trixie-slim

# curl: the prover shells out to it for every JSON-RPC call (eth_getProof,
# debug_getRawHeader) and for the verifier HTTP requests. libssl/libgomp/libstdc++:
# the prover's runtime deps (TLS, rayon/openmp in risc0, C++ runtime).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl libssl3 libstdc++6 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# A writable CWD: connected mode needs none, but --out / file mode writes here.
WORKDIR /work

# The prover proves via RISC Zero's default (external) prover, which execs the `r0vm`
# server binary — needed for BOTH real and dev-mode proving. Stage it next to the
# prover (dereferenced from the rzup toolchain, must be the matching r0vm 3.0.4).
COPY prover /usr/local/bin/prover
COPY r0vm /usr/local/bin/r0vm
RUN chmod +x /usr/local/bin/prover /usr/local/bin/r0vm

# args after the image name are passed straight to the prover.
ENTRYPOINT ["prover"]
