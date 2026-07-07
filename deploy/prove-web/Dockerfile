# syntax=docker/dockerfile:1
#
# The HUMAN, browser-wallet Proof-of-Reserves flow in ONE container: the static web UI +
# the prover-web backend + the `prover` binary + `r0vm`. Run it locally (privacy: your
# address & balance never leave your machine) or deploy it as the hosted option.
#
#   docker run --rm -p 8080:8080 ghcr.io/drgora/por-prove-web:latest
#   # open http://localhost:8080 → connect wallet → prove
#
# Base = node:22-trixie-slim (Node 22 + glibc 2.41) to match the prebuilt prover binary,
# which is built on the host (Arch, glibc ~2.41). bookworm (2.36) is too old to load it.
# Artifacts (prover, r0vm, dist, prover-web.mjs) are staged by ../prove-web/build.sh.
FROM node:22-trixie-slim

# curl: the prover shells out for JSON-RPC. libssl/libgomp/libstdc++: prover + r0vm runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl libssl3 libstdc++6 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Proving stack (prover execs r0vm; both must be the reproducible 3.0.4 pair whose image_id
# matches the deployed verifier). notary_probe: in-container notary diagnostic.
COPY prover r0vm notary_probe /usr/local/bin/
RUN chmod +x /usr/local/bin/prover /usr/local/bin/r0vm /usr/local/bin/notary_probe

# The app: prebuilt SPA + the zero-dependency Node backend.
COPY dist ./dist
COPY prover-web.mjs ./

ENV PUBLIC_DIR=/app/dist \
    PORT=8080 \
    VERIFIER_URL=https://verifier-production-d672.up.railway.app \
    NOTARY_ADDR=hayabusa.proxy.rlwy.net:39286 \
    REGISTRY_URL=https://ui-production-3e28.up.railway.app
EXPOSE 8080
CMD ["node", "prover-web.mjs"]
