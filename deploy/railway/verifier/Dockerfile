# syntax=docker/dockerfile:1
#
# Railway build for the `verifier` service. Near-instant: it just pulls the prebuilt
# runtime image (built + pushed by ../build-and-push.sh) — no Rust/Risc0/tlsn
# compile on Railway, and the verifier's guest image_id stays byte-identical to the
# prover's. The startCommand in railway.json sets VERIFIER_ADDR=[::]:$PORT.
#
# ── PREREQUISITE ────────────────────────────────────────────────────────────
# The image below MUST already exist and be pullable by Railway:
#   deploy/railway/build-and-push.sh          # builds + pushes it
# then make the GHCR package PUBLIC (personal account → Packages → package →
# settings → visibility → Public). If you see "403 Forbidden" / "failed to pull"
# here, that's this step. Must match GHCR_OWNER in ../build-and-push.sh.
FROM ghcr.io/drgora/por-risc0-runtime:latest
WORKDIR /data
CMD ["verifier"]
