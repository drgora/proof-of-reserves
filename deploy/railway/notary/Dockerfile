# syntax=docker/dockerfile:1
#
# Railway build for the `notary` service. Near-instant: it just pulls the prebuilt
# runtime image (built + pushed by ../build-and-push.sh) — no Rust/Risc0/tlsn
# compile on Railway. The startCommand in railway.json sets NOTARY_ADDR=[::]:$PORT.
#
# ── PREREQUISITE ────────────────────────────────────────────────────────────
# The image below MUST already exist and be pullable by Railway:
#   deploy/railway/build-and-push.sh          # builds + pushes it
# then make the GHCR package PUBLIC (or add Railway private-registry creds).
# If you see "failed to pull" / "unauthorized" here, that's this step.
# Replace the ref if your GHCR path differs.
FROM ghcr.io/horizenlabs/por-risc0-runtime:latest
WORKDIR /data
CMD ["notary"]
