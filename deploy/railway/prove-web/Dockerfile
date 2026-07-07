# syntax=docker/dockerfile:1
#
# Railway build for the `prove-web` service — the hosted human browser-wallet flow. Pulls the
# prebuilt image (built + pushed by deploy/prove-web/build.sh), so no Rust/Node build on
# Railway. Point the service's Root Directory here; Railway auto-detects this Dockerfile +
# railway.json.
#
# The one setting that makes the notary work: on this service set
#   NOTARY_ADDR=notary.railway.internal:7150
# i.e. reach the notary over Railway PRIVATE networking (a direct container-to-container TCP
# connection), NOT the public TCP proxy. The public proxy caps/mangles the long TLSNotary MPC
# session (~25s → EOF, measured with notary_probe); private networking behaves like a direct
# connection and carries it. Confirm from a shell on this service:
#   notary_probe --notary notary.railway.internal:7150   # expect OK
#
# PREREQUISITE: ghcr.io/drgora/por-prove-web:latest must exist + be public (deploy/prove-web/build.sh).
FROM ghcr.io/drgora/por-prove-web:latest
WORKDIR /app
CMD ["node", "/app/prover-web.mjs"]
