#!/usr/bin/env bash
# Build (and optionally push) the turnkey PoR prover image for external agents.
#
#   deploy/prover/build.sh              # build ghcr.io/$GHCR_OWNER/por-prover:latest locally
#   PUSH=1 deploy/prover/build.sh       # also docker push (needs `docker login ghcr.io`)
#
# It stages the prebuilt prover binary next to the Dockerfile, then builds. The binary
# MUST be built reproducibly so its guest image_id equals the deployed verifier's
# (0x4f02b5a5888cd107681e44eef9b9c3eaa836d18b4f15a9d10a741bff704039e6):
#
#   cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover
#
# Re-run + re-push whenever the guest changes (a new image_id invalidates old proofs).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/deploy/prover"
GHCR_OWNER="${GHCR_OWNER:-drgora}"
IMAGE="${PROVER_IMAGE:-ghcr.io/$GHCR_OWNER/por-prover:latest}"
BIN="$ROOT/por-risc0/target/release/prover"
EXPECTED_ID="0x4f02b5a5888cd107681e44eef9b9c3eaa836d18b4f15a9d10a741bff704039e6"

[ -x "$BIN" ] || { echo "ERROR: prover binary not found at $BIN"; echo "build it: (cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover)"; exit 1; }

# The prover execs `r0vm` (the RISC Zero prover server) at runtime; resolve the real
# binary behind the rzup shim/symlink and bake it in too. Must be r0vm 3.0.4.
R0VM="$(readlink -f "$(command -v r0vm 2>/dev/null || echo /nonexistent)")"
[ -x "$R0VM" ] || { echo "ERROR: r0vm not found on PATH (install the RISC0 toolchain: rzup install)"; exit 1; }

echo "Staging prover ($(du -h "$BIN" | cut -f1)) + r0vm ($(du -h "$R0VM" | cut -f1)) ..."
cp "$BIN" "$HERE/prover"
cp "$R0VM" "$HERE/r0vm"

echo "Building $IMAGE ..."
docker build -t "$IMAGE" "$HERE"
rm -f "$HERE/prover" "$HERE/r0vm"

echo
echo "Built $IMAGE"
echo "Verify its image_id matches the deployed verifier ($EXPECTED_ID):"
echo "  RISC0_DEV_MODE=1 docker run --rm $IMAGE   # legacy DEMO; prints vk in proof.json"
if [ "${PUSH:-0}" = "1" ]; then
  echo "Pushing $IMAGE ..."
  docker push "$IMAGE"
  echo "Pushed. Make the GHCR package PUBLIC so agents can pull anonymously."
fi
