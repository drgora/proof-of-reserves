#!/usr/bin/env bash
# Build the por-risc0 notary + verifier and bake them into the GHCR runtime image
# that the Railway `notary` and `verifier` services pull (via Dockerfile.risc0).
#
# Run from anywhere; requires: a working Risc0 toolchain, Docker, and `docker login
# ghcr.io` (a GitHub PAT with write:packages).
#
#   ./build-and-push.sh                 # reproducible guest build → image → push
#   SKIP_BUILD=1 ./build-and-push.sh    # reuse existing target/release binaries
#   RISC0_RUNTIME_IMAGE=ghcr.io/you/img:tag ./build-and-push.sh
#
# WHY RISC0_USE_DOCKER=1: the verifier embeds the guest ELF, so its image_id must
# byte-match the prover's. The prover builds the guest reproducibly in Docker; the
# verifier must too, or every real proof is rejected on an image_id mismatch. Only
# the guest needs Docker — the host binary is compiled natively (its glibc linkage,
# not its image_id, is what the trixie runtime base cares about).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE="${RISC0_RUNTIME_IMAGE:-ghcr.io/horizenlabs/por-risc0-runtime:latest}"

if [ "${SKIP_BUILD:-0}" != 1 ]; then
  echo ">> building por-risc0 notary + verifier (RISC0_USE_DOCKER=1 for a deterministic guest image_id)"
  ( cd "$ROOT/por-risc0" && RISC0_USE_DOCKER=1 cargo build --release --bin notary --bin verifier )
fi

for b in notary verifier; do
  src="$ROOT/por-risc0/target/release/$b"
  [ -x "$src" ] || { echo "ERROR: missing binary $src (run without SKIP_BUILD)"; exit 1; }
done

mkdir -p "$HERE/bin"
cp "$ROOT/por-risc0/target/release/notary"   "$HERE/bin/notary"
cp "$ROOT/por-risc0/target/release/verifier" "$HERE/bin/verifier"

echo ">> docker build $IMAGE"
docker build -f "$HERE/Dockerfile.runtime" -t "$IMAGE" "$HERE"

echo ">> docker push $IMAGE"
docker push "$IMAGE"

echo ">> done. Redeploy the 'notary' and 'verifier' Railway services to pull the new image."
