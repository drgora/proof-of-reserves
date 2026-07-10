#!/usr/bin/env bash
# Build + publish EVERY production component from ONE Docker-reproducible guest build, so the
# prover, verifier/notary, and the marketplace-registered vkHash all share the same guest
# image_id. This is the command to run for a full production release.
#
#   deploy/publish-production.sh            # build all + push (default)
#   PUSH=0 deploy/publish-production.sh     # build all, push nothing (dry run / local test)
#   GHCR_OWNER=you deploy/publish-production.sh
#
# Publishes:
#   • ghcr.io/$GHCR_OWNER/por-risc0-runtime   (verifier + notary)  -> Railway verifier/notary
#   • ghcr.io/$GHCR_OWNER/por-prover          (headless AI agents)
#   • ghcr.io/$GHCR_OWNER/por-prove-web       (browser wallet, humans)
#
# WHY one script: the guest image_id is only reproducible under RISC0_USE_DOCKER=1, and it must
# be IDENTICAL across all three images. The failure mode this prevents: a stray native
# `cargo build` leaves target/release/prover with a machine-specific id, and the image build
# scripts (which only STAGE the binary) then ship a prover the verifier rejects. Here the guest
# is built ONCE, up front, in Docker; every image stages that same binary; and each build script
# re-asserts the id (deploy/lib.sh) before it ships. Never run a native `cargo build` in between.
#
# Requires: RISC0 toolchain, Docker, Node (for the web bundle), and `docker login ghcr.io`
# with a PAT that has write:packages on $GHCR_OWNER (unless PUSH=0).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/deploy/lib.sh"   # EXPECTED_GUEST_ID + assert_guest_id
export PUSH="${PUSH:-1}"

echo "==> [1/4] Building all binaries with RISC0_USE_DOCKER=1 (one deterministic guest image_id)"
echo "         expected guest image_id: $EXPECTED_GUEST_ID"
( cd "$ROOT/por-risc0" && RISC0_USE_DOCKER=1 cargo build --release \
    --bin prover --bin verifier --bin notary --bin notary_probe )

# Fail fast, before any image is built, if the reproducible build didn't yield the expected id
# (e.g. the guest legitimately changed and EXPECTED_GUEST_ID in deploy/lib.sh is stale).
echo "==> verifying the freshly built binaries embed $EXPECTED_GUEST_ID"
assert_guest_id "$ROOT/por-risc0/target/release/prover"   || exit 1
assert_guest_id "$ROOT/por-risc0/target/release/verifier" || exit 1

# SKIP_BUILD=1: reuse the binaries we just built in step 1 (don't rebuild the guest again).
echo "==> [2/4] Runtime image (verifier + notary) -> GHCR"
SKIP_BUILD=1 "$ROOT/deploy/railway/build-and-push.sh"

echo "==> [3/4] por-prover image (headless AI agents; unified CPU/GPU)"
# The prover image bakes a CUDA r0vm for GPU proving when R0VM_CUDA points at one (build it
# from the risc0 monorepo, -F cuda — see deploy/prover/build.sh). Without it, ship the same
# image CPU-only (SKIP_CUDA=1) rather than hard-fail: the unified entrypoint still runs
# everywhere, just always picks the CPU r0vm. Set R0VM_CUDA to enable GPU in the release.
if [ -n "${R0VM_CUDA:-}" ]; then
  R0VM_CUDA="$R0VM_CUDA" "$ROOT/deploy/prover/build.sh"
else
  echo "    (no R0VM_CUDA set -> CPU-only por-prover; set R0VM_CUDA=/path/to/cuda-r0vm to bake GPU)"
  SKIP_CUDA=1 "$ROOT/deploy/prover/build.sh"
fi

echo "==> [4/4] por-prove-web image (browser wallet, humans)"
"$ROOT/deploy/prove-web/build.sh"

echo
if [ "$PUSH" = 1 ]; then
  echo "✓ All production images built + pushed (guest image_id $EXPECTED_GUEST_ID)."
  echo "  Next:"
  echo "    1. Redeploy the Railway 'verifier' and 'notary' services to pull por-risc0-runtime:latest."
  echo "    2. Ensure the GHCR packages are PUBLIC so agents/humans can pull anonymously."
  echo "    3. Push any git changes Railway tracks (UI / adapter) so it redeploys those too."
else
  echo "✓ All production images built (PUSH=0, nothing pushed). Re-run with PUSH=1 to publish."
fi
