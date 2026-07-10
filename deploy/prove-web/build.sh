#!/usr/bin/env bash
# Build (and optionally push) the browser-wallet PoR web image (por-prove-web).
#
#   deploy/prove-web/build.sh            # build locally
#   PUSH=1 deploy/prove-web/build.sh     # also docker push (needs `docker login ghcr.io`)
#
# Stages the prebuilt prover + r0vm (reproducible, image_id must match the verifier), builds
# the frontend, and bakes both plus prover-web.mjs into the image. Re-run + re-push whenever
# the guest OR the frontend changes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/deploy/prove-web"
source "$ROOT/deploy/lib.sh"   # EXPECTED_GUEST_ID + assert_guest_id
GHCR_OWNER="${GHCR_OWNER:-drgora}"
IMAGE="${PROVE_WEB_IMAGE:-ghcr.io/$GHCR_OWNER/por-prove-web:latest}"
BIN="$ROOT/por-risc0/target/release/prover"
R0VM="$(readlink -f "$(command -v r0vm 2>/dev/null || echo /nonexistent)")"

[ -x "$BIN" ]  || { echo "ERROR: prover not at $BIN — (cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover)"; exit 1; }

# GUARD: same image_id check as por-prover — never bake a native-built (wrong-id) prover.
assert_guest_id "$BIN" || exit 1
[ -x "$R0VM" ] || { echo "ERROR: r0vm not on PATH (rzup install the RISC0 toolchain)"; exit 1; }

# notary_probe: baked in so you can diagnose the notary endpoint from inside the container
# (e.g. `notary_probe --notary notary.railway.internal:7150` to confirm private networking).
PROBE="$ROOT/por-risc0/target/release/notary_probe"
[ -x "$PROBE" ] || { echo "building notary_probe ..."; ( cd "$ROOT/por-risc0" && cargo build --release --bin notary_probe ); }

echo "Building frontend ..."
# `npm run build` (not `npx vite build`) so the `prebuild` hook runs sync-docs.mjs, staging the
# canonical AGENT_GUIDE.md + openapi.json into public/ (served at /docs and /openapi.json).
( cd "$ROOT/app/web" && [ -d node_modules ] || npm install; npm run build )

echo "Staging prover + r0vm + notary_probe + dist + backend ..."
cp "$BIN" "$HERE/prover"
cp "$R0VM" "$HERE/r0vm"
cp "$PROBE" "$HERE/notary_probe"
rm -rf "$HERE/dist"; cp -r "$ROOT/app/web/dist" "$HERE/dist"
cp "$ROOT/app/web/prover-web.mjs" "$HERE/prover-web.mjs"

echo "Building $IMAGE ..."
docker build -t "$IMAGE" "$HERE"
rm -rf "$HERE/prover" "$HERE/r0vm" "$HERE/notary_probe" "$HERE/dist" "$HERE/prover-web.mjs"

echo
echo "Built $IMAGE"
echo "  docker run --rm -p 8080:8080 $IMAGE   # then open http://localhost:8080"
if [ "${PUSH:-0}" = "1" ]; then
  echo "Pushing $IMAGE ..."
  docker push "$IMAGE"
  echo "Pushed. Make the GHCR package PUBLIC so users can pull anonymously."
fi
