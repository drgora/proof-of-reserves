#!/usr/bin/env bash
# Build (and optionally push) the UNIFIED CPU/GPU PoR prover image for external agents.
#
#   deploy/prover/build.sh              # build ghcr.io/$GHCR_OWNER/por-prover:latest locally
#   PUSH=1 deploy/prover/build.sh       # also docker push (needs `docker login ghcr.io`)
#   SKIP_CUDA=1 deploy/prover/build.sh  # CPU-only fallback build (no CUDA r0vm baked; see below)
#
# One image that auto-selects at runtime (entrypoint.sh + gpu-preflight): CUDA r0vm on a host
# with a usable >=16 GB GPU (`--gpus all`), else the CPU r0vm — same UX as the old CPU image.
#
# It stages three prebuilt binaries next to the Dockerfile, then builds:
#   1. prover   — the SAME reproducible binary as before (RISC0_USE_DOCKER=1) so its guest
#                 image_id == the deployed verifier's + the marketplace vkHash. Unchanged by
#                 GPU support (proving backend is external), so proofs stay byte-identical.
#   2. r0vm-cpu — the rzup r0vm (3.0.4), as the old image baked.
#   3. r0vm-cuda— a CUDA build of r0vm 3.0.4 (pass R0VM_CUDA=/path). rzup ships CPU-only, so
#                 build it from the risc0 monorepo (VERIFIED against tag v3.0.4):
#                   git clone https://github.com/risc0/risc0 && cd risc0 && git checkout v3.0.4
#                   NVCC_APPEND_FLAGS=-arch=<sm_XX> cargo build --release -p risc0-r0vm -F cuda
#                   # -> target/release/r0vm  (needs CUDA 12.x + nvcc; risc0 3.0.x rejects 13)
#                 Must require glibc <= this image's base (debian:trixie = 2.41); the guard
#                 below enforces it. (A monorepo build on glibc 2.39/2.43 satisfies this — the
#                 binary keys off the newest symbol it uses, measured ~2.39.)
#
# Re-run + re-push whenever the guest changes (a new image_id invalidates old proofs) or when
# you rebuild r0vm. The prover binary itself is unchanged from the CPU image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/deploy/prover"
source "$ROOT/deploy/lib.sh"   # EXPECTED_GUEST_ID + assert_guest_id
GHCR_OWNER="${GHCR_OWNER:-drgora}"
IMAGE="${PROVER_IMAGE:-ghcr.io/$GHCR_OWNER/por-prover:latest}"
BIN="$ROOT/por-risc0/target/release/prover"
BASE_GLIBC="2.41"   # debian:trixie-slim

# assert_glibc_le <binary> <max>  — the runtime base's glibc must be >= what the binary needs.
assert_glibc_le() {
  local bin="$1" max="$2"
  local need; need="$(objdump -T "$bin" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1)"
  [ -n "$need" ] || { echo "  (glibc check skipped for $(basename "$bin"): no versioned symbols)"; return 0; }
  if [ "$(printf '%s\n%s\n' "$need" "$max" | sort -V | tail -1)" = "$max" ]; then
    echo "  ✓ $(basename "$bin") needs glibc $need <= base $max"
  else
    echo "ERROR: $(basename "$bin") needs glibc $need > base $max ($BASE_GLIBC). Build it on an" >&2
    echo "  older-glibc host (e.g. inside debian:trixie) so it runs on this image." >&2
    return 1
  fi
}

# assert_r0vm_version <binary>
assert_r0vm_version() {
  local ver; ver="$("$1" --version 2>/dev/null || true)"
  case "$ver" in *3.0.4*) echo "  ✓ $(basename "$1"): $ver" ;;
    *) echo "ERROR: $1 must be r0vm 3.0.4 (got '${ver:-unknown}') — matches guest + zkVerify V3_0" >&2; return 1 ;;
  esac
}

# ---- 1. prover (unchanged, reproducible) --------------------------------------------------
[ -x "$BIN" ] || { echo "ERROR: prover binary not found at $BIN"; echo "build it: (cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover)"; exit 1; }
assert_guest_id "$BIN" || exit 1
assert_glibc_le "$BIN" "$BASE_GLIBC" || exit 1

# ---- 2. CPU r0vm (rzup) -------------------------------------------------------------------
R0VM_CPU="$(readlink -f "$(command -v r0vm 2>/dev/null || echo /nonexistent)")"
[ -x "$R0VM_CPU" ] || { echo "ERROR: r0vm not on PATH (rzup install the RISC0 toolchain)"; exit 1; }
assert_r0vm_version "$R0VM_CPU" || exit 1
assert_glibc_le "$R0VM_CPU" "$BASE_GLIBC" || exit 1

# ---- 3. CUDA r0vm (from the monorepo; optional via SKIP_CUDA) ------------------------------
if [ "${SKIP_CUDA:-0}" = "1" ]; then
  echo "SKIP_CUDA=1 -> baking a CPU stand-in as r0vm-cuda; the image will ALWAYS fall back to CPU."
  echo "  (Ship this to get the unified entrypoint now; rebuild with R0VM_CUDA to enable GPU.)"
  R0VM_CUDA="$R0VM_CPU"   # gpu-preflight still runs, but a CPU r0vm can't init CUDA -> CPU path
else
  R0VM_CUDA="${R0VM_CUDA:-}"
  [ -n "$R0VM_CUDA" ] || { echo "ERROR: set R0VM_CUDA=/path/to/cuda-r0vm (or SKIP_CUDA=1). See header."; exit 1; }
  [ -x "$R0VM_CUDA" ] || { echo "ERROR: R0VM_CUDA not executable: $R0VM_CUDA"; exit 1; }
  assert_r0vm_version "$R0VM_CUDA" || exit 1
  assert_glibc_le "$R0VM_CUDA" "$BASE_GLIBC" || exit 1
  # grep -c (not -q): reads all input so `strings` isn't killed by SIGPIPE, which under
  # `set -o pipefail` would spuriously fail this check (the symbols appear early in output).
  cuda_syms=$(strings -a "$R0VM_CUDA" | grep -acE '__cudaRegisterFatBinary|cudaLaunchKernel|libcudart\.so' || true)
  if [ "${cuda_syms:-0}" -gt 0 ]; then
    echo "  ✓ r0vm-cuda has CUDA kernel/runtime symbols ($cuda_syms)"
  else
    echo "ERROR: $R0VM_CUDA has NO CUDA symbols — it's a CPU r0vm. Build it -F cuda (see header)." >&2
    exit 1
  fi
fi

echo "Staging prover + r0vm-cpu + r0vm-cuda ..."
cp "$BIN"       "$HERE/prover"
cp "$R0VM_CPU"  "$HERE/r0vm-cpu"
cp "$R0VM_CUDA" "$HERE/r0vm-cuda"

echo "Building $IMAGE ..."
docker build -t "$IMAGE" "$HERE"
rm -f "$HERE/prover" "$HERE/r0vm-cpu" "$HERE/r0vm-cuda"

echo
echo "Built $IMAGE"
echo "  CPU (anywhere):  docker run --rm $IMAGE --print-backend        # -> cpu"
echo "  GPU (>=16 GB):   docker run --rm --gpus all $IMAGE --print-backend   # -> gpu"
echo "Guest image_id verified ($EXPECTED_GUEST_ID); prover unchanged from the CPU image."
if [ "${PUSH:-0}" = "1" ]; then
  echo "Pushing $IMAGE ..."
  docker push "$IMAGE"
  echo "Pushed. Make the GHCR package PUBLIC so agents can pull anonymously."
fi
