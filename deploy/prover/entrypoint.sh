#!/bin/sh
# Unified CPU/GPU entrypoint for por-prover.
#
# The prover proves via risc0's EXTERNAL prover (it execs an r0vm server). This image bakes
# BOTH r0vm builds; we pick one at runtime and point RISC0_SERVER_PATH at it, then exec prover.
#   - GPU (CUDA r0vm) iff a CUDA device is actually usable with enough free VRAM
#   - CPU r0vm otherwise (default everywhere; the PoR succinct proof needs >= 16 GB VRAM)
#
# Selection (override with POR_PROVER_BACKEND=auto|cpu|gpu; VRAM gate POR_MIN_VRAM_GB, default 16):
#   1. RISC0_DEV_MODE set (!=0) -> CPU (dev mode is fake; no real proving, no GPU)
#   2. POR_PROVER_BACKEND=cpu|gpu -> forced
#   3. auto -> gpu-preflight probes the real driver + free VRAM; GPU iff it passes
#
# Diagnostic: `docker run --gpus all <img> --print-backend` prints the chosen backend and exits.
set -eu

R0VM_CPU="${POR_R0VM_CPU:-/usr/local/bin/r0vm-cpu}"
R0VM_CUDA="${POR_R0VM_CUDA:-/usr/local/bin/r0vm-cuda}"
PREFLIGHT="${POR_PREFLIGHT_BIN:-/usr/local/bin/gpu-preflight}"
PROVER="${POR_PROVER_BIN:-prover}"
MIN_VRAM="${POR_MIN_VRAM_GB:-16}"
BACKEND="${POR_PROVER_BACKEND:-auto}"

choose() {
  if [ -n "${RISC0_DEV_MODE:-}" ] && [ "${RISC0_DEV_MODE}" != "0" ]; then echo cpu; return; fi
  case "$BACKEND" in
    cpu) echo cpu; return ;;
    gpu) echo gpu; return ;;
    auto) : ;;
    *) echo "[por-prover] WARN: bad POR_PROVER_BACKEND='$BACKEND', using auto" >&2 ;;
  esac
  if [ -x "$R0VM_CUDA" ] && [ -x "$PREFLIGHT" ] && "$PREFLIGHT" "$MIN_VRAM"; then
    echo gpu
  else
    echo cpu
  fi
}

BK="$(choose)"
if [ "$BK" = gpu ]; then
  export RISC0_SERVER_PATH="$R0VM_CUDA"
  export RISC0_PROVER=ipc
  export RISC0_DEFAULT_PROVER_NUM_GPUS="${RISC0_DEFAULT_PROVER_NUM_GPUS:-1}"
  echo "[por-prover] backend=GPU  ($RISC0_SERVER_PATH)" >&2
else
  export RISC0_SERVER_PATH="$R0VM_CPU"
  export RISC0_PROVER=ipc
  echo "[por-prover] backend=CPU  ($RISC0_SERVER_PATH)" >&2
fi

if [ "${1:-}" = "--print-backend" ]; then echo "$BK"; exit 0; fi
exec "$PROVER" "$@"
