# Shared deploy helpers. Source this: `source "$(dirname "$0")/../lib.sh"` (adjust depth).
#
# EXPECTED_GUEST_ID is the Docker-reproducible RISC Zero guest image_id that the deployed
# verifier embeds AND the marketplace vkHash is registered against. Everything that ships must
# agree on it. A NATIVE `cargo build` produces a machine-specific id that does NOT match, which
# is exactly the footgun assert_guest_id catches before an image is built/pushed.
#
# Update EXPECTED_GUEST_ID ONLY when the guest changes -- then you must also re-register the
# vkHash on the marketplace (setVkHash) and rebuild every component. Read it back from a
# reproducibly built binary with:  cargo run --release --bin marketplace_offsets   (prints vkHash)
EXPECTED_GUEST_ID="0xd78517f8ad9d6816218dc3fc10a1980cbe2b801471bd62a5a1848e87e45750b0"

# assert_guest_id <binary>
# Abort unless <binary> embeds EXPECTED_GUEST_ID (the id is stored as 8 LE u32 words == the 32
# raw bytes of the hex). Uses only coreutils (od/tr/grep) so it runs anywhere the build does.
assert_guest_id() {
  local bin="$1" hexid="${EXPECTED_GUEST_ID#0x}"
  [ -r "$bin" ] || { echo "ERROR: assert_guest_id: cannot read $bin" >&2; return 1; }
  if od -An -v -tx1 "$bin" | tr -d ' \n' | grep -qi "$hexid"; then
    echo "  ✓ guest image_id $EXPECTED_GUEST_ID present in $(basename "$bin")"
    return 0
  fi
  echo "ERROR: $bin does NOT embed the expected guest image_id $EXPECTED_GUEST_ID." >&2
  echo "  It was almost certainly built WITHOUT RISC0_USE_DOCKER=1 (a native build yields a" >&2
  echo "  machine-specific id that the verifier + marketplace will reject). Rebuild reproducibly:" >&2
  echo "    (cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover)" >&2
  echo "  If the guest legitimately changed, update EXPECTED_GUEST_ID in deploy/lib.sh and" >&2
  echo "  re-register the vkHash on the marketplace." >&2
  return 1
}
