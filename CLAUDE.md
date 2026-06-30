# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **proof-of-reserves framework**: a trading agent proves it controls a wallet **and** holds **≥ T** of assets — **without revealing the balance or the address** (native ETH on L1 for v1).

The balance is read **directly from on-chain state**, not an API: an EIP-1186 `eth_getProof` account proof verified against the `state_root` in the block header. A **Risc0 zkVM** receipt shows, in one proof: the account-state Merkle-Patricia proof verifies under the header's state root, `balance ≥ threshold`, and (unless a public `debug` flag is set) **in-circuit secp256k1 ownership** of the address — with balance + address kept private. The journal commits only `{block_hash, threshold, chain_id, debug}`.

Authenticity is anchored on `block_hash`: the verifier binds `keccak256(attested_header) == journal.block_hash`. The attested header comes from a **TLSNotary (MPC-TLS)** presentation proving a *named RPC* (drpc) served it (zkTLS) — so neither the agent nor the RPC can forge the state. This is **wired**: the host MPC-TLS-attests `debug_getRawHeader(N)` to drpc via a separate notary and bundles the `Presentation` into `proof.json`; `por_verify` verifies it (notary sig + Mozilla cert chain + drpc Host allowlist) and binds the attested header to the receipt. Only the **header** is attested — the `eth_getProof` is self-verifying against the header's `state_root` in-circuit, so it needs no attestation.

> History: this evolved from an earlier design that read balances from the **Zerion API** and proved the threshold with a **Noir/UltraHonk** circuit. Both were dropped — Zerion → on-chain state proofs, Noir → Risc0 (the Risc0 receipt verifies on **zkVerify** with no version coupling, unlike UltraHonk's bb/Noir version pinning). Decision history + measured findings live in the project memory.

## Layout

**tlsn is a pinned *git dependency*, not vendored** — `github.com/tlsnotary/tlsn` rev `0fe3c32d35382b3f290a43c4156399ca4512bb89` (the alpha `Session`/driver API).

- **`por-risc0/`** — **the active flow** (Risc0 zkVM; cargo-risczero layout, its own target).
  - `host/src/main.rs` (bin `host`) — prover. Fetches `eth_getProof` + `debug_getRawHeader` from drpc (`curl`), builds the witness, proves a **succinct** receipt, writes `proof.json` (the zkVerify/Kurier bundle: `proofType risc0` / `V3_0` / CBOR receipt / image_id / journal). Two modes:
    - **DEMO** (no key): proves the beacon deposit contract with `debug=true` (no private key for a contract).
    - **OWNERSHIP** (`POR_PRIVATE_KEY=<32B hex>`): derive the EOA, fetch *its* proof, sign EIP-191(`block_hash`), prove `debug=false`.
    - **TLSNotary**: if `NOTARY_ADDR` is set, MPC-TLS-attests `debug_getRawHeader(N)` to drpc via the notary and bundles the `Presentation` into `proof.json` (`src/attest.rs`, a noir-free port of por-zk's `por_core`); unset → dev mode (no presentation).
    - Env: `POR_THRESHOLD` (wei, default 1 ETH), `POR_SEGMENT_PO2` (segment size; default 20), `NOTARY_ADDR` (notary TCP addr → enables attestation).
  - `host/src/bin/notary.rs` (bin `notary`) — the **TLSNotary notary** (own secp256k1 key persisted to `notary-signing-key.bin`; a separate trust domain). Co-runs the MPC-TLS session and signs the attestation. Port of por-zk's `zerion_notary`, reusing por-risc0's compiled tlsn.
  - `host/src/bin/por_verify.rs` — independent verifier (unified). Verifies the receipt against the guest ID, decodes the journal, and **binds** `keccak256(attested header) == journal.block_hash`, where the attested header comes from the bundled TLSNotary `Presentation` (verified: notary sig + Mozilla cert chain + drpc Host allowlist; the header is recovered from the revealed response) — or a dev-only by-hash re-fetch if no presentation. Then enforces policy (reject `debug != 0` unless `POR_ALLOW_DEBUG`, `threshold ≥ POR_REQUIRED_THRESHOLD`, `chain_id == 1`). Finally, if `KURIER_API_KEY` is set, it submits the verified receipt to **zkVerify via Kurier** (`POST /submit-proof` → poll `/job-status` to inclusion) — the relying party settles on-chain only what it already verified. Env: `KURIER_API_KEY` (gates it), `KURIER_API_URL` (default `https://api-testnet.kurier.xyz`), `KURIER_CHAIN_ID` (optional).
  - `host/src/bin/ownership_selftest.rs` — synthetic-state self-test of the `debug=false` ownership path (positive + negative controls; `POR_SELFTEST_PROVE=1` also produces a real receipt).
  - `methods/guest/src/main.rs` — the guest: `extract_state_root` (alloy-rlp header walk to item 3) → `verify_proof` (alloy-trie `TrieAccount` MPT) → ownership (`k256` ecrecover, unless `debug`) → `balance ≥ threshold` → commit `{block_hash, threshold, chain_id, debug}`. **Accelerated precompiles**: k256 + keccak via the risc0 forks (see gotchas).
  - `cudacheck.c` / `cudacheck_dl.c` — CUDA bring-up probes. `[features] cuda` enables GPU proving (see GPU gotcha).
- **`por-zk/`** — **trimmed TLSNotary reference** (source-only, ~200 K; builds without Barretenberg now).
  - Built bins: `zerion_notary` (the separate notary — own secp256k1 key; adds signed `por.recv_commitments` + `por.siwe` attestation extensions) and `siwe_selftest`.
  - Reference source only (no `[[bin]]`, not built): `por_core.rs` (MPC-TLS prover), `por_witness.rs`, `por_zk.rs`, `por_prove.rs`, `por_verifier.rs`, `por_service.rs`, `siwe_verify.rs`, `types.rs`. This is the reference for wiring TLSNotary attestation into the Risc0 flow. *(The Noir/UltraHonk circuit + the noir-rs/Barretenberg dep were removed when the ZK layer moved to Risc0.)*
- **`app/web/`** — React + wagmi/viem + `siwe` frontend (Vite). It was built against `por-zk`'s `por_service` (now reference-only), so **it has no live backend** until a Risc0 service is built.

## Build

Toolchain: **rustc ≥ 1.95** (the tlsn alpha, for `por-zk`) + the **Risc0 toolchain** for the guest (`rzup`: cargo-risczero / r0vm **3.0.4** = zkVerify `V3_0`; `rzup install rust` if the guest toolchain is too old for alloy's deps). Node 22.

- **`por-risc0/` (active):** `cd por-risc0 && cargo build --release` (builds `host`, `por_verify`, `ownership_selftest`; the guest ELF builds via `risc0-build`). GPU: `--features cuda` (see GPU gotcha — CUDA 12.x + ≥16 GB VRAM).
- **`por-zk/` (reference):** `cargo build --manifest-path por-zk/Cargo.toml` — builds `zerion_notary` + `siwe_selftest` (the tlsn/MPC-TLS stack is the bulk; no Barretenberg).
- **Frontend:** `npm --prefix app/web install`, then `run dev` (Vite :5173, proxies `/api` → :8090) / `run build`.
- **Bumping the tlsn rev** means re-checking the API against the alpha — it changes shape between revs.

## Run

**The product (Risc0 + TLSNotary, balance + address hidden):**
```bash
# 1. Notary (separate trust domain) on :7150
NOTARY_ADDR=127.0.0.1:7150 por-risc0/target/release/notary &
# 2. Prove + MPC-TLS-attest (DEMO: beacon contract, debug=true) -> proof.json (+ presentation)
NOTARY_ADDR=127.0.0.1:7150 por-risc0/target/release/host
#    OWNERSHIP variant: a funded EOA you hold the key for, debug=false
POR_PRIVATE_KEY=<32B-hex> POR_THRESHOLD=<wei> NOTARY_ADDR=127.0.0.1:7150 por-risc0/target/release/host
# 3. Verify receipt + TLSNotary presentation + binding (debug=true receipt needs POR_ALLOW_DEBUG=1)
POR_REQUIRED_THRESHOLD=<wei> por-risc0/target/release/por_verify
#    ...and settle on-chain on zkVerify — the relying party submits what it verified:
KURIER_API_KEY=<key> POR_REQUIRED_THRESHOLD=<wei> por-risc0/target/release/por_verify
```
Omit `NOTARY_ADDR` for a dev run (no attestation; `por_verify` falls back to a by-hash header re-fetch). `por_verify` submits to **zkVerify via Kurier** when `KURIER_API_KEY` is set — verified compatible: zkVerify's `risc0-verifier` supports risc0 **v3.0.0** (our r0vm-3.0.4 / `V3_0` receipt), and `proof.json`'s `proofData` is already the required shape (`proof` = hex CBOR receipt, `vk` = LE-word image_id, `publicSignals` = hex journal); no VK pre-registration. CPU proving is ~265 s (debug) / ~300–530 s (ownership). The first `--release` build also compiles the tlsn/MPC-TLS stack alongside risc0 (heavier, one-time).

## Tests / self-checks

- `por-risc0/target/release/ownership_selftest` — execution + negative controls for the `debug=false` ownership path; `POR_SELFTEST_PROVE=1` adds a real succinct prove (~5 min CPU).
- `por-risc0/target/release/por_verify` — verifies a receipt + the `block_hash` binding (against a `proof.json`).
- `por-zk/target/.../siwe_selftest` — SIWE EIP-191 recovery roundtrip.

## Architecture & trust model

Three independent trust domains, bound by **`block_hash`**:
1. **Agent / prover** — holds the wallet key, fetches state from a named RPC, proves in Risc0 (balance + address private).
2. **Notary** (TLSNotary, separate process, own key) — co-runs the RPC TLS session via MPC so session keys are **split**; signs a commitment to the *encrypted* transcript, never sees plaintext, cannot forge it. *(Reference in `por-zk`; not yet integrated into the Risc0 flow.)*
3. **Verifier** (independent) — verifies the Risc0 receipt, binds `keccak256(attested header) == journal.block_hash`, enforces policy. In prod the header comes from the TLSNotary presentation (proving a named RPC served it); the cert identifies the *RPC*, not the chain, so chain identity rests on a Host allowlist + M-of-N RPC quorum.

The Risc0 proof says "balance ≥ T under this `block_hash`"; the attestation says "a named RPC served the header whose keccak == `block_hash`."

## Critical gotchas (these will bite)

**Risc0 flow (`por-risc0`):**
- **Accelerated precompiles** (`methods/guest/Cargo.toml` `[patch.crates-io]` + `risc0-zkvm`/`risc0-build` `unstable` feature): k256 = risc0 fork `k256/v0.13.4-risczero.1` (needs the risc0 `crypto-bigint` fork); keccak = risc0 `tiny-keccak` fork — alloy's keccak backend, so all MPT/header keccak is accelerated. alloy's `native-keccak` hook does **not** link on risc0; don't use it.
- **Prague header has 21 fields** (Cancun 20): `extract_state_root` reads item index 3 (`state_root`, stable across forks); the guest keccaks the whole header for `block_hash`.
- **GPU (`--features cuda`)**: needs **CUDA 12.x** (risc0 3.0.4 rejects CUDA 13). Pass `-arch=sm_XX` **explicitly** via `NVCC_PREPEND_FLAGS` (`-arch=native` mis-detects in a chroot → slow `sm_52`). On glibc ≥2.41, patch CUDA's `crt/math_functions.h` (`throw()` on the 6 C23 math decls). **An 8 GB GPU OOMs** (only fits at `po2≤15` → impractically many segments); a **≥16 GB** card is the real requirement. In a chroot where `cuInit` returns 304, **build in the chroot, run the binary on the host**.
- `eth_getProof` uses minimal hex — odd-nibble values like `"0x0"` exist; left-pad before `hex::decode` (the `hexb` helper).
- `por_verify`'s balance-leak privacy check guards `balance != 0` (a zero balance serializes to 16 zero bytes == a public `threshold=0`).

**TLSNotary (wired into `por-risc0`; the notary port + fuller reference also live in `por-zk`):**
- **tlsn + risc0 dep trees coexist** in `por-risc0/host` (de-risked: both compile + link in one crate) — that's why the unified verifier is possible.
- **Only the header is attested.** The MPC-TLS session attests `debug_getRawHeader(N)`; the `eth_getProof` is *self-verifying* against the header's `state_root` in-circuit, so it needs no attestation. Pin a **finalized** block so the attested header is byte-identical to the one proven.
- **drpc is TLSNotary-compatible** (measured): it negotiates TLS 1.2 + `ECDHE-ECDSA-AES128-GCM-SHA256` with an **ECDSA P-256** cert — the alpha's only supported suite.
- **Don't fork tlsn.** It's a pinned git dep. Surface verifier-visible data via a **notary-signed attestation extension** (as `por.recv_commitments` does), read from `PresentationOutput.extensions`. (The Risc0 verifier instead reads the *revealed* transcript via `PresentationOutput.transcript` + `received_unsafe()` and keccaks the header.)
- **tlsn MPC futures are `!Send`** — inside an axum handler run via `spawn_blocking(|| Handle::current().block_on(...))`.
- **Commitments** default to BLAKE3 (set SHA256); a hash commitment opens whole.
- **SIWE is manual EIP-191** (k256 + tiny-keccak), not the `siwe` crate (dep conflict); the frontend uses the `siwe` npm package only to *build* the message.
- **RPC / TLSNotary specifics**: TLSNotary supports only **TLS 1.2 + `ECDHE-ECDSA-AES128-GCM-SHA256`**; always send `Accept-Encoding: identity` (it can't handle compression). drpc serves `debug_getRawHeader` (accepts a block **hash**) and `eth_getProof`.

## Further context

`por-zk/POR_SERVICE.md` documents the (now-reference) TLSNotary REST flow. The current architecture's decision history + measured findings (Risc0 perf, GPU bring-up, ownership E2E, the `por-zk` trim, the zkVerify/Kurier gap) live in the Claude Code project memory.
