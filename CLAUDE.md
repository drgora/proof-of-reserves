# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **proof-of-reserves framework**: a trading agent proves it controls a wallet (SIWE) and holds **≥ T USD** of assets (read from the Zerion API) — and, in the ZK variant, proves the threshold **without revealing the balance**. Authenticity comes from **TLSNotary (MPC-TLS)**: a content-blind, independent notary attests the encrypted TLS session with `api.zerion.io`, so neither the agent nor the service can forge the balance.

## Layout

Everything here is ours. **tlsn is a pinned *git dependency*, not vendored** — `github.com/tlsnotary/tlsn` at rev `0fe3c32d35382b3f290a43c4156399ca4512bb89` (the alpha `Session`/driver API), declared in both crates' `Cargo.toml`. Cargo fetches it into its own cache.

- **`por/`** — the non-ZK / **reveal-balance** flow + the notary. Standalone crate; bins auto-discovered from `por/src/bin/`:
  - `zerion_notary` — the **separate notary** (own signing key; also adds the signed `por.recv_commitments` + `por.siwe` attestation extensions the ZK flow relies on).
  - `zerion_attest_{prove,present,verify}` — the separate-notary **attestation** flow (reveal-balance).
  - `por_service` — a SIWE-gated REST service that proves + reveals the balance (the simpler variant).
  - `zerion` — a one-shot in-process-notary plumbing PoC.
- **`por-zk/`** — the **zero-knowledge** flow. **Standalone crate (its own lockfile + `[workspace]`)** because `noir-rs` pulls the noir-lang monorepo via git (~1 GB) + a heavy Barretenberg build. Bins: `por_prove` (agent CLI), `por_verifier` (independent REST verifier), `por_service` (**SIWE-gated ZK prover** serving the UI), `zk_selftest`/`siwe_selftest` (no-network tests). Shared modules: `por_core.rs` (prover), `por_zk.rs` (ZK helpers + REST wire types), `siwe_verify.rs` (manual EIP-191), `types.rs`. Circuit: `por-zk/noir/src/main.nr`, pre-compiled to `por-zk/noir/target/noir.json`. See `por-zk/POR_SERVICE.md`.
- **`app/web/`** — React + wagmi/viem + `siwe` frontend (Vite). Calls the prover service over `/api/*`.

## Build

Toolchain: **rustc ≥ 1.95** (this alpha requires it). Node 22.

- **`por/`** (fast-ish; first build fetches tlsn from git + compiles it):
  `cargo build --release --manifest-path por/Cargo.toml`
- **`por-zk/`** (heavy: ~1 GB `noir-rs` git fetch + Barretenberg; **separate lockfile/target**):
  `cargo build --release --manifest-path por-zk/Cargo.toml`
- **Frontend:** `npm --prefix app/web install`, then `npm --prefix app/web run dev` (Vite :5173, proxies `/api` → :8090) or `run build`.
- The Noir circuit is pre-compiled. To change it you need **`nargo` pinned to `1.0.0-beta.19`** (`noirup --version 1.0.0-beta.19`) — `noir-rs` can't consume bytecode from another compiler.
- **Bumping the tlsn rev** (both `Cargo.toml`s must match) means re-checking the API against this alpha — it changes shape between revs.

## Run

**The product (ZK, balance hidden) — 4 processes:**
```bash
por/target/release/zerion_notary                                             # notary  :7150  (NOTARY_ADDR)
POR_REQUIRED_THRESHOLD=1000000 por-zk/target/release/por_verifier             # verifier :8080
ZERION_API_KEY=<key> NOTARY_ADDR=127.0.0.1:7150 \
  VERIFIER_URL=http://127.0.0.1:8080/verify POR_LISTEN_ADDR=127.0.0.1:8090 \
  por-zk/target/release/por_service                                          # prover  :8090
npm --prefix app/web run dev                                                 # UI      :5173
```
Browser w/ MetaMask → threshold → Prove. The Zerion API key lives **only** in the prover service's env.

**Simpler flows:** `por/target/release/zerion` (one-shot plumbing, reveals data, redacts the key); the `zerion_attest_*` trio against `zerion_notary` (reveal-balance attestation); `por-zk/target/release/por_prove` CLI (writes `por.bundle.json`, prints a `curl` to `por_verifier`'s `/verify`).

## Tests / self-checks

No conventional `cargo test` suite for the glue. Validate with:
- `cd por-zk/noir && nargo test` — circuit tests (needs nargo `1.0.0-beta.19`).
- `por-zk/target/release/zk_selftest` / `siwe_selftest` — no-network ZK and SIWE-recovery roundtrips.
- `node app/web/synthtest.mjs` (with `BASE=http://127.0.0.1:8090`) — headless SIWE → `/api/prove` against a running service.

## Architecture & trust model (the big picture)

Three independent trust domains; understanding the system means seeing how they bind:

1. **Agent / prover** — holds the Zerion key, runs MPC-TLS to `api.zerion.io`.
2. **Notary** (separate process, own secp256k1 key) — co-runs the TLS session via MPC so the session keys are **split**; signs a commitment to the *encrypted* transcript and **never sees plaintext or the balance**, and cannot forge it. (This is why TLSNotary, not a proxy-attestor scheme where the attestor signs the *value*.)
3. **Verifier** (independent, offline REST) — checks notary signature + server cert chain (Mozilla roots) + the ZK proof.

**Binding the ZK proof to the attested data without forking tlsn:** the balance is SHA256-committed inside the attestation; a Noir/UltraHonk proof shows `floor(balance) ≥ T` against that commitment. This alpha only exposes commitments publicly in the *interactive* flow, so the **notary adds a signed `Extension` (`por.recv_commitments`)** carrying its received-side commitments; the verifier reads it via the public `PresentationOutput.extensions`, matches the proof's `committed_hash` to it, and thus binds proof ↔ attested transcript. SIWE ownership is bound the same way (a signed `por.siwe` extension). `por_service` (`por-zk/`) verifies the SIWE personal_sign, derives the wallet, and proves for it.

## Critical gotchas (these will bite)

- **Don't fork tlsn for verifier-visible data.** It's a pinned git dep. If the verifier seems to need a `pub(crate)` tlsn field, surface it via a **notary-signed attestation extension** instead (as `por.recv_commitments` does).
- **tlsn MPC futures are `!Send`.** Inside an axum handler, run the prover via `tokio::task::spawn_blocking(|| Handle::current().block_on(...))` — otherwise the handler fails axum's `Handler` bound with an opaque error.
- **Commitment mechanics:** `TranscriptCommitConfigBuilder` defaults to **BLAKE3** (set SHA256). `reveal_*` requires revealed ⊆ committed ranges, and a **hash commitment opens whole** — to keep the balance hidden, only fully-open committed ranges that are **disjoint** from the balance value.
- **Barretenberg SRS:** call `setup_srs_from_bytecode(...)` once per process before `get_ultra_honk_verification_key`/`verify_ultra_honk` — the separate verifier process needs it too.
- **SIWE verification is manual EIP-191** (k256 + tiny-keccak), not the `siwe` crate (its deps conflict). The frontend uses the `siwe` npm package to *build* the message.
- **Zerion specifics:** serves **TLS 1.2 + `ECDHE-ECDSA-AES128-GCM-SHA256`** (TLSNotary's only supported suite). Balance is `data.attributes.total.positions` (USD). Keyless → **HTTP 402** (x402 / Machine Payments Protocol); a valid key → 200; an invalid key → 401. Responses are `Transfer-Encoding: chunked`. Always send `Accept-Encoding: identity` (TLSNotary can't handle compression). Demo keys are ~1 req/s, 300/day.

## Further context

`por-zk/POR_SERVICE.md` documents the REST product, its trust model, and what `/verify` checks. Project decision history and measured findings live in the Claude Code project memory.
