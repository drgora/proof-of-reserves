# Proof of Reserves — REST service (TLSNotary + ZK threshold)

A trading agent proves it holds **≥ T USD** on Zerion **without revealing the
balance**, and a REST service verifies that claim **offline**.

This builds on:
- the `≥T` Noir circuit (`noir/src/main.nr`) — proves `floor(balance) ≥ T` and
  that the balance commits to a SHA256 hash, in zero knowledge;
- the separate-notary **attestation** flow (`crates/examples/zerion_attest`) —
  a content-blind notary signs a commitment to the TLS transcript.

## Trust model

Three parties, three trust domains:

```
   ┌──────────┐   MPC-TLS    ┌───────────────┐
   │  Agent   │─────────────▶│ api.zerion.io │   (real data source; TLS server)
   │ (prover) │◀─────────────└───────────────┘
   └────┬─────┘   MPC          
        │  co-compute + sign
        ▼
   ┌──────────┐  signs Attestation over the (encrypted) transcript commitment
   │  Notary  │  (own key; never sees plaintext or the balance)
   └──────────┘
        │  Agent builds { presentation, zk_proof } and POSTs it
        ▼
   ┌──────────────────┐  verifies OFFLINE: notary sig + CA roots + ZK proof
   │ Verifier (REST)  │  → "balance ≥ T", never learns the balance
   └──────────────────┘
```

The verifier learns: the session was with `api.zerion.io`, which wallet/endpoint
was queried, and that the hidden balance ≥ T. It never sees the balance or the
API key. The notary never sees plaintext. The agent cannot forge the balance
(the notary-signed commitment binds it; the ZK proof is checked against that
commitment).

## What the verifier checks (`POST /verify`)

1. The presentation's **notary signature** and **server cert chain** (Mozilla roots).
2. The session server is `api.zerion.io`.
3. The **ZK proof** verifies and was produced by our exact circuit.
4. The proof's committed hash **equals a notary-signed commitment** (binds proof → attested data).
5. The committed range is exactly the `data.attributes.total.positions` value.
6. The proven threshold meets the service's required minimum (`POR_REQUIRED_THRESHOLD`).

## Run it (3 processes)

All paths relative to the repo root `…/proof-of-reserves/tlsn`.

**1. Notary** (separate trust domain; own signing key):
```bash
NOTARY_ADDR=127.0.0.1:7150 RUST_LOG=info \
  cargo run --release -p tlsn-examples --example zerion_notary
```

**2. Verifier REST service:**
```bash
cd crates/examples-zk
POR_REQUIRED_THRESHOLD=1000000 RUST_LOG=info \
  cargo run --release --bin por_verifier        # listens on 127.0.0.1:8080
```

**3. Agent** (needs your Zerion key — keep it in your shell, never paste it):
```bash
cd crates/examples-zk
ZERION_API_KEY=<your-key> \
ZERION_WALLET=0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 \
THRESHOLD=1000000 NOTARY_ADDR=127.0.0.1:7150 RUST_LOG=info \
  cargo run --release --bin por_prove
```
`por_prove` writes `por.bundle.json` and prints a ready-to-run curl. Submit it:
```bash
curl -s -X POST http://127.0.0.1:8080/verify \
     -H 'content-type: application/json' --data @por.bundle.json | jq
```

Expected response:
```json
{
  "verified": true,
  "server_name": "api.zerion.io",
  "time": "2026-06-25T…Z",
  "threshold_proven": 1000000,
  "notary_key": "03fada…",
  "error": null
}
```
Set `THRESHOLD` above the real balance to see the agent fail to prove (the
circuit assertion fails), or `POR_REQUIRED_THRESHOLD` above `THRESHOLD` to see
the verifier reject a valid-but-insufficient proof.

## Known PoC simplifications (hardening for production)

- **Notary trust**: the verifier reports the notary key but does not enforce an
  allowlist — add one (M-of-N notaries for real trust-minimization).
- **`total.positions` location check** is substring-based on the revealed JSON
  (`"total":` then `"positions":`); tune it to Zerion's exact response shape.
- **Balance ≤ 32 ASCII chars** (circuit `MAX_BALANCE_LEN`); integer part ≤ u64.
- **One commitment per field**; a balance value straddling a TLS-record/chunk
  boundary would make the committed range non-contiguous (rare; fails closed).
- **No tlsn changes.** The verifier binds the ZK proof to the notary-signed
  commitment by reading a signed attestation **extension** (`por.recv_commitments`,
  added by the notary from its `VerifierOutput`), exposed through the public
  `PresentationOutput.extensions` API — not by reaching into tlsn internals.
```
