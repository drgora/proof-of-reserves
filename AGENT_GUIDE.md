# Proof-of-Reserves — external agent guide

Prove your agent controls **one or more wallets** **and** that their **combined** balance is
**at least `T`** of a chain's native coin — **without revealing the balances, the addresses,
or how many wallets**. The chain is public; the proof is a RISC Zero zkVM receipt bound to a
real block header attested by TLSNotary. This guide is everything an external agent (or the agent's operator) needs to
generate a proof and submit it to the live verifier.

## Live service

| Role | Endpoint | Protocol |
|------|----------|----------|
| **Verifier** (challenge / response API) | `https://verifier-production-d672.up.railway.app` | HTTPS / JSON |
| **Notary** (TLSNotary MPC-TLS) | `hayabusa.proxy.rlwy.net:39286` | raw TCP |
| **Directory / UI** (verified agents) | `https://ui-production-3e28.up.railway.app` | web |

This deployment runs in **testnet mode**. You prove reserves of a **testnet** native
coin, so funding a wallet is free (faucets).

## How it works (30 seconds)

1. You ask the verifier for a **challenge**. It draws a random nonce, pins the chain's
   finalized head, and picks **3 recent block numbers** spread across a ~3-day window.
   You can't predict them.
2. For each block your prover fetches the account state (`eth_getProof`) and the raw
   header (`debug_getRawHeader`), and produces **one zkVM receipt** proving, privately:
   the account is in the block's state trie, `balance ≥ T`, and you control the address
   (an in-circuit signature). The notary MPC-TLS-attests each header so neither you nor
   the RPC can forge the block.
3. You submit the 3 proofs plus a signature over the challenge from your agent's
   registered owner key.
4. The verifier checks all 3 receipts, binds each to its attested block, confirms they
   answer *this* challenge, authenticates the owner signature, and returns a **verdict**.

Because the blocks are unpredictable and already finalized, you can't pre-compute,
replay, cherry-pick a favorable block, or pass with momentarily-borrowed funds — you
must have held `≥ T` at all 3 points. Your **balance and address never leave your
machine** and are never in the proof or the committed journal.

---

## Prerequisites

Before you can get a `verified` verdict you need all four:

1. **A registered agent** on the Horizen Labs Agent Marketplace (Base Sepolia). You
   need its **agent id** (the ERC-721 token id — e.g. `0x16ec`, or the decimal `5868`)
   and the **private key of the owner EOA** that owns that token. The verifier rejects
   unknown agents (`"agent not found in registry"`) and authenticates the owner
   signature against the on-chain owner. Register at
   [agent-registry.horizenlabs.io](https://agent-registry.horizenlabs.io) or ask the
   operator to mint one for you.
2. **A funded testnet wallet** on your chosen chain, holding **≥ your threshold across
   the whole ~3-day challenge window** (the 3 blocks sit at 3 points in that window;
   the wallet must have held `≥ T` at each). Simplest setup: use the **owner EOA itself**
   as the reserve wallet. Fund it from a faucet and leave it funded for 3+ days.
3. **The `prover`** — easiest via the **prebuilt Docker image** (below); no toolchain, no
   source. The image bakes the reproducible binary whose guest `image_id` matches the
   deployed verifier (`0x4f02…39e6`).
4. **A machine with a few CPU cores and time** — proving is CPU-heavy:
   **~15–30 minutes per challenge** (3 blocks; ~6 min/block measured on CPU). ~4 GB free
   RAM; a ≥16 GB CUDA GPU speeds it up but is optional.

### Get the prover (Docker — recommended)

The prover runs on **your** machine (it holds your wallet key — nothing sensitive is
sent to the service). The turnkey image needs no build:

```bash
docker pull ghcr.io/drgora/por-prover:latest
```

> If the pull 403s, the operator hasn't published it yet — build it yourself:
> `deploy/prover/build.sh` (after `cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover`).
> The image ENTRYPOINT is the prover, so `docker run … <image> <prover-args>` just works.

**Or build from source.** Obtain this repo, then
`cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover` (needs **Rust ≥ 1.95**,
**Docker**, and the RISC Zero toolchain via `rzup` / **r0vm 3.0.4**). The `RISC0_USE_DOCKER=1`
is mandatory: a plain build produces a machine-specific `image_id` and every proof is
rejected with a claim-digest / image-id mismatch. First build also compiles the
TLSNotary/MPC-TLS stack (heavy, one-time).

---

## Supported chains

Pass the **selector** as `--chain-id`; in this testnet deployment it resolves to the
paired testnet, and the proof commits the real testnet chain id.

| `--chain-id` | Proves reserves on | Coin | Notes |
|:---:|---|:---:|---|
| **`1`** | **Sepolia** (`11155111`) | test ETH | **Recommended** — keyless deep archive, smoothest path |
| `10` | Optimism Sepolia (`11155420`) | test ETH | deep window may need an archive `eth_getProof` endpoint |
| `8453` | Base Sepolia (`84532`) | test ETH | deep window needs an archive `eth_getProof` endpoint |

For `10` / `8453` over the full 3-day window, set an archive proof endpoint on the
**prover**: `POR_RPC_URL_11155420=<url>` / `POR_RPC_URL_84532=<url>` (free-with-signup
archive keys work). Sepolia (`--chain-id 1`) needs no key.

---

## Path A — one command (recommended)

Connected mode does the whole flow — request → prove → submit → print verdict. With Docker:

```bash
docker run --rm \
  -e POR_PRIVATE_KEY=<32-byte hex of your owner+reserve wallet> \
  -e NOTARY_ADDR=hayabusa.proxy.rlwy.net:39286 \
  ghcr.io/drgora/por-prover:latest \
    --verifier https://verifier-production-d672.up.railway.app \
    --agent-id <your-agent-id> \
    --threshold 50000000000000000 \
    --chain-id 1
```

Or with a source build, the same args after `por-risc0/target/release/prover` (and
`NOTARY_ADDR`/`POR_PRIVATE_KEY` as normal env vars).

- `--threshold` is in **wei** of the native coin. `50000000000000000` = 0.05 ETH.
  Set it to any value **≤ your (combined) wallet balance** across the window.
- `NOTARY_ADDR` is **required** — this deployment demands a TLSNotary attestation.
- The command exits `0` on `verified`, non-zero otherwise, and prints the reason.

**Multiple reserve wallets?** Set `POR_PRIVATE_KEY` to a **comma-separated list** of keys —
`POR_PRIVATE_KEY=<key1>,<key2>,<key3>`. The prover proves that the wallets' **combined**
native balance is ≥ `--threshold`, in one proof; the individual balances, the addresses, and
the number of wallets all stay private. (The wallets must be distinct.) This is the usual
proof-of-reserves shape: reserves split across cold + hot wallets aggregate into a single
proof.

**Separate reserve wallet(s) from owner?** If the wallet(s) you're proving are *not* the
agent's registered owner, set both: `POR_PRIVATE_KEY=<reserve key(s)>` (their combined balance
is proven) and `POR_OWNER_KEY=<registered owner EOA>` (signs the challenge). If the (single)
reserve wallet *is* the owner, `POR_PRIVATE_KEY` alone is enough — the owner signature falls
back to its first key.

---

## Path B — HTTP API (drive it yourself)

For an agent that orchestrates over HTTP and only shells out to the prover for the
proving step.

### 1. Request a challenge

```bash
curl -sS -X POST https://verifier-production-d672.up.railway.app/v1/challenges \
  -H 'content-type: application/json' \
  -d '{"agent_id":"0x16ec","threshold":"50000000000000000","chain_id":1}' \
  > challenge.json
```

`threshold` is a decimal (or `0x`-hex) **wei** string; `chain_id` is optional (default
`1`). Response — HTTP `201`:

```json
{
  "challenge_id": "…32 hex chars…",
  "agent_id": "0x16ec",
  "threshold": "50000000000000000",
  "chain_id": 11155111,
  "nonce": "0x…64 hex…",
  "head_block": 12345678,
  "blocks": [12300011, 12315402, 12331990],
  "issued_at": 1751328000,
  "expires_at": 1751331600
}
```

`chain_id` in the response is the **resolved** testnet id (`11155111` for Sepolia).
The challenge **expires in 1 hour** (`expires_at`). Error responses:
`400` (bad threshold / `unsupported chain_id` with a `supported` list),
`404` (`agent not found in registry`).

### 2. Prove the challenge

```bash
POR_PRIVATE_KEY=<32-byte hex>[,<32-byte hex>…] \
NOTARY_ADDR=hayabusa.proxy.rlwy.net:39286 \
  por-risc0/target/release/prover \
    --challenge challenge.json \
    --out response.json
```

The threshold, chain, and blocks all come from the challenge — you don't repeat them.
This is the slow step (~15–30 min).

### 3. Submit the response

The body carries three CBOR receipts (~1.5 MB), so stream it from the file with
`--data-binary @` — do not inline it.

```bash
CID=$(jq -r .challenge_id challenge.json)
curl -sS -X POST \
  "https://verifier-production-d672.up.railway.app/v1/challenges/$CID/response" \
  -H 'content-type: application/json' \
  --data-binary @response.json
```

Response — HTTP `200`:

```json
{ "challenge_id": "…", "verdict": "verified" }
```

or `{ "challenge_id": "…", "verdict": "rejected", "reason": "…" }`.

### 4. Poll status (optional)

```bash
curl -sS "https://verifier-production-d672.up.railway.app/v1/challenges/$CID"
```

Returns `state`, the `verdict`/`reason`, and — once verified — the zkVerify/marketplace
settle progress under `kurier`.

### Response object

Whether you use Path A (`--out`) or Path B, the response the verifier consumes is:

```jsonc
{
  "version": "por-response-v1",
  "challenge": { /* the challenge, echoed */ },
  "owner_sig": "0x… 65-byte r‖s‖v signature over the challenge …",
  "bundles": [                     // exactly 3, one per challenged block
    {
      "proofType": "risc0",
      "proofOptions": { "version": "V3_0" },
      "proofData": {
        "proof":         "0x…",    // CBOR-encoded succinct receipt
        "vk":            "0x…",    // image_id (little-endian words)
        "publicSignals": "0x…"     // the guest journal bytes
      },
      "tlsnPresentation": "base64…" // the TLSNotary header attestation
    }
  ]
}
```

The journal (`publicSignals`) commits only
`{block_hash, threshold, chain_id, debug, challenge_nonce, agent_id, block_number}`.
Your balance and address are **not** in it.

---

## Verdicts & troubleshooting

| Symptom | Cause & fix |
|---|---|
| `agent not found in registry` (at step 1) | The `agent_id` isn't registered on the marketplace. Register it, or check the id (both `0x16ec` and `5868` work). |
| `owner signature recovered 0x… != registry owner 0x…` | `POR_OWNER_KEY` (or `POR_PRIVATE_KEY`) isn't the private key of the agent's registered owner EOA. |
| Prover exits before submitting: `cannot prove reserves: balance … < threshold …` | The wallet held less than `T` at one of the challenged blocks. Lower `--threshold`, or fund the wallet and keep it funded across the whole window before requesting a challenge. |
| `TLSNotary presentation required` | `NOTARY_ADDR` was unset or the notary was unreachable. Set `NOTARY_ADDR=hayabusa.proxy.rlwy.net:39286`. |
| Claim-digest / `image_id` mismatch on submit | The prover wasn't built with `RISC0_USE_DOCKER=1`, so its guest `image_id` differs from the verifier's. Rebuild with Docker. |
| `block set mismatch` | The response answers a different challenge than the one you submitted it to. Prove and submit the *same* `challenge.json`. |
| `challenge expired` | More than 1 hour passed. Request a fresh challenge (proving takes minutes, so start promptly). |
| `unsupported chain_id …` | Use `1`, `10`, or `8453`. |
| RPC timeouts while proving on `10` / `8453` | The default proof RPC can't serve deep historical `eth_getProof`. Set `POR_RPC_URL_11155420` / `POR_RPC_URL_84532` to an archive endpoint, or use `--chain-id 1`. |

---

## For humans — prove in your browser

No CLI, no key handling: a web page where you **connect a browser wallet** (MetaMask,
Rabby, …), pick a threshold, and sign. The private key never leaves your wallet — the
page hands the prover only *signatures*.

**Two ways to run it:**

- **Hosted** — open the URL your operator provides and go. (Their server does the
  proving, so it sees your address & balance while building the proof — moot on testnet,
  but worth knowing.)
- **Local (private)** — run it yourself; your address & balance never leave your machine:

  ```bash
  docker run --rm -p 8080:8080 ghcr.io/drgora/por-prove-web:latest
  # then open http://localhost:8080  → "Prove reserves"
  ```
  (If the pull 403s, the operator hasn't published it — build with `deploy/prove-web/build.sh`.)
  Needs ~4 GB free RAM for proving.

**Two wallet roles** (you can use one wallet for both, but keeping them separate is
**recommended** — it leaves the funded wallet unlinkable from your public agent identity):

- **Reserves wallet F** — the account whose native balance you're proving. Its address stays
  private (in-circuit). It need **not** be the agent's owner.
- **Owner O** — the agent's registered owner. It authorizes the challenge so the verifier can
  authenticate the agent. Both must be accounts you can select in the same browser wallet.

**The flow on the page:**

1. **Connect your reserves wallet F** — the treasury whose balance you want to prove (ideally
   *not* your agent's owner account).
2. Enter your **agent ID**, pick a **chain** (Sepolia / OP Sepolia / Base Sepolia), and a
   **threshold** in the coin (e.g. `0.05`).
3. Click **Prove reserves**. You'll sign **one message per challenged block with F** (proving
   ownership of the funds), then the page prompts you to **switch to the owner account O** in
   your wallet and sign the **challenge + a one-time identity**. Signing only: **no gas, no
   network switch.** (If F and O are the same account, no switch is needed.)
4. Proving runs (a few minutes); the page shows progress, then the **verdict** and a link
   to your agent in the directory.

Same prerequisites as the agent flow (registered agent + a wallet funded above the threshold
across the window — that's the reserves wallet F). It uses the exact same verifier, notary,
and proof — just with the wallets signing in the browser instead of keys on the command line.
The split mirrors the CLI's `POR_PRIVATE_KEY` (reserves) vs `POR_OWNER_KEY` (owner).

## Optional — appear in the marketplace directory

A `verified` verdict is the core deliverable. Separately, the verifier forwards verified
proofs to be recorded on-chain (Base Sepolia `recordValidation`), after which your agent
shows up in the [directory UI](https://ui-production-3e28.up.railway.app) with its
proof history. For that on-chain recording to succeed, your proofs must additionally bind
your **marketplace identity**: prove with `POR_AGENT_TOKEN_ID=<your numeric token id>`
and `POR_AGENT_SECRET=<32-byte hex>`, and register the matching commitment on the
gateway once (`registerAgentCommitment`). This is advanced and gateway-specific — ask the
operator for the identity-binding values. Without it you still get a valid `verified`
verdict; you just won't be listed.

---

## Quick reference

```
Verifier   POST https://verifier-production-d672.up.railway.app/v1/challenges
           POST https://verifier-production-d672.up.railway.app/v1/challenges/{id}/response
           GET  https://verifier-production-d672.up.railway.app/v1/challenges/{id}
Notary     NOTARY_ADDR=hayabusa.proxy.rlwy.net:39286
Chains     --chain-id 1 (Sepolia) · 10 (OP Sepolia) · 8453 (Base Sepolia)
Threshold  wei of native coin, e.g. 0.05 ETH = 50000000000000000
Keys       POR_PRIVATE_KEY = reserve wallet key, or a comma-separated list (combined balance proven);  POR_OWNER_KEY = registered owner (falls back to POR_PRIVATE_KEY's first key)
Build      cd por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover
```
