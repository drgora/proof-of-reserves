# External-user prover images

Two turnkey Docker images so external users can produce PoR proofs without a source build.
Both embed the **reproducible** prover (guest `image_id 0x4f02…39e6`, matching the deployed
verifier) — so **build the prover with Docker first**, then run a `build.sh`:

```bash
cd ../../por-risc0 && RISC0_USE_DOCKER=1 cargo build --release --bin prover
```

## `por-prover` — AI agents (CLI)

`deploy/prover/` · `ghcr.io/drgora/por-prover`. Slim image, `ENTRYPOINT prover` + baked `r0vm`.

```bash
deploy/prover/build.sh                 # build   (PUSH=1 to also push)
docker run --rm \
  -e POR_PRIVATE_KEY=<32B hex> \
  -e NOTARY_ADDR=hayabusa.proxy.rlwy.net:39286 \
  ghcr.io/drgora/por-prover:latest \
    --verifier https://verifier-production-d672.up.railway.app \
    --agent-id <id> --threshold <wei> --chain-id 1
```

## `por-prove-web` — humans (browser wallet)

`deploy/prove-web/` · `ghcr.io/drgora/por-prove-web`. One container = static SPA +
`prover-web.mjs` backend + prover + `r0vm` (`node:22-trixie-slim`, glibc 2.41 to match the
binary). The wallet signs in the browser; the key never reaches the container.

```bash
deploy/prove-web/build.sh              # builds the frontend + image (PUSH=1 to push)
docker run --rm -p 8080:8080 ghcr.io/drgora/por-prove-web:latest
# open http://localhost:8080 → "Prove reserves"
```

Env (defaults point at the live deployment): `VERIFIER_URL`, `NOTARY_ADDR`
(`none` disables attestation for dev), `REGISTRY_URL` (owner lookup + `/api` proxy),
`PORT`, `PUBLIC_DIR`, plus any `POR_*` the prover reads (passed through to the subprocess).

### Hosting `por-prove-web` on Railway (the "hosted for humans" option)

Add a 6th service: **New Service → this repo → Root Directory `deploy/railway/prove-web`**
(auto-detects its Dockerfile + railway.json, which pull `ghcr.io/drgora/por-prove-web`).
Generate a public domain (target port **8080**). Set these Variables:

```
PORT=8080
NOTARY_ADDR=notary.railway.internal:7150          # PRIVATE networking — see below
VERIFIER_URL=http://verifier.railway.internal:7100
REGISTRY_URL=http://adapter.railway.internal:8090
```

> **The notary MUST be reached over private networking, not the public TCP proxy.** The
> public proxy (`*.proxy.rlwy.net`) caps/mangles the long TLSNotary MPC session — measured
> with `notary_probe`: a local notary OKs in ~1.2 s, but the proxy EOFs mid-`commitment`
> after ~25 s. Railway **private networking** (`notary.railway.internal:7150`) is a *direct*
> container-to-container TCP connection (not a proxy), so it carries the session like a local
> connection does. Confirm before relying on it — from a shell on this service:
> `notary_probe --notary notary.railway.internal:7150` (baked into the image; expect `OK`).

Notes: the operator-hosted server sees each user's address + balance while proving (moot on
testnet); the **local** `docker run` keeps them on the user's machine. Proving is CPU-heavy
(~15–30 min, ~4 GB RAM) — size the instance accordingly; the backend already serializes to
one prove at a time.

**External CLI agents can't use the public-proxy notary** (same ~25 s cap). If you need the
agent (off-Railway) flow to attest, host the notary on something that exposes a real public
TCP port (a small VM / fly.io / a VPS) rather than Railway's TCP proxy, and give agents that
`NOTARY_ADDR`. Test any candidate endpoint with `notary_probe --notary <host:port>` first.

## GHCR publish

Same as the runtime image (see `../railway/README.md`): `docker login ghcr.io`, `PUSH=1
build.sh`, then make the package **public**. Re-push whenever the guest changes.
