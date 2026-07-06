# Railway deployment

Deploys the Proof-of-Reserves stack as **5 Railway services** in one project, all
from this repo. The **Root Directory** is the one setting that makes each service
build the right thing (see "Create the services" — do not skip it):

| Service     | Process                     | Root Directory (set this)  | Config-as-code path            | Exposure               |
|-------------|-----------------------------|----------------------------|--------------------------------|------------------------|
| `notary`    | `notary` (Rust, raw TCP)    | `deploy/railway/notary`    | auto (`railway.json` in dir)   | **public TCP proxy**   |
| `verifier`  | `verifier` (Rust, HTTP)     | `deploy/railway/verifier`  | auto (`railway.json` in dir)   | **public HTTPS domain**|
| `adapter`   | `node sepolia-registry.mjs` | `app/web`                  | `deploy/railway/adapter.json`  | private (internal)     |
| `submitter` | `node submitter.mjs`        | `app/web`                  | `deploy/railway/submitter.json`| private (internal)     |
| `ui`        | `vite` dev server           | `app/web`                  | `deploy/railway/ui.json`       | **public HTTPS domain**|

> **The two Rust services live in their own subdirectories** (`deploy/railway/notary`,
> `deploy/railway/verifier`), each with its own `Dockerfile` + `railway.json`. Point
> the service's Root Directory there and Railway auto-detects both — no config path to
> set, and it can never pick up the wrong Dockerfile. The three Node services share
> `app/web` (one Dockerfile), so they differ only by their config-as-code file.

The **prover is not deployed** — it runs on the agent's own machine (heavy Risc0
proving) and connects *in* to the public `verifier` (HTTP) and `notary` (raw TCP).

```
              external agent (prover)
                 │                 │
      HTTP (challenge/response)   raw TCP (MPC-TLS attest)
                 ▼                 ▼
          ┌────────────┐     ┌──────────┐
          │  verifier  │     │  notary  │   ← Railway TCP Proxy + Volume(/data)
          └─────┬──────┘     └──────────┘
     owner lookup│ └─ forward verified bundles ┐
                 ▼                              ▼
          ┌────────────┐   PIPELINE_URL   ┌────────────┐
   /api ← │  adapter   │ ───────────────▶ │ submitter  │ → Kurier + Base Sepolia
          └────────────┘                  └────────────┘   (recordValidation)
                 ▲
       vite proxies /api (server-side, private)
                 │
          ┌────────────┐
   users →│     ui     │
          └────────────┘
```

Services talk to each other over Railway's **private network** at
`<service-name>.railway.internal`. Name the services exactly `adapter`,
`submitter`, `notary`, `verifier`, `ui` so the hostnames below resolve. Private
networking is IPv6 — the Node services bind `::` by default (fine) and the Rust
services are told to bind `[::]` in their start commands.

The two private services (`adapter`, `submitter`) pin a fixed `PORT` (8090 / 8092)
so (a) peers can address them at `<svc>.railway.internal:<port>` and (b) Railway's
healthcheck and port-detection target the same port the app listens on. If a
healthcheck ever blocks a deploy, remove `healthcheckPath` from that service's
config — it's optional.

---

## FIRST (do this before deploying notary/verifier): build & push the runtime image

The `notary`/`verifier` Dockerfiles are just `FROM ghcr.io/horizenlabs/por-risc0-runtime`.
**That image must exist and be pullable by Railway, or those two builds fail at the
`FROM`** (`failed to pull` / `unauthorized`). Build + push it first:

```bash
docker login ghcr.io                       # GitHub PAT with write:packages
deploy/railway/build-and-push.sh           # builds guest reproducibly, pushes image
```

Then in GitHub, make the GHCR package **public** (Packages → the package → Settings →
Change visibility), or add **private-registry credentials** in Railway. Verify from
another machine: `docker pull ghcr.io/horizenlabs/por-risc0-runtime:latest`.

- Push to a path you control and update the `FROM` line in
  `deploy/railway/{notary,verifier}/Dockerfile` (default
  `ghcr.io/horizenlabs/por-risc0-runtime:latest`), or set `RISC0_RUNTIME_IMAGE` for
  the script.
- **Re-run this and redeploy `notary`+`verifier` whenever the guest changes** — a
  verifier built from a different guest rejects every real proof (image_id mismatch).
  See the note in `build-and-push.sh`.

The binaries are staged to `deploy/railway/bin/` (git-ignored) and never committed.

---

## Create the services

**`notary` and `verifier`** (Root Directory does everything):

1. **New Service → GitHub Repo** → this repo.
2. **Settings → Root Directory** → `deploy/railway/notary` (or `.../verifier`).
   Railway auto-detects the `railway.json` + `Dockerfile` sitting there. Leave the
   config-as-code path empty — do **not** point it at the repo root.
3. Set **Variables** + Networking (below).

**`adapter`, `submitter`, `ui`** (share `app/web`, so they need the config path):

1. **New Service → GitHub Repo** → this repo.
2. **Settings → Root Directory** → `app/web`.
3. **Settings → Config-as-code** → `deploy/railway/adapter.json` (repo-root-relative;
   or `submitter.json` / `ui.json`). This sets the start command + healthcheck.
   *Alternative:* leave config empty and set a **Custom Start Command** in the
   dashboard instead (`node sepolia-registry.mjs` / `node submitter.mjs` /
   `npm run dev -- --host 0.0.0.0 --port $PORT`).
4. Set **Variables** + Networking (below).

> Why subdirs for the Rust services: with Root Directory pointing at a folder that
> contains exactly one `Dockerfile` named `Dockerfile`, Railway can't misresolve the
> path or fall back to a repo-root Dockerfile — the failure mode that bit the first
> attempt. The configs use `builder: DOCKERFILE` with **no** `dockerfilePath`, so the
> default (`Dockerfile` in the Root Directory) always resolves correctly.

---

## Networking

- **`ui`** — add a **public domain** (Settings → Networking → Generate Domain).
  Railway routes it to the vite server on `$PORT`.
- **`verifier`** — add a **public domain**. This is the URL agents pass as
  `--verifier https://<verifier-domain>`.
- **`notary`** — add a **TCP Proxy** (Settings → Networking → TCP Proxy). Railway
  gives you `<host>.proxy.rlwy.net:<port>`. Agents pass this as
  `NOTARY_ADDR=<host>.proxy.rlwy.net:<port>`. (The notary speaks raw TLSNotary
  MPC-TLS, not HTTP, so it needs a TCP proxy — a normal HTTP domain won't work.)
- **`adapter`**, **`submitter`** — **no public networking**; reached only over the
  private network by `verifier`/`ui`/`adapter`.

---

## Volume (notary)

The notary persists its secp256k1 signing key to `notary-signing-key.bin` in its
working directory (`/data`). Attach a **Volume** to the `notary` service mounted at
`/data` so the key survives restarts/redeploys. Without it, the notary mints a new
identity on every boot.

- First boot generates a fresh key on the volume. To reuse an existing notary key,
  upload your `notary-signing-key.bin` into the volume once (e.g. via a temporary
  shell), then restart.

---

## Variables

Secrets (🔒) go in Railway variables, never in the repo. `$PORT` is injected by
Railway for the public services; the private services pin their port so peers can
address them.

### `adapter`
```
PORT=8090
POR_AGENT_IDS=0x16ec                       # your marketplace agent id(s), comma-separated
PIPELINE_URL=http://submitter.railway.internal:8092/pipeline
# optional overrides (defaults target Base Sepolia):
# BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
# IDENTITY_REGISTRY=0x8004A818BFB912233c491871b3d84c89A494BD9e
# VALIDATION_GATEWAY=0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920
# RECEIPTS_FROM_BLOCK=<block>              # narrow the on-chain receipt scan
```

### `submitter`
```
PORT=8092                                  # aligns Railway's healthcheck/port-detect
SUBMITTER_PORT=8092                        # the port the app actually reads
PRIVATE_KEY=0x...            🔒            # Base Sepolia wallet (gas + protocol fee)
KURIER_API_KEY=...           🔒            # testnet Kurier key
# optional (defaults shown in submitter.mjs):
# BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
# KURIER_API_URL=https://api-testnet.kurier.xyz
# DOMAIN_ID=2
```
> Mirror whatever you set in your local `.env` / `por-tmux.sh` for the submitter —
> those are the same keys used by the recordValidation pipeline today.

### `notary`
```
# NOTARY_ADDR is set from $PORT by the start command — nothing to add.
# (Attach the /data volume; see above.)
```

### `verifier`  (production mode — no dev/allow flags)
```
POR_REGISTRY_URL=http://adapter.railway.internal:8090
POR_SUBMITTER_URL=http://submitter.railway.internal:8092
# optional:
# POR_WINDOW_DAYS=3
# POR_TESTNET=1                            # set ONLY if proving testnet chains
# POR_RPC_URL_1=https://<archive-endpoint> # per-chain head-pin endpoint (id = chain id)
```
> Do **not** set `KURIER_API_KEY` here — the verifier forwards verified bundles to
> the submitter, which owns Kurier settlement. Do **not** set `POR_ALLOW_DEBUG`,
> `POR_ALLOW_NO_PRESENTATION`, or `POR_ALLOW_UNVERIFIED_OWNER` — those disable
> production checks.

### `ui`
```
API_PROXY=http://adapter.railway.internal:8090
```

---

## Running the prover against the deployment

From the agent machine (unchanged flow, just remote endpoints):

```bash
POR_PRIVATE_KEY=<32B-hex> POR_OWNER_KEY=<32B-hex> \
NOTARY_ADDR=<host>.proxy.rlwy.net:<port> \
  por-risc0/target/release/prover \
    --verifier https://<verifier-domain> \
    --agent-id <agent-id> --threshold <wei> [--chain-id <id>]
```

The prover must build its guest with `RISC0_USE_DOCKER=1` so its `image_id` matches
the deployed verifier's.

---

## Notes / caveats

- **`ui` runs the vite dev server** (matches `docker-compose.yml`). It works behind
  Railway's HTTPS edge; HMR websockets may not connect but the app loads fine. For a
  hardened UI, switch to a static build + a server that also proxies `/api` (needs
  `preview.proxy` in `vite.config.ts`).
- **Runtime base is `debian:trixie-slim`** to match the glibc the binaries are built
  against. If a Rust service fails at startup on a missing `.so`, add it to the apt
  list in `Dockerfile.runtime` and re-push.
- **RPC egress**: `adapter`/`submitter` hit Base Sepolia; `verifier` head-pins each
  proven chain via its default (drpc) RPCs. For reliability on mainnet windows, set
  `POR_RPC_URL_<id>` to archive endpoints on the verifier.
