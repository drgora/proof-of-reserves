// register-agent — self-custody agent registration on the HL Agent Marketplace (Base Sepolia).
//
// The PoR verifier authenticates an agent by recovering its challenge signature and matching the
// on-chain owner: `ecrecover(owner_sig) == IdentityRegistry.ownerOf(agentId)`. So an agent must
// OWN its ERC-721 AgentCard. `IdentityRegistry.register(agentURI)` sets `msg.sender` as owner —
// meaning you must register from the very wallet whose key you'll later use to authorize
// challenges (POR_OWNER_KEY on the CLI, or the owner account in the browser). This helper sends
// that one transaction from a key you provide; the key stays in this process and is never sent
// anywhere. It is both a CLI and an importable module (the MCP server's `register_agent` tool
// calls `registerAgent()`).
//
// Usage (CLI):
//   node register-agent.mjs --key 0x<32-byte owner key> --name "My Agent" \
//     [--description "..."] [--endpoint https://...] [--skills a,b] [--domains defi] \
//     [--rpc https://sepolia.base.org] [--dry-run]
//
// Env fallbacks: PRIVATE_KEY / POR_OWNER_KEY (key), BASE_SEPOLIA_RPC_URL (rpc),
//   IDENTITY_REGISTRY (contract).
//
// --dry-run builds + prints the agentURI and calldata WITHOUT sending (no key or gas needed;
// pass any --key or none). Useful to inspect the exact transaction, or to sign it elsewhere.

import {
  createPublicClient, createWalletClient, http as viemHttp,
  encodeFunctionData, parseEventLogs, toHex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { baseSepolia } from 'viem/chains'

const DEFAULT_RPC = process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org'
const DEFAULT_IDENTITY_REGISTRY = process.env.IDENTITY_REGISTRY || '0x8004A818BFB912233c491871b3d84c89A494BD9e'
const MARKETPLACE_URL = (process.env.MARKETPLACE_URL || 'https://agent-registry.horizenlabs.io').replace(/\/$/, '')

// IMPORTANT: use register(string), NOT safeMint/mint (per hl-registry-integration).
export const registerAbi = [
  {
    type: 'function', name: 'register', stateMutability: 'nonpayable',
    inputs: [{ name: 'agentURI', type: 'string' }],
    outputs: [{ name: 'agentId', type: 'uint256' }],
  },
  {
    type: 'event', name: 'Registered', anonymous: false,
    inputs: [
      { indexed: true, name: 'agentId', type: 'uint256' },
      { indexed: false, name: 'agentURI', type: 'string' },
      { indexed: true, name: 'owner', type: 'address' },
    ],
  },
]

/** Build the AgentCard metadata JSON the marketplace expects (ERC-8004 AgentCard shape). */
export function buildMetadata({ name, description, endpoint, skills = [], domains = [] }) {
  return {
    name: name || 'Proof-of-Reserves Agent',
    description: description || 'Proves control of native-coin reserves above a threshold, privately, via RISC Zero + TLSNotary.',
    services: [
      {
        name: 'proof-of-reserves',
        endpoint: endpoint || 'https://example.com',
        version: '0.1.0',
        skills: skills.length ? skills : ['proof-of-reserves'],
        domains: domains.length ? domains : ['defi'],
      },
    ],
    supportedTrust: ['zkVerify-risc0'],
    metadata: { proofSystem: 'risc0', product: 'proof-of-reserves' },
  }
}

/** metadata object -> base64 data: URI (the `agentURI` argument to register()). */
export function metadataToUri(metadata) {
  return `data:application/json;base64,${Buffer.from(JSON.stringify(metadata)).toString('base64')}`
}

const hexId = (id) => '0x' + id.toString(16)

/**
 * Register an agent on IdentityRegistry from `privateKey`.
 * @returns { agentId, agentIdHex, agentIdDec, owner, txHash, agentUri, marketplaceUrl }
 * With { dryRun: true } (or no key) returns { dryRun, agentUri, to, data } — nothing is sent.
 */
export async function registerAgent(opts = {}) {
  const {
    privateKey, name, description, endpoint, skills, domains,
    rpcUrl = DEFAULT_RPC, identityRegistry = DEFAULT_IDENTITY_REGISTRY, dryRun = false,
  } = opts

  const metadata = buildMetadata({ name, description, endpoint, skills, domains })
  const agentUri = metadataToUri(metadata)
  const data = encodeFunctionData({ abi: registerAbi, functionName: 'register', args: [agentUri] })

  if (dryRun || !privateKey) {
    return { dryRun: true, agentUri, to: identityRegistry, data, metadata }
  }

  const account = privateKeyToAccount(privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`)
  const publicClient = createPublicClient({ chain: baseSepolia, transport: viemHttp(rpcUrl) })
  const walletClient = createWalletClient({ account, chain: baseSepolia, transport: viemHttp(rpcUrl) })

  // Guard against the #1 support issue: an unfunded wallet. register() costs gas on Base Sepolia.
  const balance = await publicClient.getBalance({ address: account.address })
  if (balance === 0n) {
    throw new Error(
      `wallet ${account.address} has 0 Base Sepolia ETH — fund it from a Base Sepolia faucet before registering (gas is needed).`,
    )
  }

  const txHash = await walletClient.writeContract({
    address: identityRegistry, abi: registerAbi, functionName: 'register', args: [agentUri],
  })
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash })
  if (receipt.status !== 'success') throw new Error(`register() reverted (tx ${txHash})`)

  // Canonical source of the new token id: the Registered event.
  const logs = parseEventLogs({ abi: registerAbi, logs: receipt.logs, eventName: 'Registered' })
  const ev = logs.find((l) => l.args?.owner?.toLowerCase() === account.address.toLowerCase()) || logs[0]
  const agentId = ev?.args?.agentId
  if (agentId == null) {
    throw new Error(`registered (tx ${txHash}) but could not parse the agentId from the Registered event`)
  }
  return {
    agentId,
    agentIdHex: hexId(agentId),
    agentIdDec: agentId.toString(),
    owner: account.address,
    txHash,
    agentUri,
    marketplaceUrl: `${MARKETPLACE_URL}/agent/${hexId(agentId)}`,
  }
}

// --- CLI --------------------------------------------------------------------
function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (!a.startsWith('--')) continue
    const key = a.slice(2)
    const next = argv[i + 1]
    if (key === 'dry-run') out.dryRun = true
    else if (next && !next.startsWith('--')) { out[key] = next; i++ }
    else out[key] = true
  }
  return out
}

async function main() {
  const a = parseArgs(process.argv.slice(2))
  const key = a.key || process.env.PRIVATE_KEY || process.env.POR_OWNER_KEY
  const dryRun = !!a.dryRun
  if (!key && !dryRun) {
    console.error('need --key 0x<owner private key> (or PRIVATE_KEY / POR_OWNER_KEY), or --dry-run to just print the tx')
    process.exit(2)
  }
  const res = await registerAgent({
    privateKey: key,
    name: a.name,
    description: a.description,
    endpoint: a.endpoint,
    skills: a.skills ? String(a.skills).split(',').map((s) => s.trim()).filter(Boolean) : undefined,
    domains: a.domains ? String(a.domains).split(',').map((s) => s.trim()).filter(Boolean) : undefined,
    rpcUrl: a.rpc,
    identityRegistry: a['identity-registry'],
    dryRun,
  })
  if (res.dryRun) {
    console.log('DRY RUN — nothing sent. Build this transaction from your own wallet:')
    console.log(`  to:   ${res.to}`)
    console.log(`  data: ${res.data}`)
    console.log(`  agentURI: ${res.agentUri}`)
    return
  }
  console.log('Registered ✓')
  console.log(`  agent id : ${res.agentIdHex}  (decimal ${res.agentIdDec})`)
  console.log(`  owner    : ${res.owner}`)
  console.log(`  tx       : ${res.txHash}`)
  console.log(`  page     : ${res.marketplaceUrl}`)
  console.log('\nUse this agent id with the verifier, and authorize challenges with the SAME owner key.')
}

// Run as a CLI only when invoked directly (not when imported by the MCP server).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(`error: ${e.shortMessage || e.message || e}`)
    process.exit(1)
  })
}
