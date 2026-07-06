// Base Sepolia chain facts for the HL Agent Marketplace, per the
// hl-registry-integration skill. The marketplace's identity + validation
// contracts live here; agents register on IdentityRegistry and record
// zkVerify-backed validations through ValidationGateway V2.
//
// These addresses are the *stable* entry points (the ValidationGateway is a
// UUPS proxy — always the address to call, even as its impl is upgraded).

export const NETWORK = 'Base Sepolia'
export const CHAIN_ID = 84532

/** Canonical explorer / marketplace bases (overridable per-response by the proxy). */
export const DEFAULT_BASESCAN = 'https://sepolia.basescan.org'
export const DEFAULT_MARKETPLACE = 'https://agent-registry.horizenlabs.io'

export type ContractInfo = { name: string; address: string; purpose: string }

/** Base Sepolia contracts the marketplace runs on (skill: "Contracts"). */
export const CONTRACTS: ContractInfo[] = [
  {
    name: 'IdentityRegistry',
    address: '0x8004A818BFB912233c491871b3d84c89A494BD9e',
    purpose: 'ERC-721 AgentCards — where agents register',
  },
  {
    name: 'ValidationGateway',
    address: '0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920',
    purpose: 'Records zkVerify-backed validations (V2 UUPS proxy)',
  },
  {
    name: 'ValidationRegistry',
    address: '0x75a7f712635D7918563659795450ddE6751D71BC',
    purpose: 'Immutable validation storage',
  },
  {
    name: 'zkVerify Attestation',
    address: '0x0807C544D38aE7729f8798388d89Be6502A1e8A8',
    purpose: 'Proof-aggregation relay from zkVerify',
  },
]

const trim = (u: string) => u.replace(/\/$/, '')

/** BaseScan link for the Base Sepolia `recordValidation` transaction. */
export const baseTxUrl = (base: string | undefined, hash: string) =>
  `${trim(base || DEFAULT_BASESCAN)}/tx/${hash}`

/** BaseScan link for an address (owner EOA, contract, …). */
export const baseAddressUrl = (base: string | undefined, addr: string) =>
  `${trim(base || DEFAULT_BASESCAN)}/address/${addr}`

/**
 * Canonical marketplace agent page: `.../agent/{tokenIdHex}`.
 * The registry keys agents by an ERC-721 token id. Decimal ids are converted
 * to hex (skill example: 2094 → 0x82e); values already in `0x…` form pass
 * through lowercased.
 */
export function marketplaceAgentUrl(base: string | undefined, agentId: string): string {
  const m = trim(base || DEFAULT_MARKETPLACE)
  const id = String(agentId || '').trim()
  let hex = id.toLowerCase()
  if (/^\d+$/.test(id)) {
    try {
      hex = '0x' + BigInt(id).toString(16)
    } catch {
      hex = id
    }
  }
  return `${m}/agent/${hex}`
}
