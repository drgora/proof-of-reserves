//! The supported-chain registry: the single source of truth mapping a `chain_id` to the
//! RPC endpoint its state is read from AND the TLSNotary-attested server name that vouches
//! for it. Imported by BOTH the prover (which fetches + attests against it) and the verifier
//! (which binds `journal.chain_id`'s expected host to the attested presentation), so the
//! chain-identity trust anchor can never drift between the two sides.
//!
//! ## Why the host binding matters
//!
//! `chain_id` is NOT part of an Ethereum block header and is not proven on-chain -- the guest
//! simply commits whatever `chain_id` the host wrote. Chain identity therefore rests entirely
//! on the TLSNotary attestation proving that a *named RPC* served the header. The verifier
//! must check that the attested server name equals [`ChainSpec::rpc_host`] for the claimed
//! `chain_id`; otherwise a prover could commit `chain_id = 1` (mainnet) while attesting a
//! header served by a cheap testnet endpoint. This table is that allowlist.
//!
//! ## Mainnets and testnets
//!
//! Both mainnets and testnets are first-class rows keyed by their REAL `chain_id`, so all
//! resolution downstream of chain selection (fetch endpoint, attested host, policy) works by
//! the real id and is mode-agnostic. Selection is the only place the global testnet flag
//! applies: [`resolve_chain`] turns a mainnet *selector* (e.g. `1`) into its paired testnet
//! (Sepolia) when `testnet` is set -- so the same `--chain-id 1` command runs end-to-end
//! against testnets by flipping one flag, while the journal still commits the real testnet id.
//!
//! ## Split header / proof endpoints
//!
//! `debug_getRawHeader` (the header) and `eth_getProof` (the account proof) are fetched from
//! DIFFERENT endpoints, because they have different retention needs. The header comes from
//! `rpc_host` -- a `*.drpc.org` endpoint (shared wildcard ECDSA P-256 cert, TLS 1.2 +
//! `ECDHE-ECDSA-AES128-GCM-SHA256`, the TLSNotary-compatible suite) that serves
//! `debug_getRawHeader` at any depth and is the attested host. The proof comes from `rpc_url`,
//! which must be ARCHIVE-capable for the multi-day window (pruned free nodes only hold ~128
//! recent blocks of state) but need not serve `debug_` or even be drpc. This split is what lets
//! free/mixed endpoints work: e.g. Sepolia header from `sepolia.drpc.org` + proof from the EF
//! DevOps public archive; Base header from `base.drpc.org` + proof from `mainnet.base.org`.

/// A supported EVM chain: how to read its state and who vouches for its identity.
#[derive(Debug, Clone, Copy)]
pub struct ChainSpec {
    /// EIP-155 chain id, committed publicly in the guest journal.
    pub chain_id: u32,
    /// Human-readable name (surfaced in verdicts / UI).
    pub name: &'static str,
    /// Default endpoint for the ACCOUNT PROOF (`eth_getProof`). This is the one call that needs
    /// ARCHIVE state for the multi-day challenge window, so it is SEPARATE from the header
    /// endpoint (below) and points at an archive-capable RPC -- which need not be drpc and need
    /// not serve `debug_`. NOT security-critical (the proof is self-verifying against the
    /// header's state_root in-circuit), so it is env-overridable via `POR_RPC_URL_<chain_id>`.
    pub rpc_url: &'static str,
    /// The TLSNotary-attested server name (DNS) that vouches for this chain's headers. This IS
    /// the trust anchor: the verifier requires the attested presentation's server name to equal
    /// this. It also serves as the HEADER endpoint (`https://{rpc_host}`) -- a full node there
    /// serves `debug_getRawHeader` at ANY depth (headers are never pruned, only state), so the
    /// header endpoint does not need archive state. Never overridable by env (trust anchor).
    pub rpc_host: &'static str,
    /// Approximate block time, seconds. Used only to size the challenge window in blocks
    /// (so "3 days" is the right block count on a fast L2); not security-relevant -- the owner
    /// signature binds the concrete block set regardless.
    pub block_time_secs: u64,
    /// True for a test network.
    pub testnet: bool,
    /// For a mainnet chain, the `chain_id` of its paired testnet (what a mainnet selector
    /// resolves to under the global testnet flag). `None` if no supported testnet, or if this
    /// row is itself a testnet.
    pub testnet_id: Option<u32>,
}

/// The supported-chain allowlist. EVM chains that mirror Ethereum's state model (EIP-1186
/// account proofs, RLP headers with `state_root` at item 3 / `number` at item 8, secp256k1
/// ownership) and are reachable + TLSNotary-compatible via drpc.
///
/// Absent by measurement (drpc does not serve `debug_getRawHeader` for them): Arbitrum One /
/// Arbitrum Sepolia (Nitro), Polygon Amoy, BNB testnet -- so Polygon PoS and BNB have no
/// paired testnet here.
pub const CHAINS: &[ChainSpec] = &[
    // ---- mainnets ----
    ChainSpec {
        chain_id: 1,
        name: "Ethereum",
        rpc_url: "https://eth.drpc.org",
        rpc_host: "eth.drpc.org",
        block_time_secs: 12,
        testnet: false,
        testnet_id: Some(11155111), // Sepolia
    },
    ChainSpec {
        chain_id: 10,
        name: "Optimism",
        // drpc free tier serves getProof only for recent state; for the multi-day window set
        // POR_RPC_URL_10 to an OP-mainnet archive endpoint.
        rpc_url: "https://optimism.drpc.org",
        rpc_host: "optimism.drpc.org",
        block_time_secs: 2,
        testnet: false,
        testnet_id: Some(11155420), // Optimism Sepolia
    },
    ChainSpec {
        chain_id: 56,
        name: "BNB Smart Chain",
        rpc_url: "https://bsc.drpc.org", // deep-window getProof may need POR_RPC_URL_56 (archive)
        rpc_host: "bsc.drpc.org",
        block_time_secs: 3,
        testnet: false,
        testnet_id: None, // BNB testnet: drpc doesn't serve debug_getRawHeader
    },
    ChainSpec {
        chain_id: 137,
        name: "Polygon PoS",
        rpc_url: "https://polygon.drpc.org", // deep-window getProof may need POR_RPC_URL_137 (archive)
        rpc_host: "polygon.drpc.org",
        block_time_secs: 2,
        testnet: false,
        testnet_id: None, // Polygon Amoy: drpc doesn't serve debug_getRawHeader
    },
    ChainSpec {
        chain_id: 8453,
        name: "Base",
        // base.drpc.org won't route getProof at all; Coinbase's public endpoint is archive
        // (measured deep). Header still comes from base.drpc.org (rpc_host, serves debug_).
        rpc_url: "https://mainnet.base.org",
        rpc_host: "base.drpc.org",
        block_time_secs: 2,
        testnet: false,
        testnet_id: Some(84532), // Base Sepolia
    },
    // ---- testnets (real chain ids; paired to a mainnet above) ----
    ChainSpec {
        chain_id: 11155111,
        name: "Sepolia",
        // sepolia.drpc.org is pruned (no historical state); EF DevOps public endpoint is a
        // free keyless archive (measured deep). Header still comes from sepolia.drpc.org.
        rpc_url: "https://rpc.sepolia.ethpandaops.io",
        rpc_host: "sepolia.drpc.org",
        block_time_secs: 12,
        testnet: true,
        testnet_id: None,
    },
    ChainSpec {
        chain_id: 11155420,
        name: "Optimism Sepolia",
        rpc_url: "https://optimism-sepolia.drpc.org", // deep-window getProof may need POR_RPC_URL_11155420
        rpc_host: "optimism-sepolia.drpc.org",
        block_time_secs: 2,
        testnet: true,
        testnet_id: None,
    },
    ChainSpec {
        chain_id: 84532,
        name: "Base Sepolia",
        // No free KEYLESS deep archive exists for Base Sepolia (all free endpoints cap
        // eth_getProof to recent state). thirdweb serves getProof within ~10k blocks of head,
        // so it works keyless with a SHORT window (POR_WINDOW_DAYS=1 POR_SLOT_SECONDS=15 ->
        // ~5760 blocks) -- fine for a testnet. For the full multi-day window set POR_RPC_URL_84532
        // to a free-with-signup archive (e.g. Alchemy base-sepolia). Header comes from rpc_host.
        rpc_url: "https://84532.rpc.thirdweb.com",
        rpc_host: "base-sepolia.drpc.org",
        block_time_secs: 2,
        testnet: true,
        testnet_id: None,
    },
];

/// Look up the [`ChainSpec`] for a real chain id, or `None` if unsupported.
pub fn chain_spec(chain_id: u32) -> Option<&'static ChainSpec> {
    CHAINS.iter().find(|c| c.chain_id == chain_id)
}

/// True if `chain_id` is a supported chain (mainnet or testnet).
pub fn is_supported(chain_id: u32) -> bool {
    chain_spec(chain_id).is_some()
}

/// The TLSNotary-attested server name that vouches for `chain_id`'s headers -- the value the
/// verifier must match the attested presentation against. Errors for an unsupported chain.
pub fn expected_host(chain_id: u32) -> Result<&'static str, String> {
    chain_spec(chain_id)
        .map(|c| c.rpc_host)
        .ok_or_else(|| format!("unsupported chain_id {chain_id}"))
}

/// Resolve a requested chain *selector* to the effective [`ChainSpec`], honoring the global
/// testnet flag. This is the ONE place selection semantics live:
///
/// - `testnet = true`: a mainnet selector (e.g. `1`) resolves to its paired testnet (Sepolia);
///   a testnet id is accepted as-is. A mainnet with no paired testnet is an error.
/// - `testnet = false`: mainnet selectors resolve to themselves; a testnet id is rejected, so a
///   mainnet verifier can't be asked to treat testnet reserves as real.
///
/// The returned spec's `chain_id` is the real, effective id that flows into the challenge,
/// journal, and host binding.
pub fn resolve_chain(selector: u32, testnet: bool) -> Result<&'static ChainSpec, String> {
    let base = chain_spec(selector).ok_or_else(|| format!("unsupported chain_id {selector}"))?;
    if testnet {
        if base.testnet {
            Ok(base)
        } else {
            let t = base.testnet_id.ok_or_else(|| {
                format!("chain {} ({}) has no supported testnet", selector, base.name)
            })?;
            chain_spec(t).ok_or_else(|| format!("paired testnet {t} missing from registry"))
        }
    } else if base.testnet {
        Err(format!(
            "chain_id {selector} ({}) is a testnet; run with POR_TESTNET=1 to use testnets",
            base.name
        ))
    } else {
        Ok(base)
    }
}

/// Selector ids to advertise in the given mode (for error hints / startup logs). In testnet
/// mode: the mainnet ids that have a paired testnet (keep using the mainnet id). In mainnet
/// mode: the mainnet ids.
pub fn selectable_ids(testnet: bool) -> Vec<u32> {
    CHAINS
        .iter()
        .filter(|c| !c.testnet && (if testnet { c.testnet_id.is_some() } else { true }))
        .map(|c| c.chain_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_present_and_bound() {
        let eth = chain_spec(1).expect("mainnet must be supported");
        assert_eq!(eth.rpc_host, "eth.drpc.org");
        assert_eq!(expected_host(1).unwrap(), "eth.drpc.org");
    }

    #[test]
    fn unsupported_chain_rejected() {
        assert!(chain_spec(999_999).is_none());
        assert!(!is_supported(80002)); // polygon amoy: not in the allowlist
        assert!(expected_host(999_999).is_err());
    }

    #[test]
    fn ids_unique_and_hosts_distinct() {
        for (i, a) in CHAINS.iter().enumerate() {
            for b in &CHAINS[i + 1..] {
                assert_ne!(a.chain_id, b.chain_id, "duplicate chain_id {}", a.chain_id);
                assert_ne!(a.rpc_host, b.rpc_host, "duplicate rpc_host {}", a.rpc_host);
            }
            assert!(a.block_time_secs > 0, "{} has zero block time", a.name);
        }
    }

    #[test]
    fn every_testnet_pairing_resolves() {
        for c in CHAINS.iter().filter(|c| !c.testnet) {
            if let Some(t) = c.testnet_id {
                let ts = chain_spec(t).unwrap_or_else(|| panic!("{} pairs to missing testnet {t}", c.name));
                assert!(ts.testnet, "{} paired to non-testnet {t}", c.name);
            }
        }
    }

    #[test]
    fn resolve_chain_honors_mode() {
        // testnet flag translates the mainnet selector to its paired testnet
        assert_eq!(resolve_chain(1, true).unwrap().chain_id, 11155111);
        assert_eq!(resolve_chain(10, true).unwrap().chain_id, 11155420);
        assert_eq!(resolve_chain(8453, true).unwrap().chain_id, 84532);
        // mainnet mode: selector resolves to itself
        assert_eq!(resolve_chain(1, false).unwrap().chain_id, 1);
        // a testnet id is accepted as-is under the flag, rejected without it
        assert_eq!(resolve_chain(11155111, true).unwrap().chain_id, 11155111);
        assert!(resolve_chain(11155111, false).is_err());
        // a mainnet with no supported testnet errors under the flag
        assert!(resolve_chain(56, true).is_err());
        assert!(resolve_chain(137, true).is_err());
        // unknown chain errors either way
        assert!(resolve_chain(999_999, true).is_err());
    }

    #[test]
    fn selectable_ids_by_mode() {
        assert_eq!(selectable_ids(false), vec![1, 10, 56, 137, 8453]);
        assert_eq!(selectable_ids(true), vec![1, 10, 8453]); // only chains with a paired testnet
    }
}
