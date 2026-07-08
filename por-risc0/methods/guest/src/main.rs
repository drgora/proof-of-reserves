// Full proof-of-reserves guest: verify N Ethereum account-state Merkle-Patricia proofs
// against a single block header, hide every balance + address, prove that the COMBINED
// balance across the wallets >= threshold, and (unless debug) prove ownership of each
// address. Journal commits ONLY {block_hash, threshold, chain_id, debug, challenge_nonce,
// agent_id, block_number} -- identical whether one wallet or many, so the number of wallets,
// the individual balances, and the addresses all stay private.
//
// Multi-wallet: all wallets are read at the SAME block (one header, one state_root), so a
// single receipt attests the aggregate reserves at that block. Wallets MUST be supplied
// distinct and strictly ascending by address; the guest enforces this so the same wallet
// cannot be listed twice to double-count its balance into the sum.
//
// Precompiles: k256 (secp256k1 ecrecover) accelerated via the risc0 fork; keccak
// accelerated via the risc0 tiny-keccak fork (alloy's backend), so the MPT/header
// keccak runs on the coprocessor.
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::{Decodable, Header};
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use risc0_zkvm::guest::env;

// Fields we read out of the block-header RLP list (indices stable across forks):
//   item 3 = state_root (32 bytes), item 8 = block number (u64).
// The number is derived IN-CIRCUIT from the same header we keccak for block_hash, so it is
// unspoofable and bound to block_hash -- the verifier matches it against the challenge set.
struct HeaderFields {
    state_root: B256,
    number: u64,
}

fn extract_header_fields(header_rlp: &[u8]) -> HeaderFields {
    let mut buf: &[u8] = header_rlp;
    let outer = Header::decode(&mut buf).expect("header rlp");
    assert!(outer.list, "header is not an RLP list");
    // skip items 0,1,2 (parent_hash, ommers_hash, beneficiary)
    for _ in 0..3 {
        let h = Header::decode(&mut buf).expect("skip item");
        buf = &buf[h.payload_length..];
    }
    // item 3: state_root (32 bytes)
    let h = Header::decode(&mut buf).expect("state_root item");
    assert_eq!(h.payload_length, 32, "state_root not 32 bytes");
    let state_root = B256::from_slice(&buf[..32]);
    buf = &buf[32..];
    // skip items 4,5,6,7 (transactions_root, receipts_root, logs_bloom, difficulty)
    for _ in 0..4 {
        let h = Header::decode(&mut buf).expect("skip item");
        buf = &buf[h.payload_length..];
    }
    // item 8: block number -- RLP variable-length int; u64::decode consumes it and advances buf
    let number = u64::decode(&mut buf).expect("block number");
    HeaderFields { state_root, number }
}

// Private per-wallet witness: one account's state + its ownership signature. All wallets in
// a proof share the block header (hence the state_root and block_hash), so the header is read
// once, outside this struct.
struct Wallet {
    address: [u8; 20],
    nonce: u64,
    balance: u128,
    storage_hash: [u8; 32],
    code_hash: [u8; 32],
    account_proof: Vec<Vec<u8>>,
    sig: Vec<u8>, // empty when debug
}

fn main() {
    // ---- PRIVATE inputs ----
    let header_rlp: Vec<u8> = env::read();
    // Number of wallets whose balances are summed into the reserves. >= 1.
    let n_wallets: u32 = env::read();
    let mut wallets = Vec::with_capacity(n_wallets as usize);
    for _ in 0..n_wallets {
        let address: [u8; 20] = env::read();
        let nonce: u64 = env::read();
        let balance: u128 = env::read();
        let storage_hash: [u8; 32] = env::read();
        let code_hash: [u8; 32] = env::read();
        let account_proof: Vec<Vec<u8>> = env::read();
        let sig: Vec<u8> = env::read(); // empty when debug
        wallets.push(Wallet { address, nonce, balance, storage_hash, code_hash, account_proof, sig });
    }
    // ---- PUBLIC inputs (committed) ----
    let threshold: u128 = env::read();
    let chain_id: u32 = env::read();
    let debug: bool = env::read();
    // Opaque public labels echoed into the journal (NOT authenticated in-circuit -- their
    // authenticity is established by the verifier checking the owner signature over the
    // challenge). challenge_nonce ties the proof to a specific verifier challenge; agent_id
    // is keccak256(registry agent id).
    let challenge_nonce: [u8; 32] = env::read();
    let agent_id: [u8; 32] = env::read();
    // Marketplace (HL ValidationGatewayV2) binding fields.
    let agent_token_id: u64 = env::read(); // PUBLIC: ERC-721 token id from IdentityRegistry
    let agent_secret: [u8; 32] = env::read(); // PRIVATE: never committed raw

    assert!(n_wallets >= 1, "no wallets");

    // Header hash + fields (state_root, block number) from the attested RLP.
    let block_hash = keccak256(&header_rlp);
    let fields = extract_header_fields(&header_rlp);
    let state_root = fields.state_root;

    // EIP-191 personal_sign prehash of block_hash -- the message every wallet's owner signs
    // (same for all wallets; computed once). Skipped in debug (no ownership check).
    let msg_hash = if debug {
        None
    } else {
        let mut msg = Vec::with_capacity(60);
        msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        msg.extend_from_slice(block_hash.as_slice());
        Some(keccak256(&msg))
    };

    // Sum every wallet's balance in U256 (can't overflow a realistic total supply) and require
    // the COMBINED reserves to meet the threshold. Each wallet must (1) verify against the one
    // state_root, (2) be owned (unless debug), and (3) be distinct + ascending by address so a
    // wallet can't be double-counted.
    let mut total = U256::ZERO;
    let mut prev = [0u8; 20];
    for (i, w) in wallets.iter().enumerate() {
        // (0) Canonical ordering => distinct addresses (blocks listing the same wallet twice).
        assert!(i == 0 || w.address > prev, "wallets must be distinct and ascending by address");
        prev = w.address;

        // (1) Account MPT proof: reconstruct the trie account from the private fields and
        // verify it is the value at keccak(address) under state_root. A wrong balance
        // reconstructs a different account RLP and fails, binding `balance` to chain state.
        let account = TrieAccount {
            nonce: w.nonce,
            balance: U256::from(w.balance),
            storage_root: B256::from(w.storage_hash),
            code_hash: B256::from(w.code_hash),
        };
        let account_rlp = alloy_rlp::encode(&account);
        let key = Nibbles::unpack(keccak256(w.address));
        let proof: Vec<Bytes> = w.account_proof.iter().cloned().map(Bytes::from).collect();
        verify_proof(state_root, key, Some(account_rlp), &proof).expect("account MPT proof invalid");

        // (2) Ownership of the (private) address, unless debug.
        if let Some(msg_hash) = &msg_hash {
            let signature = Signature::from_slice(&w.sig[..64]).expect("bad signature");
            let recid = RecoveryId::from_byte(w.sig[64]).expect("bad recid");
            let vk = VerifyingKey::recover_from_prehash(msg_hash.as_slice(), &signature, recid)
                .expect("recover failed");
            let enc = vk.to_encoded_point(false);
            let signer = keccak256(&enc.as_bytes()[1..65]);
            assert_eq!(signer[12..32], w.address, "signer address != proven address");
        }

        total += U256::from(w.balance);
    }

    // (3) Threshold predicate on the aggregate (individual balances stay private).
    assert!(total >= U256::from(threshold), "combined balance below threshold");

    // (4) Commit only public values: {block_hash, threshold, chain_id, debug,
    // challenge_nonce, agent_id, block_number}. balance + address stay private.
    let bh: [u8; 32] = block_hash.into();
    env::commit(&bh);
    env::commit(&threshold);
    env::commit(&chain_id);
    env::commit(&debug);
    env::commit(&challenge_nonce);
    env::commit(&agent_id);
    env::commit(&fields.number);

    // Marketplace public signals, committed CONTIGUOUSLY so the gateway's fixed-length
    // _extractField can read them (a [u8;32] would word-expand to 128 non-contiguous bytes).
    // identity = keccak256(agent_secret): only the secret holder can produce a journal
    // matching the registered commitment. keccak (not Poseidon) -- accelerated in-guest, and
    // the gateway checks value==commitment, not which hash produced it.
    let identity = keccak256(&agent_secret);
    let id_limbs: [u64; 4] =
        core::array::from_fn(|i| u64::from_le_bytes(identity[i * 8..i * 8 + 8].try_into().unwrap()));
    env::commit(&agent_token_id); // u64     -> 8 contiguous LE bytes
    env::commit(&id_limbs); // [u64;4] -> 32 contiguous bytes
}
