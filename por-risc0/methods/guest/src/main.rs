// Full proof-of-reserves guest: verify an Ethereum account-state Merkle-Patricia
// proof against a block header, hide balance + address, prove balance >= threshold,
// and (unless debug) prove ownership of the address. Journal commits ONLY
// {block_hash, threshold, chain_id, debug}.
//
// Precompiles: k256 (secp256k1 ecrecover) accelerated via the risc0 fork; keccak
// accelerated via the risc0 tiny-keccak fork (alloy's backend), so the MPT/header
// keccak runs on the coprocessor.
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::Header;
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use risc0_zkvm::guest::env;

// state_root is item index 3 of the block-header RLP list (stable across forks).
fn extract_state_root(header_rlp: &[u8]) -> B256 {
    let mut buf: &[u8] = header_rlp;
    let outer = Header::decode(&mut buf).expect("header rlp");
    assert!(outer.list, "header is not an RLP list");
    for _ in 0..3 {
        let h = Header::decode(&mut buf).expect("skip item");
        buf = &buf[h.payload_length..];
    }
    let h = Header::decode(&mut buf).expect("state_root item");
    assert_eq!(h.payload_length, 32, "state_root not 32 bytes");
    B256::from_slice(&buf[..32])
}

fn main() {
    // ---- PRIVATE inputs ----
    let header_rlp: Vec<u8> = env::read();
    let account_proof: Vec<Vec<u8>> = env::read();
    let address: [u8; 20] = env::read();
    let nonce: u64 = env::read();
    let balance: u128 = env::read();
    let storage_hash: [u8; 32] = env::read();
    let code_hash: [u8; 32] = env::read();
    let sig: Vec<u8> = env::read(); // empty when debug
    // ---- PUBLIC inputs (committed) ----
    let threshold: u128 = env::read();
    let chain_id: u32 = env::read();
    let debug: bool = env::read();

    // Header hash + state_root from the attested RLP.
    let block_hash = keccak256(&header_rlp);
    let state_root = extract_state_root(&header_rlp);

    // (1) Account MPT proof: reconstruct the trie account from the private fields and
    // verify it is the value at keccak(address) under state_root. A wrong balance
    // reconstructs a different account RLP and fails, binding `balance` to chain state.
    let account = TrieAccount {
        nonce,
        balance: U256::from(balance),
        storage_root: B256::from(storage_hash),
        code_hash: B256::from(code_hash),
    };
    let account_rlp = alloy_rlp::encode(&account);
    let key = Nibbles::unpack(keccak256(address));
    let proof: Vec<Bytes> = account_proof.into_iter().map(Bytes::from).collect();
    verify_proof(state_root, key, Some(account_rlp), &proof).expect("account MPT proof invalid");

    // (2) Ownership of the (private) address, unless debug.
    if !debug {
        let mut msg = Vec::with_capacity(60);
        msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        msg.extend_from_slice(block_hash.as_slice());
        let msg_hash = keccak256(&msg);
        let signature = Signature::from_slice(&sig[..64]).expect("bad signature");
        let recid = RecoveryId::from_byte(sig[64]).expect("bad recid");
        let vk = VerifyingKey::recover_from_prehash(msg_hash.as_slice(), &signature, recid)
            .expect("recover failed");
        let enc = vk.to_encoded_point(false);
        let signer = keccak256(&enc.as_bytes()[1..65]);
        assert_eq!(signer[12..32], address, "signer address != proven address");
    }

    // (3) Threshold predicate (balance stays private).
    assert!(balance >= threshold, "balance below threshold");

    // (4) Commit only public values.
    let bh: [u8; 32] = block_hash.into();
    env::commit(&bh);
    env::commit(&threshold);
    env::commit(&chain_id);
    env::commit(&debug);
}
