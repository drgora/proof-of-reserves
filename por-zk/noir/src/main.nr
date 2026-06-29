// Proof of reserves via an Ethereum state proof, bound to a zkTLS-attested block.
//
// Public inputs : threshold (wei), block_hash, chain_id, debug
// Private inputs: address, account, account-trie proof, block header (+RLP),
//                 and the owner's secp256k1 public key + signature.
//
// The circuit proves, in zero knowledge, that:
//   (1) `header_rlp` is a self-consistent Ethereum block header whose keccak hash
//       equals the PUBLIC `block_hash` (which the verifier matches against the
//       TLSNotary-attested RPC header - that is what anchors the head to a named
//       operator);
//   (2) the account-trie Merkle-Patricia proof for `address` verifies against the
//       header's `state_root`, yielding the account's true `balance`;
//   (3) unless `debug` is set, the prover controls `address` - the wallet signed
//       `personal_sign(block_hash)` and that key hashes to `address`;
//   (4) `balance >= threshold`.
//
// Neither `balance` nor `address` is revealed: the public statement is only
// "some wallet I control holds >= threshold at this block on this chain".
//
// `debug` is a PUBLIC bypass of the ownership check (3), for testing the
// state-proof/threshold path without a wallet signature. The production verifier
// MUST reject any proof with debug != 0 (and the release build is compiled from a
// variant with the bypass removed entirely).
//
// The `ethereum` modules below are vendored from noir-lang/eth-proofs (MIT) and
// folded into this bin crate so `main` can reach the (otherwise pub(crate))
// verifiers directly. One soundness fix is applied in verifiers/account.nr - see
// the comment there (balance was constrained only mod 2^128 upstream).

pub mod account;
mod account_int_test;
pub mod header;
mod header_int_test;
pub mod account_with_storage;
mod account_with_storage_int_test;
pub mod account_with_storage_recursive;
mod account_with_storage_recursive_int_test;
pub mod receipt;
mod receipt_int_test;
pub mod log;
mod log_test;
mod log_int_test;
pub mod transaction;
mod transaction_test;
mod transaction_int_test;
pub mod misc;
mod chain;
pub mod serde;
mod serde_test;
pub mod uint256;
mod uint256_test;
mod benchmark;

pub mod fixtures;
pub(crate) mod verifiers;
pub(crate) mod merkle_patricia_proofs;
pub(crate) mod rlp;

pub(crate) global HASH_LEN: u32 = 32;

use crate::account::{
    Account, MAX_ACCOUNT_DEPTH_NO_LEAF_M, MAX_ACCOUNT_LEAF_LEN, MAX_ACCOUNT_STATE_LEN,
    MAX_PREFIXED_KEY_NIBBLE_LEN,
};
use crate::header::{BlockHeaderPartial, BlockHeaderRlp};
use crate::merkle_patricia_proofs::proof::ProofInput;
use crate::misc::types::{Address, Bytes32};
use crate::verifiers::account::verify_account;
use crate::verifiers::header::verify_header;
use keccak256::keccak256;

// Account-trie proof dimensions (native account; no storage slot). Matches the
// `MAX_ACCOUNT_DEPTH_NO_LEAF_M` convention the prover pads proofs to.
pub type AccountStateProof = ProofInput<MAX_PREFIXED_KEY_NIBBLE_LEN, MAX_ACCOUNT_STATE_LEN, MAX_ACCOUNT_DEPTH_NO_LEAF_M, MAX_ACCOUNT_LEAF_LEN>;

fn main(
    threshold: pub u128,
    block_hash: pub Bytes32,
    chain_id: pub u32,
    debug: pub bool,
    address: Address,
    account: Account,
    state_proof: AccountStateProof,
    header: BlockHeaderPartial,
    header_rlp: BlockHeaderRlp,
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature: [u8; 64],
) {
    // (1) Header self-consistency: header_rlp -> number, state_root, and hash.
    verify_header(chain_id, header, header_rlp);

    // (2) Bind the proven header to the PUBLIC block_hash.
    assert(header.hash == block_hash, "header hash != public block_hash");

    // (3) Account MPT proof against the header's state_root. After the soundness
    //     fix in assert_account_equals, account.balance is the exact on-chain value.
    verify_account(address, account, state_proof, header.state_root);

    // (4) Ownership of the (private) address, unless the debug bypass is set.
    if !debug {
        verify_ownership(block_hash, address, pubkey_x, pubkey_y, signature);
    }

    // (5) Threshold predicate; balance stays hidden.
    assert((account.balance as u128) >= threshold, "balance below threshold");
}

// Prove control of `address`: the wallet signed personal_sign(block_hash); verify
// the signature under the supplied public key, then bind that key to `address`.
fn verify_ownership(
    block_hash: Bytes32,
    address: Address,
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature: [u8; 64],
) {
    let msg_hash = eip191_personal_sign_hash(block_hash);
    let valid = std::ecdsa_secp256k1::verify_signature(pubkey_x, pubkey_y, signature, msg_hash);
    assert(valid, "invalid ownership signature");

    // Ethereum address = last 20 bytes of keccak256(pubkey_x ++ pubkey_y).
    let mut pubkey: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey[i] = pubkey_x[i];
        pubkey[32 + i] = pubkey_y[i];
    }
    let derived = keccak256(pubkey, 64);
    for i in 0..20 {
        assert(derived[12 + i] == address[i], "signer address != proven address");
    }
}

// keccak256("\x19Ethereum Signed Message:\n32" ++ block_hash) - the EIP-191
// personal_sign digest for a 32-byte message.
fn eip191_personal_sign_hash(block_hash: Bytes32) -> [u8; 32] {
    // 0x19 ++ "Ethereum Signed Message:\n" ++ "32"  (28 bytes)
    let prefix: [u8; 28] = [
        0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65,
        0x64, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32,
    ];
    let mut msg: [u8; 60] = [0; 60];
    for i in 0..28 {
        msg[i] = prefix[i];
    }
    for i in 0..32 {
        msg[28 + i] = block_hash[i];
    }
    keccak256(msg, 60)
}

// ---------------------------------------------------------------------------
// Tests (no network / no oracle): use the real crypto_punks mainnet fixture.
// ---------------------------------------------------------------------------
mod por_tests {
    use crate::chain::ETHEREUM_MAINNET_ID;
    use crate::fixtures::mainnet::london::crypto_punks::{
        account::{account, address},
        header::{block_header_partial, block_header_rlp},
        state_proof::proof_input,
    };

    // crypto_punks balance = 14_523_859_557_397_289_696_549 wei (~14.5k ETH).
    global BELOW: u128 = 14_000_000_000_000_000_000_000;
    global ABOVE: u128 = 15_000_000_000_000_000_000_000;

    // EIP-191 ownership vector (deterministic test key signing personal_sign of the
    // crypto_punks block hash), generated by the por_sigvec helper.
    global OWNER_BLOCK_HASH: [u8; 32] = [0xbe, 0x8a, 0xa5, 0x94, 0x5d, 0x33, 0x77, 0xe6, 0x5e, 0xd0, 0x67, 0x57, 0x55, 0x5d, 0x0d, 0x4b, 0xab, 0xe2, 0x69, 0x09, 0x75, 0x74, 0xc2, 0x10, 0x13, 0x3e, 0x59, 0xcf, 0x6b, 0xc1, 0x7d, 0x18];
    global OWNER_ADDR: [u8; 20] = [0x63, 0x70, 0xef, 0x2f, 0x4d, 0xb3, 0x61, 0x1d, 0x65, 0x7b, 0x90, 0x66, 0x7d, 0xe3, 0x98, 0xa2, 0xcc, 0x2a, 0x37, 0x0c];
    global OWNER_PKX: [u8; 32] = [0x84, 0xbf, 0x75, 0x62, 0x26, 0x2b, 0xbd, 0x69, 0x40, 0x08, 0x57, 0x48, 0xf3, 0xbe, 0x6a, 0xfa, 0x52, 0xae, 0x31, 0x71, 0x55, 0x18, 0x1e, 0xce, 0x31, 0xb6, 0x63, 0x51, 0xcc, 0xff, 0xa4, 0xb0];
    global OWNER_PKY: [u8; 32] = [0x8c, 0xc4, 0x3d, 0x63, 0xb2, 0x85, 0x9d, 0x46, 0x9f, 0xee, 0x15, 0xf3, 0x1c, 0x9e, 0xdb, 0x53, 0x24, 0x26, 0x6e, 0x6f, 0xd0, 0x40, 0x7e, 0x87, 0x38, 0x2d, 0x60, 0xfc, 0x45, 0x11, 0xac, 0xd8];
    global OWNER_SIG: [u8; 64] = [0xd3, 0x70, 0x2e, 0xad, 0x36, 0x6c, 0xe7, 0xbf, 0x49, 0x0d, 0xbe, 0xa6, 0x61, 0x49, 0x89, 0xa3, 0x9c, 0x46, 0x18, 0x55, 0x23, 0xe9, 0x26, 0x96, 0xcf, 0x63, 0x50, 0x31, 0x9e, 0xd4, 0x21, 0xf6, 0x1f, 0xdf, 0x53, 0x17, 0xe8, 0x75, 0x55, 0xd1, 0x4f, 0x74, 0x45, 0x07, 0xbd, 0xe8, 0xd3, 0x87, 0xac, 0x74, 0x28, 0x7b, 0x27, 0x4e, 0xb5, 0x51, 0x3e, 0xb6, 0x97, 0x2b, 0x26, 0x91, 0xe7, 0xea];

    #[test]
    fn test_verify_ownership_ok() {
        crate::verify_ownership(OWNER_BLOCK_HASH, OWNER_ADDR, OWNER_PKX, OWNER_PKY, OWNER_SIG);
    }

    #[test(should_fail_with = "signer address != proven address")]
    fn test_verify_ownership_wrong_address() {
        let mut wrong = OWNER_ADDR;
        wrong[0] += 1;
        crate::verify_ownership(OWNER_BLOCK_HASH, wrong, OWNER_PKX, OWNER_PKY, OWNER_SIG);
    }

    #[test(should_fail_with = "invalid ownership signature")]
    fn test_verify_ownership_bad_signature() {
        let mut bad = OWNER_SIG;
        bad[0] ^= 0x01;
        crate::verify_ownership(OWNER_BLOCK_HASH, OWNER_ADDR, OWNER_PKX, OWNER_PKY, bad);
    }

    // Closes the audit residual: a manipulated proof.depth (path truncation) must
    // be rejected (the MPT verifier asserts all key nibbles are consumed).
    #[test(should_fail)]
    fn test_proof_depth_truncation_rejected() {
        let mut p = proof_input;
        p.proof.depth -= 1;
        crate::main(
            BELOW,
            block_header_partial.hash,
            ETHEREUM_MAINNET_ID,
            true,
            address,
            account,
            p,
            block_header_partial,
            block_header_rlp,
            [0; 32],
            [0; 32],
            [0; 64],
        );
    }

    #[test]
    fn test_reserves_ok_debug_bypass() {
        crate::main(
            BELOW,
            block_header_partial.hash,
            ETHEREUM_MAINNET_ID,
            true, // debug: skip ownership (no wallet sig needed)
            address,
            account,
            proof_input,
            block_header_partial,
            block_header_rlp,
            [0; 32],
            [0; 32],
            [0; 64],
        );
    }

    #[test(should_fail_with = "balance below threshold")]
    fn test_reserves_below_threshold_fails() {
        crate::main(
            ABOVE,
            block_header_partial.hash,
            ETHEREUM_MAINNET_ID,
            true,
            address,
            account,
            proof_input,
            block_header_partial,
            block_header_rlp,
            [0; 32],
            [0; 32],
            [0; 64],
        );
    }

    // Regression guard for the vendored soundness fix: a balance inflated by 2^128
    // (the upstream forgery) must now be rejected by assert_max_bit_size::<128>.
    #[test(should_fail)]
    fn test_balance_overflow_rejected() {
        let mut forged = account;
        forged.balance = account.balance + 0x0100000000000000000000000000000000;
        crate::main(
            BELOW,
            block_header_partial.hash,
            ETHEREUM_MAINNET_ID,
            true,
            address,
            forged,
            proof_input,
            block_header_partial,
            block_header_rlp,
            [0; 32],
            [0; 32],
            [0; 64],
        );
    }

    // Binding check: a block_hash that doesn't match the header must be rejected.
    #[test(should_fail_with = "header hash != public block_hash")]
    fn test_wrong_block_hash_fails() {
        let mut wrong = block_header_partial.hash;
        wrong[0] += 1;
        crate::main(
            BELOW,
            wrong,
            ETHEREUM_MAINNET_ID,
            true,
            address,
            account,
            proof_input,
            block_header_partial,
            block_header_rlp,
            [0; 32],
            [0; 32],
            [0; 64],
        );
    }
}
