// TEMPORARY: generate an EIP-191 (personal_sign) ownership test vector for the
// Noir circuit's verify_ownership, using the crate's own k256 + tiny-keccak.
// Prints ready-to-paste Noir globals. Remove after de-risk.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tiny_keccak::{Hasher, Keccak};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

fn noir_arr(name: &str, len: usize, bytes: &[u8]) {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
    println!("    global {name}: [u8; {len}] = [{}];", items.join(", "));
}

fn main() {
    // Deterministic test key (NOT real). sk = [1,2,...,32].
    let mut sk_bytes = [0u8; 32];
    for i in 0..32 {
        sk_bytes[i] = (i as u8) + 1;
    }
    let sk = SigningKey::from_slice(&sk_bytes).unwrap();
    let vk = sk.verifying_key();
    let pt = vk.to_encoded_point(false); // 0x04 || x(32) || y(32)
    let pub_bytes = pt.as_bytes();
    let x = &pub_bytes[1..33];
    let y = &pub_bytes[33..65];

    let mut xy = [0u8; 64];
    xy[..32].copy_from_slice(x);
    xy[32..].copy_from_slice(y);
    let addr = &keccak(&xy)[12..32];

    // crypto_punks block hash = the message the wallet personal_signs.
    let block_hash: [u8; 32] = [
        0xbe, 0x8a, 0xa5, 0x94, 0x5d, 0x33, 0x77, 0xe6, 0x5e, 0xd0, 0x67, 0x57, 0x55, 0x5d, 0x0d,
        0x4b, 0xab, 0xe2, 0x69, 0x09, 0x75, 0x74, 0xc2, 0x10, 0x13, 0x3e, 0x59, 0xcf, 0x6b, 0xc1,
        0x7d, 0x18,
    ];
    let mut msg = Vec::new();
    msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    msg.extend_from_slice(&block_hash);
    let digest = keccak(&msg);

    let sig: Signature = sk.sign_prehash(&digest).unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    let sig_bytes = sig.to_bytes();

    noir_arr("OWNER_BLOCK_HASH", 32, &block_hash);
    noir_arr("OWNER_ADDR", 20, addr);
    noir_arr("OWNER_PKX", 32, x);
    noir_arr("OWNER_PKY", 32, y);
    noir_arr("OWNER_SIG", 64, &sig_bytes);
}
