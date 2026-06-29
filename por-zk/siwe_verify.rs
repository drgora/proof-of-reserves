// Minimal SIWE / EIP-191 `personal_sign` signature recovery.
//
// We avoid the heavyweight `siwe`/`alloy` crates (which pull a conflicting k256
// version) and recover the signer directly with the repo's k256 0.13 plus
// tiny-keccak. This recovers the Ethereum address that produced a
// `personal_sign` signature over a SIWE (EIP-4361) message string.

#![allow(dead_code)]

use anyhow::{Result, anyhow};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Recover the 20-byte Ethereum address that signed `message` via EIP-191
/// `personal_sign`. `signature` is the 65-byte r‖s‖v form returned by wallets.
pub fn recover_personal_sign(message: &[u8], signature: &[u8]) -> Result<[u8; 20]> {
    if signature.len() != 65 {
        return Err(anyhow!("signature must be 65 bytes, got {}", signature.len()));
    }

    // EIP-191 prefix: "\x19Ethereum Signed Message:\n" + len(message) + message.
    let mut buf = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    buf.extend_from_slice(message);
    let digest = keccak256(&buf);

    let rec_id = match signature[64] {
        27 | 28 => signature[64] - 27,
        v @ (0 | 1) => v,
        other => return Err(anyhow!("invalid recovery byte v={other}")),
    };
    let sig = Signature::from_slice(&signature[..64]).map_err(|e| anyhow!("bad signature: {e}"))?;
    let recid = RecoveryId::from_byte(rec_id).ok_or_else(|| anyhow!("bad recovery id"))?;

    let vk = VerifyingKey::recover_from_prehash(&digest, &sig, recid)
        .map_err(|e| anyhow!("recovery failed: {e}"))?;

    // address = last 20 bytes of keccak256(uncompressed pubkey without 0x04 tag)
    let point = vk.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

/// Lowercase 0x-prefixed hex of an address.
pub fn addr_hex(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

/// Case-insensitive address equality (callers may hold mixed-case hex).
pub fn addr_eq(a: &[u8; 20], b: &[u8; 20]) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn round_trip_recovery() {
        // Deterministic key.
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let expected = {
            let h = keccak256(&point.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&h[12..]);
            a
        };

        let message = b"example.com wants you to sign in...\nNonce: abc123";
        let mut buf = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
        buf.extend_from_slice(message);
        let digest = keccak256(&buf);

        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut sig65 = sig.to_bytes().to_vec();
        sig65.push(27 + recid.to_byte());

        let recovered = recover_personal_sign(message, &sig65).unwrap();
        assert_eq!(recovered, expected);

        // A different message must not recover the same address.
        let other = recover_personal_sign(b"different", &sig65).unwrap();
        assert_ne!(other, expected);
    }
}
