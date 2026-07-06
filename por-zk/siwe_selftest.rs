// Validates SIWE/EIP-191 recovery without a wallet: sign a message with a known
// k256 key, recover the address, and confirm it matches.
//   cargo run --release --bin siwe_selftest

mod siwe_verify;

use k256::ecdsa::SigningKey;
use siwe_verify::{addr_hex, keccak256, recover_personal_sign};

fn main() -> anyhow::Result<()> {
    let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let expected = {
        let h = keccak256(&point.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        a
    };

    let message = b"app.example wants you to sign in with your Ethereum account:\n0x...\n\nNonce: abc123";
    let mut buf = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    buf.extend_from_slice(message);
    let digest = keccak256(&buf);

    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut sig65 = sig.to_bytes().to_vec();
    sig65.push(27 + recid.to_byte());

    let recovered = recover_personal_sign(message, &sig65)?;
    assert_eq!(recovered, expected, "recovered address mismatch");
    println!("✅ recovered {} == expected {}", addr_hex(&recovered), addr_hex(&expected));

    assert!(recover_personal_sign(b"tampered", &sig65)? != expected);
    println!("✅ tampered message recovers a different address");
    Ok(())
}
