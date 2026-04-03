//! Stealth address derivation from pairwise channel key.
//!
//! Given k_pairwise (established via hybrid KEM in first contact) and a nonce,
//! derives a one-time stealth Ethereum address. Both sender and recipient can
//! compute the address; only the recipient can derive the private key.
//!
//! Spending is Ethereum-native (secp256k1 signature from the stealth address).
//! No nullifiers, no ZK proofs needed.
//!
//! NOTE: The stealth address uses classical secp256k1. For full PQ spending,
//! Ethereum needs PQ signatures (EIP-7932). Our scope is PQ KEM optimization.

use sha2::{Sha256, Digest};

/// Derive a stealth secp256k1 private key from k_pairwise + nonce.
///
/// Both sender and recipient can compute this. Only the recipient
/// (who holds k_pairwise) can derive it in practice.
pub fn derive_stealth_secret_key(
    k_pairwise: &[u8; 32],
    nonce: &[u8; 16],
) -> secp256k1::SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(b"pq-sa-stealth-v1");
    hasher.update(k_pairwise);
    hasher.update(nonce);
    let seed: [u8; 32] = hasher.finalize().into();

    // secp256k1 secret key from 32-byte seed
    // SHA-256 output is uniformly distributed, overwhelmingly likely to be a valid key
    secp256k1::SecretKey::from_slice(&seed)
        .expect("SHA-256 output is a valid secp256k1 secret key with overwhelming probability")
}

/// Derive the stealth Ethereum address from k_pairwise + nonce.
///
/// This is the address where the sender sends funds.
/// Returns (secret_key, public_key, ethereum_address).
pub fn derive_stealth_address(
    k_pairwise: &[u8; 32],
    nonce: &[u8; 16],
) -> (secp256k1::SecretKey, secp256k1::PublicKey, [u8; 20]) {
    let sk = derive_stealth_secret_key(k_pairwise, nonce);
    let secp = secp256k1::Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

    // Ethereum address = keccak256(uncompressed_pubkey[1..])[12..32]
    // We use SHA-256 here since we don't have keccak in this crate.
    // For production, use actual keccak256.
    let pk_bytes = pk.serialize_uncompressed();
    let mut hasher = Sha256::new();
    hasher.update(&pk_bytes[1..]); // skip the 0x04 prefix
    let hash: [u8; 32] = hasher.finalize().into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);

    (sk, pk, addr)
}

/// Compute only the stealth Ethereum address (for the sender, who doesn't need the sk).
pub fn compute_stealth_address(
    k_pairwise: &[u8; 32],
    nonce: &[u8; 16],
) -> [u8; 20] {
    let (_, _, addr) = derive_stealth_address(k_pairwise, nonce);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_deterministic() {
        let k = [42u8; 32];
        let n = [1u8; 16];
        let (sk1, _, addr1) = derive_stealth_address(&k, &n);
        let (sk2, _, addr2) = derive_stealth_address(&k, &n);
        assert_eq!(sk1, sk2);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_different_nonces_different_addresses() {
        let k = [42u8; 32];
        let (_, _, addr1) = derive_stealth_address(&k, &[1u8; 16]);
        let (_, _, addr2) = derive_stealth_address(&k, &[2u8; 16]);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let n = [1u8; 16];
        let (_, _, addr1) = derive_stealth_address(&[1u8; 32], &n);
        let (_, _, addr2) = derive_stealth_address(&[2u8; 32], &n);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_sender_and_recipient_derive_same_address() {
        // Both parties have k_pairwise (from hybrid KEM first contact)
        let k_pairwise = [77u8; 32];
        let nonce = [99u8; 16];

        // Sender computes address to send funds to
        let sender_addr = compute_stealth_address(&k_pairwise, &nonce);

        // Recipient derives full keypair to spend from that address
        let (_, _, recipient_addr) = derive_stealth_address(&k_pairwise, &nonce);

        assert_eq!(sender_addr, recipient_addr);
    }

    #[test]
    fn test_recipient_can_sign() {
        let k = [42u8; 32];
        let n = [1u8; 16];
        let (sk, pk, _) = derive_stealth_address(&k, &n);

        // Recipient can sign a message with the stealth key
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest([0xAB; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        // Signature verifies against the stealth public key
        assert!(secp.verify_ecdsa(&msg, &sig, &pk).is_ok());
    }

    #[test]
    fn test_many_stealth_addresses_from_one_channel() {
        let k_pairwise = [42u8; 32];
        let mut rng = ChaChaRng::seed_from_u64(42);
        let mut addresses = std::collections::HashSet::new();

        // Generate 100 stealth addresses from the same channel
        for _ in 0..100 {
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);
            let addr = compute_stealth_address(&k_pairwise, &nonce);
            addresses.insert(addr);
        }

        // All unique
        assert_eq!(addresses.len(), 100);
    }
}
