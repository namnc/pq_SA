//! Stealth address derivation — two models:
//!
//! 1. **Direct ML-KEM stealth** (ERC-5564 replacement):
//!    Fresh ML-KEM encapsulation per note. 1,088 B ciphertext per note.
//!    Viewing/spending separation via EC scalar addition.
//!    Safe delegation: server with viewing_dk can detect but not spend.
//!
//! 2. **Pairwise channel stealth** (our optimization):
//!    One-time ML-KEM first contact → k_pairwise. Then derive stealth
//!    addresses from k_pairwise + nonce. 0 B KEM overhead after first contact.
//!
//! Both models use secp256k1 for stealth address derivation and spending.
//! For full PQ spending, Ethereum needs PQ signatures (EIP-7932).
//! Our scope is PQ KEM optimization.

use sha2::{Sha256, Digest};

// =========================================================================
//  Model 1: Direct ML-KEM stealth (ERC-5564 with ML-KEM)
// =========================================================================

/// Derive stealth public key using EC algebra (viewing/spending separation).
///
/// stealth_pk = spending_pk + hash(shared_secret) * G
///
/// The viewing key holder knows hash(shared_secret) and spending_pk (public),
/// so they can compute stealth_pk (for detection). But they CANNOT compute
/// stealth_sk = spending_sk + hash(shared_secret) because spending_sk is private.
pub fn derive_stealth_pubkey(
    spending_pk: &secp256k1::PublicKey,
    shared_secret: &[u8; 32],
) -> (secp256k1::PublicKey, [u8; 20]) {
    let secp = secp256k1::Secp256k1::new();
    let offset_sk = stealth_offset(shared_secret);
    let offset_pk = secp256k1::PublicKey::from_secret_key(&secp, &offset_sk);

    let stealth_pk = spending_pk.combine(&offset_pk)
        .expect("point addition should not produce point at infinity");

    let addr = pubkey_to_eth_address(&stealth_pk);
    (stealth_pk, addr)
}

/// Derive stealth private key (recipient only — requires spending_sk).
///
/// stealth_sk = spending_sk + hash(shared_secret)
///
/// Uses the same offset as derive_stealth_pubkey — both paths go through
/// stealth_offset() to guarantee consistency.
pub fn derive_stealth_privkey(
    spending_sk: &secp256k1::SecretKey,
    shared_secret: &[u8; 32],
) -> secp256k1::SecretKey {
    let offset_sk = stealth_offset(shared_secret);
    let scalar = secp256k1::scalar::Scalar::from_be_bytes(offset_sk.secret_bytes())
        .expect("valid SecretKey is always a valid Scalar");
    spending_sk.add_tweak(&scalar)
        .expect("scalar addition should not overflow")
}

/// Derive the stealth offset key from a shared secret.
/// Both derive_stealth_pubkey and derive_stealth_privkey use this — guaranteeing
/// they always produce the same offset, even on the rare rejection-sampling path.
fn stealth_offset(shared_secret: &[u8; 32]) -> secp256k1::SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(b"pq-sa-stealth-derive-v1");
    hasher.update(shared_secret);
    let base: [u8; 32] = hasher.finalize().into();
    derive_valid_scalar(&base)
}

/// Derive a valid secp256k1 secret key from hash output with counter-based rejection.
fn derive_valid_scalar(base: &[u8; 32]) -> secp256k1::SecretKey {
    // First try the base bytes directly (succeeds with ~1 - 2^-128 probability)
    if let Ok(sk) = secp256k1::SecretKey::from_slice(base) {
        return sk;
    }
    // Counter-based rejection (astronomically unlikely to reach here)
    for counter in 1u8..=255 {
        let mut hasher = Sha256::new();
        hasher.update(base);
        hasher.update(&[counter]);
        let retry: [u8; 32] = hasher.finalize().into();
        if let Ok(sk) = secp256k1::SecretKey::from_slice(&retry) {
            return sk;
        }
    }
    unreachable!("256 attempts all produced invalid scalars")
}

/// Compute 1-byte view tag from shared secret (filters 99.6% of non-matching notes).
pub fn compute_view_tag(shared_secret: &[u8; 32]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(b"pq-sa-view-tag-v1");
    hasher.update(shared_secret);
    hasher.finalize()[0]
}

// =========================================================================
//  Model 2: Pairwise channel stealth (our optimization)
// =========================================================================

/// Derive stealth address from pairwise key + nonce (no per-note KEM).
///
/// Uses the same EC algebra as Model 1, but the shared_secret comes from
/// HKDF(k_pairwise, nonce) instead of ML-KEM encapsulation.
pub fn derive_pairwise_stealth(
    spending_pk: &secp256k1::PublicKey,
    spending_sk: Option<&secp256k1::SecretKey>,
    k_pairwise: &[u8; 32],
    nonce: &[u8; 16],
) -> StealthResult {
    // Derive shared secret from pairwise key + nonce
    let mut hasher = Sha256::new();
    hasher.update(b"pq-sa-pairwise-stealth-v1");
    hasher.update(k_pairwise);
    hasher.update(nonce);
    let ss: [u8; 32] = hasher.finalize().into();

    let (stealth_pk, addr) = derive_stealth_pubkey(spending_pk, &ss);

    let stealth_sk = spending_sk.map(|sk| derive_stealth_privkey(sk, &ss));

    StealthResult {
        stealth_pk,
        stealth_sk,
        address: addr,
        view_tag: compute_view_tag(&ss),
    }
}

pub struct StealthResult {
    pub stealth_pk: secp256k1::PublicKey,
    pub stealth_sk: Option<secp256k1::SecretKey>,
    pub address: [u8; 20],
    pub view_tag: u8,
}

// =========================================================================
//  Helpers
// =========================================================================

/// Convert secp256k1 public key to Ethereum address: keccak256(pubkey)[12..32].
fn pubkey_to_eth_address(pk: &secp256k1::PublicKey) -> [u8; 20] {
    use sha3::{Keccak256, Digest as _};
    let pk_bytes = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&pk_bytes[1..]); // skip 0x04 prefix
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    fn generate_keypair(rng: &mut ChaChaRng) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        let secp = secp256k1::Secp256k1::new();
        secp.generate_keypair(rng)
    }

    // --- Model 1: Direct ML-KEM stealth ---

    #[test]
    fn test_viewing_spending_separation() {
        // The core security property: viewing key holder CANNOT derive spending key
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (spending_sk, spending_pk) = generate_keypair(&mut rng);
        let shared_secret = [99u8; 32];

        // Sender/server computes stealth pubkey (from public info + shared_secret)
        let (stealth_pk, addr) = derive_stealth_pubkey(&spending_pk, &shared_secret);

        // Recipient computes stealth privkey (requires spending_sk)
        let stealth_sk = derive_stealth_privkey(&spending_sk, &shared_secret);

        // Verify: stealth_sk corresponds to stealth_pk
        let secp = secp256k1::Secp256k1::new();
        let derived_pk = secp256k1::PublicKey::from_secret_key(&secp, &stealth_sk);
        assert_eq!(derived_pk, stealth_pk);

        // Verify: address matches
        let derived_addr = pubkey_to_eth_address(&derived_pk);
        assert_eq!(derived_addr, addr);
    }

    #[test]
    fn test_viewing_holder_cannot_spend() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (spending_sk, spending_pk) = generate_keypair(&mut rng);
        let shared_secret = [99u8; 32];

        // Server (with viewing_dk) knows shared_secret and spending_pk
        // Server can compute stealth_pk for detection
        let (stealth_pk, _) = derive_stealth_pubkey(&spending_pk, &shared_secret);

        // But server CANNOT compute stealth_sk without spending_sk
        // The only way is: stealth_sk = spending_sk + hash(ss)
        // Server has hash(ss) but NOT spending_sk

        // Verify: a WRONG spending key produces a different stealth key
        let (wrong_sk, _) = generate_keypair(&mut rng);
        let wrong_stealth_sk = derive_stealth_privkey(&wrong_sk, &shared_secret);
        let secp = secp256k1::Secp256k1::new();
        let wrong_pk = secp256k1::PublicKey::from_secret_key(&secp, &wrong_stealth_sk);
        assert_ne!(wrong_pk, stealth_pk, "wrong spending key must produce different stealth key");
    }

    #[test]
    fn test_view_tag_filters() {
        let ss1 = [1u8; 32];
        let ss2 = [2u8; 32];
        let tag1 = compute_view_tag(&ss1);
        let tag2 = compute_view_tag(&ss2);
        // Different shared secrets should (usually) produce different tags
        // Not guaranteed for any single pair, but deterministic
        assert_eq!(compute_view_tag(&ss1), tag1); // deterministic
        // Statistical: over 256 random ss, we'd expect ~1 collision with any fixed tag
    }

    #[test]
    fn test_recipient_can_sign_from_stealth() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (spending_sk, spending_pk) = generate_keypair(&mut rng);
        let shared_secret = [99u8; 32];

        let (stealth_pk, _) = derive_stealth_pubkey(&spending_pk, &shared_secret);
        let stealth_sk = derive_stealth_privkey(&spending_sk, &shared_secret);

        // Recipient signs from stealth address
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest([0xAB; 32]);
        let sig = secp.sign_ecdsa(&msg, &stealth_sk);
        assert!(secp.verify_ecdsa(&msg, &sig, &stealth_pk).is_ok());
    }

    // --- Model 2: Pairwise channel stealth ---

    #[test]
    fn test_pairwise_stealth_deterministic() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (spending_sk, spending_pk) = generate_keypair(&mut rng);
        let k = [42u8; 32];
        let n = [1u8; 16];

        let r1 = derive_pairwise_stealth(&spending_pk, Some(&spending_sk), &k, &n);
        let r2 = derive_pairwise_stealth(&spending_pk, Some(&spending_sk), &k, &n);
        assert_eq!(r1.address, r2.address);
        assert_eq!(r1.view_tag, r2.view_tag);
    }

    #[test]
    fn test_pairwise_stealth_sender_and_recipient_agree() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (spending_sk, spending_pk) = generate_keypair(&mut rng);
        let k = [77u8; 32];
        let n = [99u8; 16];

        // Sender computes address (no spending_sk)
        let sender_result = derive_pairwise_stealth(&spending_pk, None, &k, &n);

        // Recipient computes address + spending key
        let recipient_result = derive_pairwise_stealth(&spending_pk, Some(&spending_sk), &k, &n);

        // Same address
        assert_eq!(sender_result.address, recipient_result.address);

        // Recipient can sign
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest([0xCD; 32]);
        let stealth_sk = recipient_result.stealth_sk.unwrap();
        let sig = secp.sign_ecdsa(&msg, &stealth_sk);
        assert!(secp.verify_ecdsa(&msg, &sig, &recipient_result.stealth_pk).is_ok());
    }

    #[test]
    fn test_different_nonces_different_addresses() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (_, spending_pk) = generate_keypair(&mut rng);
        let k = [42u8; 32];

        let r1 = derive_pairwise_stealth(&spending_pk, None, &k, &[1u8; 16]);
        let r2 = derive_pairwise_stealth(&spending_pk, None, &k, &[2u8; 16]);
        assert_ne!(r1.address, r2.address);
    }

    #[test]
    fn test_many_unique_stealth_addresses() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (_, spending_pk) = generate_keypair(&mut rng);
        let k = [42u8; 32];
        let mut addrs = std::collections::HashSet::new();

        for i in 0..100u64 {
            let mut n = [0u8; 16];
            n[..8].copy_from_slice(&i.to_le_bytes());
            let r = derive_pairwise_stealth(&spending_pk, None, &k, &n);
            addrs.insert(r.address);
        }
        assert_eq!(addrs.len(), 100);
    }
}
