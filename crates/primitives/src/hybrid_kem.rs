use hkdf::Hkdf;
use sha2::Sha256;
use ml_kem::ml_kem_768::{self, MlKem768};
use ml_kem::{B32, Seed, DecapsulationKey, EncapsulationKey, Decapsulate, KeyExport};
use rand::RngCore;

pub const DOMAIN: &[u8] = b"pq-sa-v1";
pub const PAIRWISE_KEY_LEN: usize = 32;
pub const EPK_SIZE: usize = 33;

/// Recipient key bundle: spending keypair (for stealth derivation) +
/// viewing keypair (EC + ML-KEM, for hybrid KEM — safe to delegate).
///
/// A scanning server needs (viewing_sk_ec, dk_kem) to recover k_pairwise.
/// It does NOT need spending_sk, so it cannot spend.
pub struct RecipientKeyPair {
    // Spending key — for stealth_sk = spending_sk + scalar. NEVER shared.
    pub spending_sk: secp256k1::SecretKey,
    pub spending_pk: secp256k1::PublicKey,
    // EC viewing key — for ECDH in hybrid KEM. Safe to delegate.
    pub viewing_sk_ec: secp256k1::SecretKey,
    pub viewing_pk_ec: secp256k1::PublicKey,
    // ML-KEM viewing key — for PQ KEM. Safe to delegate.
    pub dk_kem: DecapsulationKey<MlKem768>,
    pub ek_kem: EncapsulationKey<MlKem768>,
}

/// Derive a 32-byte key from seed using labeled HKDF-SHA256.
fn derive_32(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out).expect("HKDF expand 32");
    out
}

/// Derive a valid secp256k1 secret key from seed using labeled HKDF with counter-based rejection.
/// Probability of needing retry is ~1/2^128 per attempt — practically zero.
fn derive_ec_key(seed: &[u8; 32], label: &[u8]) -> secp256k1::SecretKey {
    for counter in 0u8..=255 {
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut info = label.to_vec();
        info.push(counter);
        let mut out = [0u8; 32];
        hk.expand(&info, &mut out).expect("HKDF expand 32");
        if let Ok(sk) = secp256k1::SecretKey::from_slice(&out) {
            return sk;
        }
    }
    unreachable!("256 HKDF attempts all produced invalid scalars — astronomically unlikely");
}

/// Derive a 64-byte key from seed using labeled HKDF-SHA256.
fn derive_64(seed: &[u8; 32], label: &[u8]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut out = [0u8; 64];
    hk.expand(label, &mut out).expect("HKDF expand 64");
    out
}

impl RecipientKeyPair {
    /// Generate from entropy. Internally generates a random seed and calls from_seed().
    pub fn generate(rng: &mut rand_chacha::ChaChaRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Deterministic key derivation from a 32-byte seed using labeled HKDF.
    /// Each key material is derived with a distinct label — stable across library versions.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secp = secp256k1::Secp256k1::new();

        // Spending key (secp256k1) — counter-based rejection sampling
        let spending_sk = derive_ec_key(seed, b"pq-sa-spending-v1");
        let spending_pk = secp256k1::PublicKey::from_secret_key(&secp, &spending_sk);

        // EC viewing key (secp256k1) — separate from spending key
        let viewing_sk_ec = derive_ec_key(seed, b"pq-sa-viewing-ec-v1");
        let viewing_pk_ec = secp256k1::PublicKey::from_secret_key(&secp, &viewing_sk_ec);

        // ML-KEM-768 viewing key
        let kem_seed_bytes = derive_64(seed, b"pq-sa-viewing-kem-v1");
        let dk_kem = DecapsulationKey::<MlKem768>::from_seed(
            Seed::try_from(kem_seed_bytes.as_slice()).expect("64-byte seed"),
        );
        let ek_kem = dk_kem.encapsulation_key().clone();

        Self { spending_sk, spending_pk, viewing_sk_ec, viewing_pk_ec, dk_kem, ek_kem }
    }

    pub fn spending_pk_bytes(&self) -> [u8; EPK_SIZE] {
        self.spending_pk.serialize()
    }

    pub fn viewing_pk_ec_bytes(&self) -> [u8; EPK_SIZE] {
        self.viewing_pk_ec.serialize()
    }

    pub fn ek_kem_bytes(&self) -> Vec<u8> {
        let key_arr = self.ek_kem.to_bytes();
        let slice: &[u8] = key_arr.as_ref();
        slice.to_vec()
    }
}

pub fn ek_kem_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>, &'static str> {
    let key_arr = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(bytes)
        .map_err(|_| "invalid ek_kem length")?;
    EncapsulationKey::<MlKem768>::new(&key_arr).map_err(|_| "invalid ek_kem")
}

pub fn pk_ec_from_bytes(bytes: &[u8]) -> Result<secp256k1::PublicKey, &'static str> {
    secp256k1::PublicKey::from_slice(bytes).map_err(|_| "invalid pk_ec")
}

pub struct FirstContactCiphertext {
    pub epk: [u8; EPK_SIZE],
    pub ct_pq: Vec<u8>,
}

fn hybrid_kdf(ss_ec: &[u8], ss_pq: &[u8]) -> [u8; PAIRWISE_KEY_LEN] {
    let mut ikm = Vec::with_capacity(ss_ec.len() + ss_pq.len());
    ikm.extend_from_slice(ss_ec);
    ikm.extend_from_slice(ss_pq);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut k = [0u8; PAIRWISE_KEY_LEN];
    hk.expand(DOMAIN, &mut k).expect("HKDF expand failed");
    k
}

/// Sender encapsulates to recipient's VIEWING keys (not spending key).
/// The ECDH is with viewing_pk_ec — safe to delegate.
pub fn encapsulate(
    viewing_pk_ec: &secp256k1::PublicKey,
    recipient_ek_kem: &EncapsulationKey<MlKem768>,
    rng: &mut rand_chacha::ChaChaRng,
) -> (FirstContactCiphertext, [u8; PAIRWISE_KEY_LEN]) {
    let secp = secp256k1::Secp256k1::new();

    // ECDH with viewing key (not spending key)
    let (esk, epk) = secp.generate_keypair(rng);
    let ecdh_point = secp256k1::ecdh::shared_secret_point(viewing_pk_ec, &esk);
    let ss_ec = &ecdh_point[..32];

    // ML-KEM-768
    let mut m_bytes = [0u8; 32];
    rng.fill_bytes(&mut m_bytes);
    let (ct_pq, ss_pq) = recipient_ek_kem.encapsulate_deterministic(
        &B32::try_from(m_bytes.as_slice()).expect("32-byte m"),
    );

    let ss_pq_ref: &[u8] = ss_pq.as_ref();
    let k_pairwise = hybrid_kdf(ss_ec, ss_pq_ref);

    let ct_pq_ref: &[u8] = ct_pq.as_ref();
    let ct = FirstContactCiphertext {
        epk: epk.serialize(),
        ct_pq: ct_pq_ref.to_vec(),
    };
    (ct, k_pairwise)
}

/// Recipient decapsulates using VIEWING keys only.
/// Does NOT require spending_sk — safe for delegated scanning.
pub fn decapsulate(
    recipient: &RecipientKeyPair,
    ct: &FirstContactCiphertext,
) -> Result<[u8; PAIRWISE_KEY_LEN], &'static str> {
    // ECDH with viewing EC key (NOT spending key)
    let epk = secp256k1::PublicKey::from_slice(&ct.epk)
        .map_err(|_| "invalid ephemeral public key")?;
    let ecdh_point = secp256k1::ecdh::shared_secret_point(&epk, &recipient.viewing_sk_ec);
    let ss_ec = &ecdh_point[..32];

    // ML-KEM decapsulation
    let ct_pq = ml_kem_768::Ciphertext::try_from(ct.ct_pq.as_slice())
        .map_err(|_| "invalid ML-KEM ciphertext")?;
    let ss_pq = recipient.dk_kem.decapsulate(&ct_pq);

    let ss_pq_ref: &[u8] = ss_pq.as_ref();
    Ok(hybrid_kdf(ss_ec, ss_pq_ref))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;

    #[test]
    fn test_roundtrip() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let recipient = RecipientKeyPair::generate(&mut rng);
        // Sender encapsulates to VIEWING key
        let (ct, k_sender) = encapsulate(&recipient.viewing_pk_ec, &recipient.ek_kem, &mut rng);
        let k_recipient = decapsulate(&recipient, &ct).unwrap();
        assert_eq!(k_sender, k_recipient);
    }

    #[test]
    fn test_wrong_recipient() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let r1 = RecipientKeyPair::generate(&mut rng);
        let r2 = RecipientKeyPair::generate(&mut rng);
        let (ct, k_sender) = encapsulate(&r1.viewing_pk_ec, &r1.ek_kem, &mut rng);
        let k_wrong = decapsulate(&r2, &ct).unwrap();
        assert_ne!(k_sender, k_wrong);
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [99u8; 32];
        let r1 = RecipientKeyPair::from_seed(&seed);
        let r2 = RecipientKeyPair::from_seed(&seed);
        assert_eq!(r1.spending_pk_bytes(), r2.spending_pk_bytes());
        assert_eq!(r1.viewing_pk_ec_bytes(), r2.viewing_pk_ec_bytes());
        assert_eq!(r1.ek_kem_bytes(), r2.ek_kem_bytes());
    }

    #[test]
    fn test_spending_and_viewing_keys_differ() {
        let seed = [42u8; 32];
        let r = RecipientKeyPair::from_seed(&seed);
        assert_ne!(r.spending_pk_bytes(), r.viewing_pk_ec_bytes());
    }

    #[test]
    fn test_ciphertext_sizes() {
        let mut rng = ChaChaRng::seed_from_u64(0);
        let recipient = RecipientKeyPair::generate(&mut rng);
        let (ct, _) = encapsulate(&recipient.viewing_pk_ec, &recipient.ek_kem, &mut rng);
        assert_eq!(ct.epk.len(), 33);
        assert_eq!(ct.ct_pq.len(), 1088);
    }
}
