use hkdf::Hkdf;
use sha2::Sha256;
use ml_kem::ml_kem_768::{self, MlKem768};
use ml_kem::{B32, Seed, DecapsulationKey, EncapsulationKey, Decapsulate, KeyExport};
use rand::RngCore;

pub const DOMAIN: &[u8] = b"pq-sa-v1";
pub const PAIRWISE_KEY_LEN: usize = 32;
pub const EPK_SIZE: usize = 33;

// =========================================================================
//  Type-safe key separation: ViewingKeys vs SpendingKey
// =========================================================================

/// Viewing keys — safe to delegate to a scanning server.
/// Contains EC viewing key (for ECDH) and ML-KEM decapsulation key.
/// CANNOT derive stealth spending keys.
pub struct ViewingKeys {
    viewing_sk_ec: secp256k1::SecretKey,
    pub viewing_pk_ec: secp256k1::PublicKey,
    dk_kem: DecapsulationKey<MlKem768>,
    pub ek_kem: EncapsulationKey<MlKem768>,
}

/// Spending key — NEVER shared. Used only for stealth_sk derivation.
pub struct SpendingKey {
    spending_sk: secp256k1::SecretKey,
    pub spending_pk: secp256k1::PublicKey,
}

/// Full recipient key bundle. Only the recipient holds this.
/// For delegation, extract viewing_keys() and share only that.
pub struct RecipientKeyPair {
    pub viewing: ViewingKeys,
    pub spending: SpendingKey,
}

/// Derive a valid secp256k1 secret key from seed using labeled HKDF with counter-based rejection.
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
    unreachable!("256 HKDF attempts all produced invalid scalars");
}

fn derive_64(seed: &[u8; 32], label: &[u8]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut out = [0u8; 64];
    hk.expand(label, &mut out).expect("HKDF expand 64");
    out
}

impl SpendingKey {
    pub fn spending_sk(&self) -> &secp256k1::SecretKey {
        &self.spending_sk
    }

    pub fn spending_pk_bytes(&self) -> [u8; EPK_SIZE] {
        self.spending_pk.serialize()
    }
}

impl ViewingKeys {
    pub fn viewing_pk_ec_bytes(&self) -> [u8; EPK_SIZE] {
        self.viewing_pk_ec.serialize()
    }

    pub fn ek_kem_bytes(&self) -> Vec<u8> {
        let key_arr = self.ek_kem.to_bytes();
        let slice: &[u8] = key_arr.as_ref();
        slice.to_vec()
    }
}

impl RecipientKeyPair {
    /// Generate from entropy.
    pub fn generate(rng: &mut rand_chacha::ChaChaRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Deterministic key derivation from a 32-byte seed using labeled HKDF.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secp = secp256k1::Secp256k1::new();

        let spending_sk = derive_ec_key(seed, b"pq-sa-spending-v1");
        let spending_pk = secp256k1::PublicKey::from_secret_key(&secp, &spending_sk);

        let viewing_sk_ec = derive_ec_key(seed, b"pq-sa-viewing-ec-v1");
        let viewing_pk_ec = secp256k1::PublicKey::from_secret_key(&secp, &viewing_sk_ec);

        let kem_seed_bytes = derive_64(seed, b"pq-sa-viewing-kem-v1");
        let dk_kem = DecapsulationKey::<MlKem768>::from_seed(
            Seed::try_from(kem_seed_bytes.as_slice()).expect("64-byte seed"),
        );
        let ek_kem = dk_kem.encapsulation_key().clone();

        Self {
            spending: SpendingKey { spending_sk, spending_pk },
            viewing: ViewingKeys { viewing_sk_ec, viewing_pk_ec, dk_kem, ek_kem },
        }
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
pub fn encapsulate(
    viewing_pk_ec: &secp256k1::PublicKey,
    recipient_ek_kem: &EncapsulationKey<MlKem768>,
    rng: &mut rand_chacha::ChaChaRng,
) -> (FirstContactCiphertext, [u8; PAIRWISE_KEY_LEN]) {
    let secp = secp256k1::Secp256k1::new();

    let (esk, epk) = secp.generate_keypair(rng);
    // shared_secret_point returns the full uncompressed point (x || y).
    // We take the x-coordinate (first 32 bytes) as the ECDH shared secret.
    // This is safe here because it's immediately fed into HKDF alongside
    // the ML-KEM secret — the KDF absorbs any bias in the x-coordinate.
    let ecdh_point = secp256k1::ecdh::shared_secret_point(viewing_pk_ec, &esk);
    let ss_ec = &ecdh_point[..32];

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

/// Decapsulate using VIEWING keys only. Does NOT require spending key.
/// This is the function a scanning server calls — it accepts ViewingKeys,
/// not RecipientKeyPair, enforcing the trust boundary at the type level.
pub fn decapsulate(
    viewing: &ViewingKeys,
    ct: &FirstContactCiphertext,
) -> Result<[u8; PAIRWISE_KEY_LEN], &'static str> {
    let epk = secp256k1::PublicKey::from_slice(&ct.epk)
        .map_err(|_| "invalid ephemeral public key")?;
    // x-coordinate of ECDH point — fed into HKDF with ML-KEM secret (see encapsulate comment)
    let ecdh_point = secp256k1::ecdh::shared_secret_point(&epk, &viewing.viewing_sk_ec);
    let ss_ec = &ecdh_point[..32];

    let ct_pq = ml_kem_768::Ciphertext::try_from(ct.ct_pq.as_slice())
        .map_err(|_| "invalid ML-KEM ciphertext")?;
    let ss_pq = viewing.dk_kem.decapsulate(&ct_pq);

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
        let (ct, k_sender) = encapsulate(&recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, &mut rng);
        let k_recipient = decapsulate(&recipient.viewing, &ct).unwrap();
        assert_eq!(k_sender, k_recipient);
    }

    #[test]
    fn test_wrong_recipient() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let r1 = RecipientKeyPair::generate(&mut rng);
        let r2 = RecipientKeyPair::generate(&mut rng);
        let (ct, k_sender) = encapsulate(&r1.viewing.viewing_pk_ec, &r1.viewing.ek_kem, &mut rng);
        let k_wrong = decapsulate(&r2.viewing, &ct).unwrap();
        assert_ne!(k_sender, k_wrong);
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [99u8; 32];
        let r1 = RecipientKeyPair::from_seed(&seed);
        let r2 = RecipientKeyPair::from_seed(&seed);
        assert_eq!(r1.spending.spending_pk_bytes(), r2.spending.spending_pk_bytes());
        assert_eq!(r1.viewing.viewing_pk_ec_bytes(), r2.viewing.viewing_pk_ec_bytes());
        assert_eq!(r1.viewing.ek_kem_bytes(), r2.viewing.ek_kem_bytes());
    }

    #[test]
    fn test_spending_and_viewing_keys_differ() {
        let seed = [42u8; 32];
        let r = RecipientKeyPair::from_seed(&seed);
        assert_ne!(r.spending.spending_pk_bytes(), r.viewing.viewing_pk_ec_bytes());
    }

    #[test]
    fn test_ciphertext_sizes() {
        let mut rng = ChaChaRng::seed_from_u64(0);
        let recipient = RecipientKeyPair::generate(&mut rng);
        let (ct, _) = encapsulate(&recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, &mut rng);
        assert_eq!(ct.epk.len(), 33);
        assert_eq!(ct.ct_pq.len(), 1088);
    }

    #[test]
    fn test_decapsulate_takes_viewing_only() {
        // This test verifies the type-level separation:
        // decapsulate() accepts &ViewingKeys, NOT &RecipientKeyPair.
        // A scanning server with only ViewingKeys can decapsulate but cannot access spending_sk.
        let mut rng = ChaChaRng::seed_from_u64(42);
        let recipient = RecipientKeyPair::generate(&mut rng);

        // Extract viewing keys (what a scanning server would receive)
        let viewing = &recipient.viewing;

        let (ct, k_sender) = encapsulate(&viewing.viewing_pk_ec, &viewing.ek_kem, &mut rng);
        let k_server = decapsulate(viewing, &ct).unwrap();
        assert_eq!(k_sender, k_server);

        // ViewingKeys has no spending_sk field or method — type system enforces separation
    }
}
