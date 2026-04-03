use hkdf::Hkdf;
use sha2::Sha256;
use ml_kem::ml_kem_768::{self, MlKem768};
use ml_kem::{B32, Seed, DecapsulationKey, EncapsulationKey, Decapsulate, KeyExport};
use rand::RngCore;

pub const DOMAIN: &[u8] = b"PQ-SA-v1";
pub const PAIRWISE_KEY_LEN: usize = 32;
pub const EPK_SIZE: usize = 33;

pub struct RecipientKeyPair {
    pub sk_ec: secp256k1::SecretKey,
    pub pk_ec: secp256k1::PublicKey,
    pub dk_kem: DecapsulationKey<MlKem768>,
    pub ek_kem: EncapsulationKey<MlKem768>,
}

impl RecipientKeyPair {
    pub fn generate(rng: &mut rand_chacha::ChaChaRng) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let (sk_ec, pk_ec) = secp.generate_keypair(rng);

        // Use ml-kem's deterministic key generation to avoid rand_core version conflict.
        // Generate a 64-byte random seed with rand 0.8, pass to from_seed.
        let mut seed_bytes = [0u8; 64];
        rng.fill_bytes(&mut seed_bytes);
        let dk_kem = DecapsulationKey::<MlKem768>::from_seed(
            Seed::try_from(seed_bytes.as_slice()).expect("64-byte seed"),
        );
        let ek_kem = dk_kem.encapsulation_key().clone();

        Self { sk_ec, pk_ec, dk_kem, ek_kem }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use rand_chacha::ChaChaRng;
        use rand::SeedableRng;
        let mut rng = ChaChaRng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    pub fn pk_ec_bytes(&self) -> [u8; EPK_SIZE] {
        self.pk_ec.serialize()
    }

    /// Serialize the ML-KEM-768 encapsulation key (1184 bytes).
    pub fn ek_kem_bytes(&self) -> Vec<u8> {
        let key_arr = self.ek_kem.to_bytes();
        let slice: &[u8] = key_arr.as_ref();
        slice.to_vec()
    }
}

/// Reconstruct an EncapsulationKey from bytes (e.g., read from chain).
pub fn ek_kem_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>, &'static str> {
    let key_arr = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(bytes)
        .map_err(|_| "invalid ek_kem length")?;
    EncapsulationKey::<MlKem768>::new(&key_arr).map_err(|_| "invalid ek_kem")
}

/// Reconstruct a secp256k1 PublicKey from bytes (33-byte compressed).
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

pub fn encapsulate(
    recipient_pk_ec: &secp256k1::PublicKey,
    recipient_ek_kem: &EncapsulationKey<MlKem768>,
    rng: &mut rand_chacha::ChaChaRng,
) -> (FirstContactCiphertext, [u8; PAIRWISE_KEY_LEN]) {
    let secp = secp256k1::Secp256k1::new();

    // ECDH
    let (esk, epk) = secp.generate_keypair(rng);
    let ecdh_point = secp256k1::ecdh::shared_secret_point(recipient_pk_ec, &esk);
    let ss_ec = &ecdh_point[..32];

    // ML-KEM-768: use deterministic encapsulation with random bytes from rand 0.8
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

pub fn decapsulate(
    recipient: &RecipientKeyPair,
    ct: &FirstContactCiphertext,
) -> Result<[u8; PAIRWISE_KEY_LEN], &'static str> {
    // ECDH
    let epk = secp256k1::PublicKey::from_slice(&ct.epk)
        .map_err(|_| "invalid ephemeral public key")?;
    let ecdh_point = secp256k1::ecdh::shared_secret_point(&epk, &recipient.sk_ec);
    let ss_ec = &ecdh_point[..32];

    // ML-KEM decapsulation (deterministic, no RNG needed)
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
        let (ct, k_sender) = encapsulate(&recipient.pk_ec, &recipient.ek_kem, &mut rng);
        let k_recipient = decapsulate(&recipient, &ct).unwrap();
        assert_eq!(k_sender, k_recipient);
    }

    #[test]
    fn test_wrong_recipient() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let r1 = RecipientKeyPair::generate(&mut rng);
        let r2 = RecipientKeyPair::generate(&mut rng);
        let (ct, k_sender) = encapsulate(&r1.pk_ec, &r1.ek_kem, &mut rng);
        let k_wrong = decapsulate(&r2, &ct).unwrap();
        assert_ne!(k_sender, k_wrong);
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [99u8; 32];
        let r1 = RecipientKeyPair::from_seed(&seed);
        let r2 = RecipientKeyPair::from_seed(&seed);
        assert_eq!(r1.pk_ec_bytes(), r2.pk_ec_bytes());
    }

    #[test]
    fn test_ciphertext_sizes() {
        let mut rng = ChaChaRng::seed_from_u64(0);
        let recipient = RecipientKeyPair::generate(&mut rng);
        let (ct, _) = encapsulate(&recipient.pk_ec, &recipient.ek_kem, &mut rng);
        assert_eq!(ct.epk.len(), 33);
        assert_eq!(ct.ct_pq.len(), 1088);
    }
}
