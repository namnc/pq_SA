use sha2::{Sha256, Digest};

/// Compute note commitment.
///
/// For the PoC, we use SHA-256 as a collision-resistant hash.
/// Production should use Poseidon-256 over the BN254 scalar field
/// for STARK-friendliness and ≥128-bit PQ collision resistance.
///
/// The commitment binds the note plaintext to the recipient address,
/// preventing the same note from being claimed by multiple recipients.
pub fn note_commitment(note_plaintext: &[u8], recipient_addr: &[u8; 20]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PQ-SA-commitment-v1");
    hasher.update(note_plaintext);
    hasher.update(recipient_addr);
    hasher.finalize().into()
}

/// Compute nullifier seed from pairwise key + nonce.
/// The nullifier seed is included in the encrypted note so the recipient
/// can later derive the nullifier for spending.
pub fn nullifier_seed(k_pairwise: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PQ-SA-nullifier-v1");
    hasher.update(k_pairwise);
    hasher.update(nonce);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_deterministic() {
        let plaintext = [1u8; 100];
        let addr = [2u8; 20];
        let c1 = note_commitment(&plaintext, &addr);
        let c2 = note_commitment(&plaintext, &addr);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_changes_with_plaintext() {
        let addr = [2u8; 20];
        let c1 = note_commitment(&[1u8; 100], &addr);
        let c2 = note_commitment(&[2u8; 100], &addr);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_changes_with_addr() {
        let plaintext = [1u8; 100];
        let c1 = note_commitment(&plaintext, &[1u8; 20]);
        let c2 = note_commitment(&plaintext, &[2u8; 20]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_nullifier_seed_deterministic() {
        let k = [1u8; 32];
        let n = [2u8; 16];
        let s1 = nullifier_seed(&k, &n);
        let s2 = nullifier_seed(&k, &n);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_nullifier_seed_changes() {
        let k = [1u8; 32];
        let s1 = nullifier_seed(&k, &[1u8; 16]);
        let s2 = nullifier_seed(&k, &[2u8; 16]);
        assert_ne!(s1, s2);
    }
}
