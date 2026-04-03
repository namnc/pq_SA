use sha2::{Sha256, Digest};

/// Identifies a pairwise channel from first-contact data.
/// Deterministic: same (epk, ct_pq) always gives the same channel_id.
pub fn channel_id(epk: &[u8], ct_pq: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(epk);
    hasher.update(ct_pq);
    hasher.finalize().into()
}

/// Msg ID for matching shards from different servers to the same note.
/// Deterministic from public calldata (commitment + nonce).
pub fn msg_id(commitment: &[u8; 32], nonce: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(commitment);
    hasher.update(nonce);
    let hash: [u8; 32] = hasher.finalize().into();
    hash[0..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_id_deterministic() {
        let epk = [1u8; 33];
        let ct_pq = [2u8; 1088];
        let id1 = channel_id(&epk, &ct_pq);
        let id2 = channel_id(&epk, &ct_pq);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_channel_id_differs() {
        let epk1 = [1u8; 33];
        let epk2 = [2u8; 33];
        let ct_pq = [3u8; 1088];
        assert_ne!(channel_id(&epk1, &ct_pq), channel_id(&epk2, &ct_pq));
    }

    #[test]
    fn test_msg_id_deterministic() {
        let commitment = [1u8; 32];
        let nonce = [2u8; 16];
        let id1 = msg_id(&commitment, &nonce);
        let id2 = msg_id(&commitment, &nonce);
        assert_eq!(id1, id2);
    }
}
