use hmac::{Hmac, Mac};
use sha2::Sha256;
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::shard::{ShardHeader, ShardWithHmac};
use crate::channel;

type HmacSha256 = Hmac<Sha256>;

pub const M: usize = 8;  // total shards
pub const K: usize = 4;  // data shards (threshold)

/// Compute HMAC for a shard (header + data).
fn compute_shard_hmac(k_pairwise: &[u8; 32], header: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(k_pairwise).unwrap();
    mac.update(header);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify a shard's HMAC. Returns true if valid.
pub fn verify_shard_hmac(k_pairwise: &[u8; 32], shard: &ShardWithHmac) -> bool {
    let header_bytes = shard.header.serialize();
    // Constant-time comparison via HMAC verify_slice
    let mut mac = HmacSha256::new_from_slice(k_pairwise).unwrap();
    mac.update(&header_bytes);
    mac.update(&shard.data);
    mac.verify_slice(&shard.hmac).is_ok()
}

/// Encode an encrypted payload into M shards with HMACs.
pub fn encode(
    payload: &[u8],
    k_pairwise: &[u8; 32],
    commitment: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<Vec<ShardWithHmac>, &'static str> {
    let rs = ReedSolomon::new(K, M - K).map_err(|_| "RS init failed")?;

    // Pad payload to a multiple of K
    let shard_data_len = (payload.len() + K - 1) / K;
    let mut padded = payload.to_vec();
    padded.resize(shard_data_len * K, 0);

    // Split into K data shards + M-K empty parity shards
    let mut shards: Vec<Vec<u8>> = padded
        .chunks(shard_data_len)
        .map(|c| c.to_vec())
        .collect();
    for _ in 0..(M - K) {
        shards.push(vec![0u8; shard_data_len]);
    }

    // RS encode (fills parity shards)
    rs.encode(&mut shards).map_err(|_| "RS encode failed")?;

    // Build shard headers and HMACs
    let mid = channel::msg_id(commitment, nonce);
    let mut result = Vec::with_capacity(M);

    for i in 0..M {
        let header = ShardHeader {
            shard_index: i as u8,
            total_shards: M as u8,
            threshold: K as u8,
            msg_id: mid,
            payload_len: payload.len() as u16,
        };

        let header_bytes = header.serialize();
        let hmac_val = compute_shard_hmac(k_pairwise, &header_bytes, &shards[i]);

        result.push(ShardWithHmac {
            header,
            data: shards[i].clone(),
            hmac: hmac_val,
        });
    }

    Ok(result)
}

/// Decode from available shards. Verifies HMACs; marks invalid shards as missing.
/// Needs at least K valid shards.
pub fn decode(
    available_shards: &[Option<ShardWithHmac>],
    k_pairwise: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if available_shards.len() != M {
        return Err("expected M shard slots");
    }

    // Get payload_len and shard_data_len from any available shard
    let payload_len = available_shards.iter()
        .flatten()
        .next()
        .ok_or("no shards available")?
        .header.payload_len as usize;
    // Verify HMACs and build RS input
    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; M];
    let mut valid_count = 0;

    for opt in available_shards.iter() {
        if let Some(shard) = opt {
            let idx = shard.header.shard_index as usize;
            if idx >= M { continue; }

            if verify_shard_hmac(k_pairwise, shard) {
                shard_data[idx] = Some(shard.data.clone());
                valid_count += 1;
            }
            // Invalid HMAC → leave as None (erasure)
        }
    }

    if valid_count < K {
        return Err("insufficient valid shards after HMAC verification");
    }

    // RS reconstruct
    let rs = ReedSolomon::new(K, M - K).map_err(|_| "RS init failed")?;
    rs.reconstruct(&mut shard_data).map_err(|_| "RS reconstruct failed")?;

    // Reassemble payload from first K data shards
    let mut payload = Vec::with_capacity(payload_len);
    for shard in shard_data.iter().take(K) {
        if let Some(data) = shard {
            payload.extend_from_slice(data);
        } else {
            return Err("data shard missing after reconstruction");
        }
    }
    payload.truncate(payload_len);

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_payload() -> Vec<u8> {
        vec![0xAB; 632] // ENCRYPTED_NOTE_SIZE
    }

    #[test]
    fn test_encode_produces_m_shards() {
        let payload = test_payload();
        let k = [1u8; 32];
        let c = [2u8; 32];
        let n = [3u8; 16];
        let shards = encode(&payload, &k, &c, &n).unwrap();
        assert_eq!(shards.len(), M);
        // Each shard data should be ceil(632/4) = 158 bytes
        assert_eq!(shards[0].data.len(), 158);
    }

    #[test]
    fn test_roundtrip_all_shards() {
        let payload = test_payload();
        let k = [1u8; 32];
        let c = [2u8; 32];
        let n = [3u8; 16];
        let shards = encode(&payload, &k, &c, &n).unwrap();

        let available: Vec<Option<ShardWithHmac>> = shards.into_iter().map(Some).collect();
        let recovered = decode(&available, &k).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_roundtrip_with_minimum_shards() {
        let payload = test_payload();
        let k = [1u8; 32];
        let c = [2u8; 32];
        let n = [3u8; 16];
        let shards = encode(&payload, &k, &c, &n).unwrap();

        // Keep only shards 0, 2, 5, 7 (any K=4 of M=8)
        let mut available: Vec<Option<ShardWithHmac>> = vec![None; M];
        for i in [0, 2, 5, 7] {
            available[i] = Some(shards[i].clone());
        }

        let recovered = decode(&available, &k).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_insufficient_shards_fails() {
        let payload = test_payload();
        let k = [1u8; 32];
        let c = [2u8; 32];
        let n = [3u8; 16];
        let shards = encode(&payload, &k, &c, &n).unwrap();

        // Keep only 3 shards (less than K=4)
        let mut available: Vec<Option<ShardWithHmac>> = vec![None; M];
        for i in [0, 2, 5] {
            available[i] = Some(shards[i].clone());
        }

        let result = decode(&available, &k);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_shard_detected() {
        let payload = test_payload();
        let k = [1u8; 32];
        let c = [2u8; 32];
        let n = [3u8; 16];
        let mut shards = encode(&payload, &k, &c, &n).unwrap();

        // Corrupt shard 1's data
        shards[1].data[0] ^= 0xFF;

        // All 8 shards available, but shard 1 has bad HMAC
        let available: Vec<Option<ShardWithHmac>> = shards.into_iter().map(Some).collect();
        // Should still decode because we have 7 valid shards (> K=4)
        let recovered = decode(&available, &k).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_wrong_key_detects_all_shards_invalid() {
        let payload = test_payload();
        let k = [1u8; 32];
        let wrong_k = [99u8; 32];
        let c = [2u8; 32];
        let n = [3u8; 16];
        let shards = encode(&payload, &k, &c, &n).unwrap();

        let available: Vec<Option<ShardWithHmac>> = shards.into_iter().map(Some).collect();
        let result = decode(&available, &wrong_k);
        assert!(result.is_err()); // All HMACs fail → 0 valid shards
    }

    #[test]
    fn test_all_k_of_m_combinations() {
        use std::collections::HashSet;

        let payload = test_payload();
        let k = [1u8; 32];
        let c = [2u8; 32];
        let n = [3u8; 16];
        let shards = encode(&payload, &k, &c, &n).unwrap();

        // Test all C(8,4) = 70 combinations
        let mut count = 0;
        for mask in 0u8..=255 {
            if mask.count_ones() as usize == K {
                let mut available: Vec<Option<ShardWithHmac>> = vec![None; M];
                for i in 0..M {
                    if mask & (1 << i) != 0 {
                        available[i] = Some(shards[i].clone());
                    }
                }
                let recovered = decode(&available, &k)
                    .unwrap_or_else(|e| panic!("failed for mask {:08b}: {}", mask, e));
                assert_eq!(recovered, payload, "mismatch for mask {:08b}", mask);
                count += 1;
            }
        }
        assert_eq!(count, 70); // C(8,4) = 70
    }
}
