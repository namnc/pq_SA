/// Fixed-size note plaintext. MEMO_BYTES = 512.
/// Serialized: 616 B. Encrypted with AEAD tag: 632 B.
#[derive(Clone, Debug, PartialEq)]
pub struct NotePlaintext {
    pub value: u64,                  // 8 B
    pub asset_id: [u8; 32],         // 32 B
    pub blinding_factor: [u8; 32],  // 32 B
    pub memo: [u8; 512],            // 512 B
    pub nullifier_seed: [u8; 32],   // 32 B
}

pub const NOTE_PLAINTEXT_SIZE: usize = 8 + 32 + 32 + 512 + 32; // 616
pub const ENCRYPTED_NOTE_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16; // 632 (+ Poly1305 tag)

impl NotePlaintext {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(NOTE_PLAINTEXT_SIZE);
        buf.extend_from_slice(&self.value.to_be_bytes());
        buf.extend_from_slice(&self.asset_id);
        buf.extend_from_slice(&self.blinding_factor);
        buf.extend_from_slice(&self.memo);
        buf.extend_from_slice(&self.nullifier_seed);
        assert_eq!(buf.len(), NOTE_PLAINTEXT_SIZE);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != NOTE_PLAINTEXT_SIZE {
            return None;
        }
        Some(Self {
            value: u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            asset_id: buf[8..40].try_into().unwrap(),
            blinding_factor: buf[40..72].try_into().unwrap(),
            memo: buf[72..584].try_into().unwrap(),
            nullifier_seed: buf[584..616].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_roundtrip() {
        let note = NotePlaintext {
            value: 1_000_000,
            asset_id: [1u8; 32],
            blinding_factor: [2u8; 32],
            memo: [0u8; 512],
            nullifier_seed: [3u8; 32],
        };
        let serialized = note.serialize();
        assert_eq!(serialized.len(), NOTE_PLAINTEXT_SIZE);
        let deserialized = NotePlaintext::deserialize(&serialized).unwrap();
        assert_eq!(note, deserialized);
    }

    #[test]
    fn test_serialize_size() {
        assert_eq!(NOTE_PLAINTEXT_SIZE, 616);
        assert_eq!(ENCRYPTED_NOTE_SIZE, 632);
    }
}
