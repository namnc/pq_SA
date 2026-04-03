/// Shard header prepended to each erasure-coded shard.
#[derive(Clone, Debug)]
pub struct ShardHeader {
    pub shard_index: u8,
    pub total_shards: u8,
    pub threshold: u8,
    pub msg_id: [u8; 16],
    pub payload_len: u16,
}

pub const SHARD_HEADER_SIZE: usize = 1 + 1 + 1 + 16 + 2; // 21

impl ShardHeader {
    pub fn serialize(&self) -> [u8; SHARD_HEADER_SIZE] {
        let mut buf = [0u8; SHARD_HEADER_SIZE];
        buf[0] = self.shard_index;
        buf[1] = self.total_shards;
        buf[2] = self.threshold;
        buf[3..19].copy_from_slice(&self.msg_id);
        buf[19..21].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < SHARD_HEADER_SIZE {
            return None;
        }
        Some(Self {
            shard_index: buf[0],
            total_shards: buf[1],
            threshold: buf[2],
            msg_id: buf[3..19].try_into().unwrap(),
            payload_len: u16::from_be_bytes(buf[19..21].try_into().unwrap()),
        })
    }
}

/// A shard with its integrity HMAC.
#[derive(Clone, Debug)]
pub struct ShardWithHmac {
    pub header: ShardHeader,
    pub data: Vec<u8>,
    pub hmac: [u8; 32],
}

impl ShardWithHmac {
    /// Serialize to bytes: header(21) + data(variable) + hmac(32)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SHARD_HEADER_SIZE + self.data.len() + 32);
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&self.data);
        buf.extend_from_slice(&self.hmac);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < SHARD_HEADER_SIZE + 32 {
            return None;
        }
        let header = ShardHeader::deserialize(&buf[..SHARD_HEADER_SIZE])?;
        let data_end = buf.len() - 32;
        let data = buf[SHARD_HEADER_SIZE..data_end].to_vec();
        let hmac: [u8; 32] = buf[data_end..].try_into().unwrap();
        Some(Self { header, data, hmac })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = ShardHeader {
            shard_index: 3,
            total_shards: 8,
            threshold: 4,
            msg_id: [0xAB; 16],
            payload_len: 632,
        };
        let serialized = header.serialize();
        assert_eq!(serialized.len(), SHARD_HEADER_SIZE);
        let deserialized = ShardHeader::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.shard_index, 3);
        assert_eq!(deserialized.total_shards, 8);
        assert_eq!(deserialized.threshold, 4);
        assert_eq!(deserialized.payload_len, 632);
    }

    #[test]
    fn test_shard_with_hmac_roundtrip() {
        let shard = ShardWithHmac {
            header: ShardHeader {
                shard_index: 0,
                total_shards: 8,
                threshold: 4,
                msg_id: [1u8; 16],
                payload_len: 100,
            },
            data: vec![0xAA; 25],
            hmac: [0xBB; 32],
        };
        let bytes = shard.to_bytes();
        let recovered = ShardWithHmac::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.header.shard_index, 0);
        assert_eq!(recovered.data, vec![0xAA; 25]);
        assert_eq!(recovered.hmac, [0xBB; 32]);
    }
}
