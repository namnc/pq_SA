use std::path::{Path, PathBuf};
use std::fs;

use primitives::shard::ShardWithHmac;

/// Simulates blob data availability using the local filesystem.
/// Each note's shards are stored in a directory: {base}/{note_id}/shard_{i}.bin
pub struct Sidecar {
    base_path: PathBuf,
}

impl Sidecar {
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        let base = base_path.as_ref().to_path_buf();
        fs::create_dir_all(&base).expect("failed to create sidecar directory");
        Self { base_path: base }
    }

    /// Write a shard for a specific note and server index.
    pub fn write_shard(&self, note_id: u64, shard: &ShardWithHmac) -> std::io::Result<()> {
        let dir = self.base_path.join(format!("{}", note_id));
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("shard_{}.bin", shard.header.shard_index));
        fs::write(path, shard.to_bytes())
    }

    /// Read a shard for a specific note and server index.
    pub fn read_shard(&self, note_id: u64, server_id: u8) -> Option<ShardWithHmac> {
        let path = self.base_path
            .join(format!("{}", note_id))
            .join(format!("shard_{}.bin", server_id));
        let bytes = fs::read(path).ok()?;
        ShardWithHmac::from_bytes(&bytes)
    }

    /// Read shards for a note from specific server indices.
    /// Returns M-sized vec with None for missing/unavailable servers.
    pub fn read_shards(
        &self,
        note_id: u64,
        server_ids: &[u8],
        total_servers: usize,
    ) -> Vec<Option<ShardWithHmac>> {
        let mut result: Vec<Option<ShardWithHmac>> = vec![None; total_servers];
        for &sid in server_ids {
            if let Some(shard) = self.read_shard(note_id, sid) {
                result[sid as usize] = Some(shard);
            }
        }
        result
    }

    /// List all note IDs that have shards.
    pub fn list_notes(&self) -> Vec<u64> {
        let mut notes = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(id) = name.parse::<u64>() {
                        notes.push(id);
                    }
                }
            }
        }
        notes.sort();
        notes
    }

    /// Clean up all sidecar data.
    pub fn clear(&self) {
        let _ = fs::remove_dir_all(&self.base_path);
        fs::create_dir_all(&self.base_path).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::shard::{ShardHeader, ShardWithHmac};

    fn make_test_shard(index: u8) -> ShardWithHmac {
        ShardWithHmac {
            header: ShardHeader {
                shard_index: index,
                total_shards: 8,
                threshold: 4,
                msg_id: [index; 16],
                payload_len: 632,
            },
            data: vec![index; 158],
            hmac: [index; 32],
        }
    }

    #[test]
    fn test_write_read_roundtrip() {
        let sidecar = Sidecar::new("/tmp/PQ-SA-sidecar-test");
        sidecar.clear();

        let shard = make_test_shard(3);
        sidecar.write_shard(42, &shard).unwrap();

        let recovered = sidecar.read_shard(42, 3).unwrap();
        assert_eq!(recovered.header.shard_index, 3);
        assert_eq!(recovered.data, vec![3u8; 158]);
        assert_eq!(recovered.hmac, [3u8; 32]);

        sidecar.clear();
    }

    #[test]
    fn test_read_missing_returns_none() {
        let sidecar = Sidecar::new("/tmp/PQ-SA-sidecar-test-2");
        sidecar.clear();
        assert!(sidecar.read_shard(999, 0).is_none());
        sidecar.clear();
    }

    #[test]
    fn test_list_notes() {
        let sidecar = Sidecar::new("/tmp/PQ-SA-sidecar-test-3");
        sidecar.clear();

        sidecar.write_shard(10, &make_test_shard(0)).unwrap();
        sidecar.write_shard(20, &make_test_shard(0)).unwrap();
        sidecar.write_shard(30, &make_test_shard(0)).unwrap();

        let notes = sidecar.list_notes();
        assert_eq!(notes, vec![10, 20, 30]);

        sidecar.clear();
    }

    #[test]
    fn test_read_shards_partial() {
        let sidecar = Sidecar::new("/tmp/PQ-SA-sidecar-test-4");
        sidecar.clear();

        // Write shards 0, 2, 5, 7 for note 1
        for i in [0, 2, 5, 7] {
            sidecar.write_shard(1, &make_test_shard(i)).unwrap();
        }

        let shards = sidecar.read_shards(1, &[0, 1, 2, 3, 4, 5, 6, 7], 8);
        assert!(shards[0].is_some());
        assert!(shards[1].is_none());
        assert!(shards[2].is_some());
        assert!(shards[3].is_none());
        assert!(shards[4].is_none());
        assert!(shards[5].is_some());
        assert!(shards[6].is_none());
        assert!(shards[7].is_some());

        sidecar.clear();
    }
}
