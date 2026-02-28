use sha2::{Digest, Sha256};

pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Compute the hash of an audit entry given its serialized bytes and the previous hash.
pub fn compute_entry_hash(sequence: u64, entry_bytes: &[u8], previous_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sequence.to_le_bytes());
    hasher.update(previous_hash);
    hasher.update(entry_bytes);
    hasher.finalize().into()
}
