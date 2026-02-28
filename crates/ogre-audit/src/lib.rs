mod entry;
mod file_log;
mod hash_chain;

pub use entry::{AuditEntry, AuditFilter, Decision, ProxyStep};
pub use file_log::FileAuditLog;
pub use hash_chain::GENESIS_HASH;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("chain broken at sequence {sequence}: expected {expected}, got {actual}")]
    ChainBroken {
        sequence: u64,
        expected: String,
        actual: String,
    },

    #[error("lock poisoned")]
    LockPoisoned,
}

/// The audit log trait. Implementations must be append-only and tamper-evident.
pub trait AuditLog: Send + Sync {
    fn append(&self, entry: AuditEntry) -> Result<(), AuditError>;
    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError>;
    fn verify_chain(&self) -> Result<ChainVerification, AuditError>;
    fn last_hash(&self) -> Result<[u8; 32], AuditError>;
    fn len(&self) -> Result<u64, AuditError>;
}

#[derive(Debug)]
pub struct ChainVerification {
    pub valid: bool,
    pub entries_checked: u64,
    pub first_broken: Option<u64>,
}
