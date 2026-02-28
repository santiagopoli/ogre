mod nonce;
mod pending;
mod proxy;

pub use pending::{PendingAction, PendingActionStore};
pub use proxy::{ProcessResult, Proxy, ProxyConfig};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error(transparent)]
    Core(#[from] ogre_core::OgreError),

    #[error(transparent)]
    Rules(#[from] ogre_rules::RulesError),

    #[error(transparent)]
    Verification(#[from] ogre_crypto::verification::VerificationError),

    #[error(transparent)]
    Connector(#[from] ogre_core::ConnectorError),

    #[error(transparent)]
    Audit(#[from] ogre_audit::AuditError),

    #[error("replay detected: nonce already used")]
    ReplayDetected,

    #[error("request expired: timestamp outside acceptance window")]
    RequestExpired,

    #[error("unknown connector: {0}")]
    UnknownConnector(String),

    #[error("unknown capability {capability} on connector {connector}")]
    UnknownCapability {
        capability: String,
        connector: String,
    },

    #[error("capability level mismatch: {capability} requires {expected}, classified as {actual}")]
    CapabilityLevelMismatch {
        capability: String,
        expected: ogre_core::ActionLevel,
        actual: ogre_core::ActionLevel,
    },

    #[error("action {0} is pending user approval")]
    PendingApproval(String),

    #[error("action {0} not found")]
    ActionNotFound(String),

    #[error("action {0} has expired")]
    ActionExpired(String),
}
