use crate::ids::{ActionId, CapabilityId, ConnectorId, RuleId};
use crate::ActionLevel;
use thiserror::Error;

/// Top-level error type for the OGRE system.
#[derive(Debug, Error)]
pub enum OgreError {
    #[error("connector error: {0}")]
    Connector(#[from] ConnectorError),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("rule denied action {action_id}: {reason}")]
    RuleDenied {
        action_id: ActionId,
        rule_id: RuleId,
        reason: String,
    },

    #[error("no rule allows action {action_id} (default-deny)")]
    DefaultDeny { action_id: ActionId },

    #[error("insufficient signatures for {level}: have {have}, need {need}")]
    InsufficientSignatures {
        level: ActionLevel,
        have: usize,
        need: usize,
    },

    #[error("invalid signature from {signer}")]
    InvalidSignature { signer: String },

    #[error("unknown connector: {0}")]
    UnknownConnector(ConnectorId),

    #[error("unknown capability {capability} on connector {connector}")]
    UnknownCapability {
        capability: CapabilityId,
        connector: ConnectorId,
    },

    #[error("capability {capability} requires {expected} but action classified as {actual}")]
    CapabilityLevelMismatch {
        capability: CapabilityId,
        expected: ActionLevel,
        actual: ActionLevel,
    },

    #[error("replay detected: nonce already used for action {0}")]
    ReplayDetected(ActionId),

    #[error("request expired: timestamp {timestamp} outside acceptance window")]
    RequestExpired { timestamp: String },

    #[error("action {0} is pending user approval")]
    PendingApproval(ActionId),

    #[error("action {0} has expired")]
    ActionExpired(ActionId),

    #[error("action {0} not found")]
    ActionNotFound(ActionId),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Errors from connector operations.
#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("classification failed: {0}")]
    ClassificationFailed(String),

    #[error("sanitization failed: {0}")]
    SanitizationFailed(String),

    #[error("sanitization would change classification from {from} to {to}")]
    SanitizationChangedLevel {
        from: ActionLevel,
        to: ActionLevel,
    },

    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    #[error("multi-statement query rejected")]
    MultiStatement,

    #[error("query timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("connection pool exhausted")]
    PoolExhausted,

    #[error("unsupported operation: {0}")]
    Unsupported(String),
}
