use crate::ids::{ActionId, CapabilityId, ConnectorId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The risk level of an action, determined by the connector.
/// Dictates how many signatures are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionLevel {
    /// Read-only operations. Requires 2/2: Ogre + Reviewer.
    Read,
    /// State-modifying but recoverable operations. Requires 2/2: Ogre + Reviewer.
    Write,
    /// Irreversible or high-impact operations. Requires 3/3: Ogre + Reviewer + User.
    Destructive,
}

impl ActionLevel {
    pub fn required_signatures(&self) -> usize {
        match self {
            ActionLevel::Read => 2,
            ActionLevel::Write => 2,
            ActionLevel::Destructive => 3,
        }
    }

    pub fn requires_user_signature(&self) -> bool {
        matches!(self, ActionLevel::Destructive)
    }
}

impl std::fmt::Display for ActionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionLevel::Read => write!(f, "read"),
            ActionLevel::Write => write!(f, "write"),
            ActionLevel::Destructive => write!(f, "destructive"),
        }
    }
}

/// The payload of an action request — what the agent wants to do.
/// This is the data that gets signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPayload {
    pub id: ActionId,
    pub nonce: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub capability: CapabilityId,
    pub connector_id: ConnectorId,
    pub parameters: serde_json::Value,
}

impl ActionPayload {
    /// Serialize the payload to canonical bytes for signing.
    /// Uses serde_json with sorted keys for deterministic output.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // serde_json preserves insertion order, but our structs have fixed field order
        // from the derive, which is deterministic.
        serde_json::to_vec(self).expect("ActionPayload serialization cannot fail")
    }
}

/// An action that has been sanitized by a connector and is safe to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeAction {
    pub original_id: ActionId,
    pub connector_id: ConnectorId,
    pub classification: ActionLevel,
    pub sanitized_parameters: serde_json::Value,
}

/// The result of executing an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_id: ActionId,
    pub outcome: Outcome,
    pub data: Option<serde_json::Value>,
    #[serde(with = "duration_millis")]
    pub duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outcome {
    Success,
    PartialSuccess { details: String },
    Error { code: String, message: String },
}

impl Outcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Outcome::Success | Outcome::PartialSuccess { .. })
    }
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
