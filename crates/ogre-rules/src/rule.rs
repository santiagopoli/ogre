use crate::condition::Condition;
use chrono::{DateTime, Utc};
use ogre_core::ids::RuleId;
use serde::{Deserialize, Serialize};

/// What happens when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// The action is explicitly allowed.
    Allow,
    /// The action is explicitly denied.
    Deny,
    /// The action requires explicit human approval before execution.
    RequireApproval,
}

/// A user-defined rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub version: u32,
    pub description: String,
    pub condition: Condition,
    pub effect: RuleEffect,
    /// Higher priority rules are evaluated first.
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    /// Hex-encoded Ed25519 signature over the canonical JSON (all fields except signature).
    pub signature: Option<String>,
}

impl Rule {
    /// Serialize the rule for signing (excludes the signature field).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut signable = serde_json::to_value(self).expect("rule serialization cannot fail");
        if let serde_json::Value::Object(ref mut map) = signable {
            map.remove("signature");
        }
        serde_json::to_vec(&signable).expect("rule serialization cannot fail")
    }
}
