use chrono::{DateTime, Utc};
use ogre_core::ids::{ActionId, RuleId};
use ogre_core::ActionLevel;
use serde::{Deserialize, Serialize};

/// How far the request progressed through the proxy pipeline before completing or failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyStep {
    Received,
    RulesEvaluated,
    Classified,
    CapabilityVerified,
    SignaturesVerified,
    Sanitized,
    Executed,
}

/// The proxy's final decision on a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied { reason: String },
    PendingUserApproval,
    Error { details: String },
}

/// A single entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub action_id: ActionId,
    pub connector_id: Option<String>,
    pub capability: Option<String>,
    pub classification: Option<ActionLevel>,
    pub signers_present: Vec<String>,
    pub rules_evaluated: Vec<RuleId>,
    pub step_reached: ProxyStep,
    pub decision: Decision,
    pub result_summary: Option<String>,
    #[serde(with = "hex_hash")]
    pub previous_hash: [u8; 32],
    #[serde(with = "hex_hash")]
    pub entry_hash: [u8; 32],
}

impl AuditEntry {
    /// Serialize the entry content (everything except entry_hash) to bytes for hashing.
    pub fn hashable_bytes(&self) -> Vec<u8> {
        // Serialize a copy without the entry_hash to get deterministic hashable content.
        // We serialize the key fields in a fixed order.
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        buf.extend_from_slice(self.action_id.as_str().as_bytes());
        if let Ok(json) = serde_json::to_vec(&self.decision) {
            buf.extend_from_slice(&json);
        }
        buf.extend_from_slice(&self.previous_hash);
        buf
    }
}

/// Filter criteria for querying the audit log.
#[derive(Debug, Default)]
pub struct AuditFilter {
    pub action_id: Option<ActionId>,
    pub connector_id: Option<String>,
    pub classification: Option<ActionLevel>,
    pub decision_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl AuditEntry {
    pub fn matches(&self, filter: &AuditFilter) -> bool {
        if let Some(ref id) = filter.action_id {
            if &self.action_id != id {
                return false;
            }
        }
        if let Some(ref cid) = filter.connector_id {
            if self.connector_id.as_ref() != Some(cid) {
                return false;
            }
        }
        if let Some(ref level) = filter.classification {
            if self.classification.as_ref() != Some(level) {
                return false;
            }
        }
        if let Some(ref from) = filter.from {
            if self.timestamp < *from {
                return false;
            }
        }
        if let Some(ref to) = filter.to {
            if self.timestamp > *to {
                return false;
            }
        }
        true
    }
}

mod hex_hash {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(hash: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let hex = String::deserialize(deserializer)?;
        if hex.len() != 64 {
            return Err(serde::de::Error::custom("hash hex must be 64 chars"));
        }
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect::<Result<_, _>>()?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid hash length"))?;
        Ok(arr)
    }
}
