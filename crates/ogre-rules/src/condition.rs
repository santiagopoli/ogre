use ogre_core::ActionLevel;
use ogre_core::ActionPayload;
use serde::{Deserialize, Serialize};

/// A condition that can be evaluated against an action payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    /// All child conditions must be true.
    And { conditions: Vec<Condition> },

    /// At least one child condition must be true.
    Or { conditions: Vec<Condition> },

    /// The child condition must be false.
    Not { condition: Box<Condition> },

    /// Match a regex against a JSON path in the parameters.
    ParameterMatches { path: String, pattern: String },

    /// Match the connector ID.
    ConnectorIs { connector_id: String },

    /// Match the capability ID.
    CapabilityIs { capability_id: String },

    /// Match the action level (evaluated after classification by the proxy).
    /// For pre-classification rules, this is ignored.
    ActionLevelIs { level: ActionLevel },

    /// Always true. Useful for unconditional allow/deny rules.
    Always,
}

impl Condition {
    /// Evaluate this condition against an action payload.
    /// Returns true if the condition matches.
    pub fn evaluate(&self, payload: &ActionPayload) -> bool {
        match self {
            Condition::And { conditions } => conditions.iter().all(|c| c.evaluate(payload)),
            Condition::Or { conditions } => conditions.iter().any(|c| c.evaluate(payload)),
            Condition::Not { condition } => !condition.evaluate(payload),
            Condition::ParameterMatches { path, pattern } => {
                eval_parameter_match(payload, path, pattern)
            }
            Condition::ConnectorIs { connector_id } => {
                payload.connector_id.as_str() == connector_id
            }
            Condition::CapabilityIs { capability_id } => {
                payload.capability.as_str() == capability_id
            }
            Condition::ActionLevelIs { .. } => {
                // Action level matching is handled by the proxy after classification.
                // At the rules layer, we can't classify yet, so this is a no-op (matches all).
                // The proxy will re-evaluate level-based rules after classification.
                true
            }
            Condition::Always => true,
        }
    }

    /// Evaluate with a known action level (used by proxy after classification).
    pub fn evaluate_with_level(
        &self,
        payload: &ActionPayload,
        known_level: Option<ActionLevel>,
    ) -> bool {
        match self {
            Condition::And { conditions } => conditions
                .iter()
                .all(|c| c.evaluate_with_level(payload, known_level)),
            Condition::Or { conditions } => conditions
                .iter()
                .any(|c| c.evaluate_with_level(payload, known_level)),
            Condition::Not { condition } => !condition.evaluate_with_level(payload, known_level),
            Condition::ActionLevelIs { level } => {
                known_level.as_ref().map_or(true, |kl| kl == level)
            }
            other => other.evaluate(payload),
        }
    }
}

fn eval_parameter_match(payload: &ActionPayload, path: &str, pattern: &str) -> bool {
    let value = resolve_json_path(&payload.parameters, path);
    match value {
        Some(s) => regex::Regex::new(pattern)
            .map(|re| re.is_match(&s))
            .unwrap_or(false),
        None => false,
    }
}

/// Simple JSON path resolver. Supports dot notation: "$.field.subfield"
fn resolve_json_path(value: &serde_json::Value, path: &str) -> Option<String> {
    let path = path.strip_prefix("$.").unwrap_or(path);
    let mut current = value;

    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment)?;
            }
            _ => return None,
        }
    }

    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        other => Some(other.to_string()),
    }
}
