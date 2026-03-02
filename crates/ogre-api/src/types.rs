use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// -- Request types --

#[derive(Debug, Deserialize)]
pub struct SubmitActionRequest {
    pub capability: String,
    pub connector_id: String,
    pub parameters: serde_json::Value,
    pub signatures: Vec<SignaturePayload>,
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
}

fn default_agent_id() -> String {
    "default-agent".to_string()
}

#[derive(Debug, Deserialize)]
pub struct SignaturePayload {
    pub signer: String,
    pub bytes_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct ApproveActionRequest {
    pub signature: SignaturePayload,
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub description: String,
    pub condition: serde_json::Value,
    pub effect: String,
    pub priority: i32,
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub action_id: Option<String>,
    pub connector_id: Option<String>,
    pub classification: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// -- Response types --

#[derive(Debug, Serialize)]
pub struct ActionResponse {
    pub action_id: String,
    pub status: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct RuleResponse {
    pub id: String,
    pub description: String,
    pub effect: String,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuditEntryResponse {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub action_id: String,
    pub classification: Option<String>,
    pub decision: String,
    pub step_reached: String,
}

#[derive(Debug, Serialize)]
pub struct ChainVerificationResponse {
    pub valid: bool,
    pub entries_checked: u64,
    pub first_broken: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ConnectorResponse {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CapabilityResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub level: String,
}

#[derive(Debug, Serialize)]
pub struct KeysResponse {
    pub ogre: Option<String>,
    pub reviewer: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DashboardSummary {
    pub total_actions: u64,
    pub pending_actions: usize,
    pub chain_valid: bool,
    pub connectors_count: usize,
    pub rules_count: usize,
}

// -- Agent types --

#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub agent_id: String,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub agent_id: String,
}

// -- Enriched pending response --

#[derive(Debug, Serialize)]
pub struct PendingActionResponse {
    pub action_id: String,
    pub agent_id: String,
    pub reason: String,
    pub classification: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
