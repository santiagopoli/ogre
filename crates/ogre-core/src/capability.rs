use crate::ids::{CapabilityId, ConnectorId};
use crate::ActionLevel;
use serde::{Deserialize, Serialize};

/// A capability declaration: what an action can do, and its fixed signature level.
/// Capabilities are declared by connectors and cannot be changed without user signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    pub id: CapabilityId,
    pub connector_id: ConnectorId,
    pub name: String,
    pub description: String,
    pub level: ActionLevel,
}
