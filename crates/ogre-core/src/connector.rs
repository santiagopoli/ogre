use crate::action::{ActionLevel, ActionPayload, ActionResult, SafeAction};
use crate::capability::CapabilityDeclaration;
use crate::error::ConnectorError;
use crate::ids::ConnectorId;

/// The connector trait: domain-specific knowledge about a protected resource.
///
/// Connectors are the only code that touches protected resources. They classify
/// actions by risk level, sanitize them to make them safe, and execute them.
///
/// # Implementing a connector
///
/// 1. `classify` — Inspect the action parameters and return the risk level.
///    This must be deterministic: the same parameters always produce the same level.
///
/// 2. `sanitize` — Transform the action to make it safe within this domain.
///    Must NOT change the classification. If sanitization would change the level,
///    return an error instead.
///
/// 3. `execute` — Run the sanitized action against the real resource.
///    Only called after all signatures have been verified by the proxy.
///
/// 4. `capabilities` — Declare what this connector can do and at what level.
///    The proxy uses this to verify that incoming actions reference valid capabilities.
pub trait Connector: Send + Sync {
    /// Unique identifier for this connector.
    fn id(&self) -> &ConnectorId;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Classify an action's risk level based on domain knowledge.
    fn classify(&self, action: &ActionPayload) -> Result<ActionLevel, ConnectorError>;

    /// Transform the action to make it safe within this domain.
    /// The returned SafeAction must have the same classification as the original.
    fn sanitize(&self, action: &ActionPayload) -> Result<SafeAction, ConnectorError>;

    /// Execute a sanitized action against the protected resource.
    fn execute(&self, action: &SafeAction) -> Result<ActionResult, ConnectorError>;

    /// List all capabilities this connector provides.
    fn capabilities(&self) -> Vec<CapabilityDeclaration>;
}
