use crate::nonce::NonceTracker;
use crate::pending::{PendingActionStore, PendingReason};
use crate::ProxyError;
use chrono::{Duration, Utc};
use ogre_audit::*;
use ogre_core::ids::ActionId;
use ogre_core::{ActionLevel, ActionPayload, ActionResult, Connector};
use ogre_crypto::keys::PublicKeySet;
use ogre_crypto::signature::Signature;

use ogre_crypto::verification::SignatureVerifier;
use ogre_rules::{RuleDecision, RulesEngine};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{info, warn};

/// Configuration for the proxy.
pub struct ProxyConfig {
    /// How old a request can be before it's rejected (in seconds).
    pub timestamp_tolerance_secs: i64,
    /// How long a pending destructive action lives before expiring (in minutes).
    pub pending_ttl_minutes: i64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            timestamp_tolerance_secs: 300, // 5 minutes
            pending_ttl_minutes: 30,
        }
    }
}

/// The deterministic proxy. Orchestrates rules, signatures, connectors, and audit.
pub struct Proxy {
    verifier: SignatureVerifier,
    rules: RulesEngine,
    connectors: HashMap<String, Arc<dyn Connector>>,
    audit: Arc<dyn AuditLog>,
    nonces: NonceTracker,
    pending: PendingActionStore,
    config: ProxyConfig,
    agents: std::sync::RwLock<HashSet<String>>,
}

impl Proxy {
    pub fn new(
        keys: PublicKeySet,
        rules: RulesEngine,
        audit: Arc<dyn AuditLog>,
        config: ProxyConfig,
    ) -> Self {
        let pending_ttl = config.pending_ttl_minutes;
        let mut initial_agents = HashSet::new();
        initial_agents.insert("default-agent".to_string());
        Self {
            verifier: SignatureVerifier::new(keys),
            rules,
            connectors: HashMap::new(),
            audit,
            nonces: NonceTracker::new(),
            pending: PendingActionStore::new(pending_ttl),
            config,
            agents: std::sync::RwLock::new(initial_agents),
        }
    }

    pub fn register_connector(&mut self, connector: Arc<dyn Connector>) {
        let id = connector.id().as_str().to_string();
        self.connectors.insert(id, connector);
    }

    pub fn register_agent(&self, agent_id: &str) {
        let mut agents = self.agents.write().expect("agents lock poisoned");
        agents.insert(agent_id.to_string());
    }

    pub fn agents(&self) -> Vec<String> {
        let agents = self.agents.read().expect("agents lock poisoned");
        agents.iter().cloned().collect()
    }

    pub fn rules_engine(&self) -> &RulesEngine {
        &self.rules
    }

    pub fn rules_engine_mut(&mut self) -> &mut RulesEngine {
        &mut self.rules
    }

    pub fn connectors(&self) -> &HashMap<String, Arc<dyn Connector>> {
        &self.connectors
    }

    pub fn pending_store(&self) -> &PendingActionStore {
        &self.pending
    }

    pub fn verifier(&self) -> &SignatureVerifier {
        &self.verifier
    }

    /// Process an action request with its signatures.
    /// For Read/Write: executes immediately if signatures are valid.
    /// For Destructive: returns PendingApproval if only agent sigs are present.
    pub fn process(
        &self,
        payload: ActionPayload,
        signatures: &[Signature],
    ) -> Result<ProcessResult, ProxyError> {
        let action_id = payload.id.clone();
        let agent_id_str = payload.agent_id.as_str().to_string();
        let mut step = ProxyStep::Received;

        // 0. Validate agent is registered
        {
            let agents = self.agents.read().expect("agents lock poisoned");
            if !agents.contains(&agent_id_str) {
                self.log_denied(&payload, step, "unknown agent");
                return Err(ProxyError::UnknownAgent(agent_id_str));
            }
        }

        // 1. Check nonce (replay protection)
        if !self.nonces.check_and_record(&payload.nonce) {
            self.log_denied(&payload, step, "replay detected");
            return Err(ProxyError::ReplayDetected);
        }

        // 2. Check timestamp
        let now = Utc::now();
        let tolerance = Duration::seconds(self.config.timestamp_tolerance_secs);
        if payload.timestamp < now - tolerance || payload.timestamp > now + tolerance {
            self.log_denied(&payload, step, "request expired");
            return Err(ProxyError::RequestExpired);
        }

        // 3. Evaluate user rules (pre-classification)
        step = ProxyStep::RulesEvaluated;
        self.rules.evaluate(&payload).map_err(|e| {
            self.log_denied(&payload, step, &e.to_string());
            ProxyError::Rules(e)
        })?;

        // 4. Find connector
        let connector_id = payload.connector_id.as_str().to_string();
        let connector = self
            .connectors
            .get(&connector_id)
            .ok_or_else(|| {
                self.log_denied(&payload, step, "unknown connector");
                ProxyError::UnknownConnector(connector_id.clone())
            })?;

        // 5. Classify
        step = ProxyStep::Classified;
        let level = connector.classify(&payload).map_err(|e| {
            self.log_denied(&payload, step, &e.to_string());
            ProxyError::Connector(e)
        })?;

        info!(
            action_id = %action_id,
            connector = %connector_id,
            level = %level,
            "action classified"
        );

        // 5b. Build ActionContext and evaluate context-aware rules
        let context = connector.extract_context(&payload);
        let context_with_level = ogre_core::ActionContext {
            tables: context.tables,
            level: Some(level),
        };
        let rule_decision = self.rules.evaluate_with_context(&payload, &context_with_level).map_err(|e| {
            self.log_denied(&payload, step, &e.to_string());
            ProxyError::Rules(e)
        })?;

        // If a rule requires approval, route to pending regardless of level
        if let RuleDecision::RequireApproval { ref rule_id } = rule_decision {
            // Verify agent signatures
            let agent_request = self
                .verifier
                .verify_agent_approved(payload, signatures)
                .map_err(|e| {
                    self.log_denied_by_id(&action_id, step, &e.to_string());
                    ProxyError::Verification(e)
                })?;

            let pending_id = self.pending.insert(
                agent_request,
                level,
                PendingReason::RuleRequiresApproval { rule_id: rule_id.clone() },
                agent_id_str,
            );

            self.log_pending(&pending_id);
            return Ok(ProcessResult::PendingApproval(pending_id));
        }

        // 6. Verify capability
        step = ProxyStep::CapabilityVerified;
        let cap_id = payload.capability.as_str();
        let cap = connector
            .capabilities()
            .into_iter()
            .find(|c| c.id.as_str() == cap_id);

        if let Some(cap) = cap {
            if cap.level != level {
                let err_msg = format!(
                    "capability {} expects {:?}, got {:?}",
                    cap_id, cap.level, level
                );
                self.log_denied(&payload, step, &err_msg);
                return Err(ProxyError::CapabilityLevelMismatch {
                    capability: cap_id.to_string(),
                    expected: cap.level,
                    actual: level,
                });
            }
        }

        // 7. Verify signatures and execute based on level
        step = ProxyStep::SignaturesVerified;
        match level {
            ActionLevel::Read | ActionLevel::Write => {
                let request = self
                    .verifier
                    .verify_agent_approved(payload, signatures)
                    .map_err(|e| {
                        self.log_denied_by_id(&action_id, step, &e.to_string());
                        ProxyError::Verification(e)
                    })?;

                // 8. Sanitize
                step = ProxyStep::Sanitized;
                let safe_action = connector.sanitize(request.payload()).map_err(|e| {
                    self.log_denied_by_id(&action_id, step, &e.to_string());
                    ProxyError::Connector(e)
                })?;

                // 9. Execute
                step = ProxyStep::Executed;
                let result = connector.execute(&safe_action).map_err(|e| {
                    self.log_error(&action_id, step, &e.to_string());
                    ProxyError::Connector(e)
                })?;

                self.log_approved(&action_id, level, step);
                Ok(ProcessResult::Executed(result))
            }
            ActionLevel::Destructive => {
                // Check if we have all 3 signatures
                let full_result = self.verifier.verify_fully_approved(
                    payload.clone(),
                    signatures,
                );

                match full_result {
                    Ok(request) => {
                        // All 3 signatures present — execute immediately
                        step = ProxyStep::Sanitized;
                        let safe_action =
                            connector.sanitize(request.payload()).map_err(|e| {
                                self.log_denied_by_id(&action_id, step, &e.to_string());
                                ProxyError::Connector(e)
                            })?;

                        step = ProxyStep::Executed;
                        let result = connector.execute(&safe_action).map_err(|e| {
                            self.log_error(&action_id, step, &e.to_string());
                            ProxyError::Connector(e)
                        })?;

                        self.log_approved(&action_id, level, step);
                        Ok(ProcessResult::Executed(result))
                    }
                    Err(_) => {
                        // Try with just agent signatures — put in pending
                        let agent_request = self
                            .verifier
                            .verify_agent_approved(payload, signatures)
                            .map_err(|e| {
                                self.log_denied_by_id(&action_id, step, &e.to_string());
                                ProxyError::Verification(e)
                            })?;

                        let pending_id = self.pending.insert(
                            agent_request,
                            level,
                            PendingReason::DestructiveAction,
                            agent_id_str,
                        );

                        self.log_pending(&pending_id);
                        Ok(ProcessResult::PendingApproval(pending_id))
                    }
                }
            }
        }
    }

    /// Complete a pending destructive action with the user's signature.
    pub fn approve_pending(
        &self,
        action_id: &str,
        user_signature: Signature,
    ) -> Result<ActionResult, ProxyError> {
        let pending = self
            .pending
            .remove(action_id)
            .ok_or_else(|| ProxyError::ActionNotFound(action_id.to_string()))?;

        if pending.expires_at < Utc::now() {
            return Err(ProxyError::ActionExpired(action_id.to_string()));
        }

        // Reconstruct signatures: agent sigs + user sig
        let mut all_sigs: Vec<Signature> = pending.request.signatures().iter().map(|s| (*s).clone()).collect();
        all_sigs.push(user_signature);

        let payload = pending.request.into_payload();

        // Verify all 3 signatures
        let fully_approved = self
            .verifier
            .verify_fully_approved(payload, &all_sigs)
            .map_err(ProxyError::Verification)?;

        // Get connector and execute
        let connector_id = fully_approved.payload().connector_id.as_str().to_string();
        let connector = self
            .connectors
            .get(&connector_id)
            .ok_or_else(|| ProxyError::UnknownConnector(connector_id))?;

        let safe_action = connector
            .sanitize(fully_approved.payload())
            .map_err(ProxyError::Connector)?;

        let result = connector
            .execute(&safe_action)
            .map_err(ProxyError::Connector)?;

        let aid = fully_approved.payload().id.clone();
        self.log_approved(&aid, ActionLevel::Destructive, ProxyStep::Executed);

        Ok(result)
    }

    // -- Audit logging helpers ------------------------------------------------

    fn log_denied(&self, payload: &ActionPayload, step: ProxyStep, reason: &str) {
        warn!(action_id = %payload.id, step = ?step, reason, "action denied");
        let entry = AuditEntry {
            sequence: 0,
            timestamp: Utc::now(),
            action_id: payload.id.clone(),
            connector_id: Some(payload.connector_id.as_str().to_string()),
            capability: Some(payload.capability.as_str().to_string()),
            classification: None,
            signers_present: vec![],
            rules_evaluated: vec![],
            step_reached: step,
            decision: Decision::Denied {
                reason: reason.to_string(),
            },
            result_summary: None,
            previous_hash: [0; 32],
            entry_hash: [0; 32],
        };
        let _ = self.audit.append(entry);
    }

    fn log_denied_by_id(&self, action_id: &ActionId, step: ProxyStep, reason: &str) {
        warn!(action_id = %action_id, step = ?step, reason, "action denied");
        let entry = AuditEntry {
            sequence: 0,
            timestamp: Utc::now(),
            action_id: action_id.clone(),
            connector_id: None,
            capability: None,
            classification: None,
            signers_present: vec![],
            rules_evaluated: vec![],
            step_reached: step,
            decision: Decision::Denied {
                reason: reason.to_string(),
            },
            result_summary: None,
            previous_hash: [0; 32],
            entry_hash: [0; 32],
        };
        let _ = self.audit.append(entry);
    }

    fn log_error(&self, action_id: &ActionId, step: ProxyStep, details: &str) {
        warn!(action_id = %action_id, step = ?step, details, "action error");
        let entry = AuditEntry {
            sequence: 0,
            timestamp: Utc::now(),
            action_id: action_id.clone(),
            connector_id: None,
            capability: None,
            classification: None,
            signers_present: vec![],
            rules_evaluated: vec![],
            step_reached: step,
            decision: Decision::Error {
                details: details.to_string(),
            },
            result_summary: None,
            previous_hash: [0; 32],
            entry_hash: [0; 32],
        };
        let _ = self.audit.append(entry);
    }

    fn log_approved(&self, action_id: &ActionId, level: ActionLevel, step: ProxyStep) {
        info!(action_id = %action_id, level = %level, "action approved");
        let entry = AuditEntry {
            sequence: 0,
            timestamp: Utc::now(),
            action_id: action_id.clone(),
            connector_id: None,
            capability: None,
            classification: Some(level),
            signers_present: vec![],
            rules_evaluated: vec![],
            step_reached: step,
            decision: Decision::Approved,
            result_summary: None,
            previous_hash: [0; 32],
            entry_hash: [0; 32],
        };
        let _ = self.audit.append(entry);
    }

    fn log_pending(&self, action_id: &ActionId) {
        info!(action_id = %action_id, "action pending user approval");
        let entry = AuditEntry {
            sequence: 0,
            timestamp: Utc::now(),
            action_id: action_id.clone(),
            connector_id: None,
            capability: None,
            classification: Some(ActionLevel::Destructive),
            signers_present: vec![],
            rules_evaluated: vec![],
            step_reached: ProxyStep::SignaturesVerified,
            decision: Decision::PendingUserApproval,
            result_summary: None,
            previous_hash: [0; 32],
            entry_hash: [0; 32],
        };
        let _ = self.audit.append(entry);
    }
}

/// The result of processing a request.
pub enum ProcessResult {
    /// Action was executed and completed.
    Executed(ActionResult),
    /// Action requires user approval (destructive with only agent signatures).
    PendingApproval(ActionId),
}
