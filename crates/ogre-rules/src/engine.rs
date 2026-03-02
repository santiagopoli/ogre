use crate::rule::{Rule, RuleEffect};
use crate::RulesError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ogre_core::ActionContext;
use ogre_core::ActionLevel;
use ogre_core::ActionPayload;

/// The decision made by the rules engine after evaluating all rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleDecision {
    /// The action is explicitly allowed.
    Allow,
    /// The action requires human approval before execution.
    RequireApproval { rule_id: String },
}

/// The rules engine. Evaluates rules against action payloads.
/// Default-deny: if no rule explicitly allows an action, it is rejected.
pub struct RulesEngine {
    rules: Vec<Rule>,
    user_public_key: Option<VerifyingKey>,
}

impl RulesEngine {
    pub fn new(user_public_key: Option<VerifyingKey>) -> Self {
        Self {
            rules: Vec::new(),
            user_public_key,
        }
    }

    /// Add a rule to the engine. Verifies the signature if a user key is configured.
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), RulesError> {
        if let Some(ref key) = self.user_public_key {
            self.verify_rule_signature(&rule, key)?;
        }
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    /// Evaluate rules against a payload (before classification).
    /// Returns Ok(()) if the action is allowed, Err if denied or no rule allows it.
    pub fn evaluate(&self, payload: &ActionPayload) -> Result<(), RulesError> {
        self.evaluate_with_level(payload, None)
    }

    /// Evaluate rules with a known action level (after classification).
    pub fn evaluate_with_level(
        &self,
        payload: &ActionPayload,
        level: Option<ActionLevel>,
    ) -> Result<(), RulesError> {
        for rule in &self.rules {
            if rule.condition.evaluate_with_level(payload, level) {
                match rule.effect {
                    RuleEffect::Allow | RuleEffect::RequireApproval => return Ok(()),
                    RuleEffect::Deny => {
                        return Err(RulesError::Denied {
                            rule_id: rule.id.to_string(),
                            reason: rule.description.clone(),
                        });
                    }
                }
            }
        }

        // Default deny: no rule matched with Allow
        Err(RulesError::DefaultDeny)
    }

    /// Evaluate rules with full context (action level + extracted tables).
    /// Returns a RuleDecision indicating whether the action is allowed or requires approval.
    pub fn evaluate_with_context(
        &self,
        payload: &ActionPayload,
        context: &ActionContext,
    ) -> Result<RuleDecision, RulesError> {
        for rule in &self.rules {
            if rule.condition.evaluate_with_context(payload, context) {
                match rule.effect {
                    RuleEffect::Allow => return Ok(RuleDecision::Allow),
                    RuleEffect::Deny => {
                        return Err(RulesError::Denied {
                            rule_id: rule.id.to_string(),
                            reason: rule.description.clone(),
                        });
                    }
                    RuleEffect::RequireApproval => {
                        return Ok(RuleDecision::RequireApproval {
                            rule_id: rule.id.to_string(),
                        });
                    }
                }
            }
        }

        // Default deny: no rule matched
        Err(RulesError::DefaultDeny)
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    fn verify_rule_signature(
        &self,
        rule: &Rule,
        key: &VerifyingKey,
    ) -> Result<(), RulesError> {
        let sig_hex = rule.signature.as_ref().ok_or_else(|| RulesError::InvalidSignature {
            rule_id: rule.id.to_string(),
            reason: "missing signature".into(),
        })?;

        let sig_bytes = hex_decode(sig_hex).map_err(|e| RulesError::InvalidSignature {
            rule_id: rule.id.to_string(),
            reason: format!("invalid hex: {e}"),
        })?;

        let sig_arr: [u8; 64] =
            sig_bytes
                .try_into()
                .map_err(|_| RulesError::InvalidSignature {
                    rule_id: rule.id.to_string(),
                    reason: "invalid signature length".into(),
                })?;

        let signature = Signature::from_bytes(&sig_arr);
        let canonical = rule.canonical_bytes();

        key.verify(&canonical, &signature)
            .map_err(|e: ed25519_dalek::SignatureError| RulesError::InvalidSignature {
                rule_id: rule.id.to_string(),
                reason: e.to_string(),
            })
    }
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
