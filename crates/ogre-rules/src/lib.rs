mod condition;
mod engine;
mod rule;

pub use condition::Condition;
pub use engine::{RuleDecision, RulesEngine};
pub use rule::{Rule, RuleEffect};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("rule signature invalid for rule {rule_id}: {reason}")]
    InvalidSignature { rule_id: String, reason: String },

    #[error("rule parse error: {0}")]
    ParseError(String),

    #[error("condition evaluation error: {0}")]
    EvalError(String),

    #[error("no rule allows this action (default-deny)")]
    DefaultDeny,

    #[error("rule {rule_id} denies this action: {reason}")]
    Denied { rule_id: String, reason: String },
}
