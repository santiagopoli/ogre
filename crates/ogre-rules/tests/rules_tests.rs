use chrono::Utc;
use ed25519_dalek::Signer;
use ogre_core::ids::{ActionId, AgentId, CapabilityId, ConnectorId, RuleId};
use ogre_core::{ActionContext, ActionLevel, ActionPayload};
use ogre_rules::{Condition, Rule, RuleDecision, RuleEffect, RulesEngine, RulesError};

fn test_payload(connector: &str, capability: &str, params: serde_json::Value) -> ActionPayload {
    ActionPayload {
        id: ActionId::generate(),
        nonce: rand::random(),
        timestamp: Utc::now(),
        capability: CapabilityId::new(capability),
        connector_id: ConnectorId::new(connector),
        parameters: params,
        agent_id: AgentId::new("test-agent"),
    }
}

fn unsigned_rule(id: &str, condition: Condition, effect: RuleEffect, priority: i32) -> Rule {
    Rule {
        id: RuleId::new(id),
        version: 1,
        description: format!("Test rule {id}"),
        condition,
        effect,
        priority,
        created_at: Utc::now(),
        signature: None,
    }
}

fn sign_rule(mut rule: Rule, key: &ed25519_dalek::SigningKey) -> Rule {
    let canonical = rule.canonical_bytes();
    let sig = key.sign(&canonical);
    let hex: String = sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    rule.signature = Some(hex);
    rule
}

#[test]
fn default_deny_with_no_rules() {
    let engine = RulesEngine::new(None);
    let payload = test_payload("sqlite", "query_read", serde_json::json!({"query": "SELECT 1"}));
    let result = engine.evaluate(&payload);
    assert!(matches!(result, Err(RulesError::DefaultDeny)));
}

#[test]
fn allow_rule_permits_action() {
    let mut engine = RulesEngine::new(None);
    let rule = unsigned_rule("r1", Condition::Always, RuleEffect::Allow, 0);
    engine.add_rule(rule).unwrap();

    let payload = test_payload("sqlite", "query_read", serde_json::json!({"query": "SELECT 1"}));
    assert!(engine.evaluate(&payload).is_ok());
}

#[test]
fn deny_rule_blocks_action() {
    let mut engine = RulesEngine::new(None);
    // Allow everything first
    let allow = unsigned_rule("r-allow", Condition::Always, RuleEffect::Allow, 0);
    // But deny sqlite with higher priority
    let deny = unsigned_rule(
        "r-deny",
        Condition::ConnectorIs {
            connector_id: "sqlite".into(),
        },
        RuleEffect::Deny,
        100,
    );
    engine.add_rule(allow).unwrap();
    engine.add_rule(deny).unwrap();

    let payload = test_payload("sqlite", "query_read", serde_json::json!({}));
    assert!(matches!(
        engine.evaluate(&payload),
        Err(RulesError::Denied { .. })
    ));
}

#[test]
fn priority_ordering() {
    let mut engine = RulesEngine::new(None);

    // Low-priority allow for everything
    let allow = unsigned_rule("r-allow", Condition::Always, RuleEffect::Allow, 1);
    // High-priority deny for sqlite
    let deny = unsigned_rule(
        "r-deny",
        Condition::ConnectorIs {
            connector_id: "sqlite".into(),
        },
        RuleEffect::Deny,
        100,
    );

    engine.add_rule(allow).unwrap();
    engine.add_rule(deny).unwrap();

    // sqlite should be denied (high-priority deny matches first)
    let sqlite_payload = test_payload("sqlite", "query_read", serde_json::json!({}));
    assert!(engine.evaluate(&sqlite_payload).is_err());

    // postgres should be allowed (deny doesn't match, allow does)
    let pg_payload = test_payload("postgres", "query_read", serde_json::json!({}));
    assert!(engine.evaluate(&pg_payload).is_ok());
}

#[test]
fn parameter_matches_condition() {
    let mut engine = RulesEngine::new(None);

    // Deny queries containing ".env"
    let deny = unsigned_rule(
        "r-deny-env",
        Condition::ParameterMatches {
            path: "$.query".into(),
            pattern: ".*\\.env.*".into(),
        },
        RuleEffect::Deny,
        100,
    );
    let allow = unsigned_rule("r-allow", Condition::Always, RuleEffect::Allow, 0);
    engine.add_rule(deny).unwrap();
    engine.add_rule(allow).unwrap();

    let safe = test_payload(
        "sqlite",
        "query_read",
        serde_json::json!({"query": "SELECT * FROM users"}),
    );
    assert!(engine.evaluate(&safe).is_ok());

    let dangerous = test_payload(
        "sqlite",
        "query_read",
        serde_json::json!({"query": "SELECT * FROM .env.production"}),
    );
    assert!(engine.evaluate(&dangerous).is_err());
}

#[test]
fn and_or_not_conditions() {
    let mut engine = RulesEngine::new(None);

    // Allow only: connector=sqlite AND capability=query_read
    let allow = unsigned_rule(
        "r-allow-sqlite-read",
        Condition::And {
            conditions: vec![
                Condition::ConnectorIs {
                    connector_id: "sqlite".into(),
                },
                Condition::CapabilityIs {
                    capability_id: "query_read".into(),
                },
            ],
        },
        RuleEffect::Allow,
        0,
    );
    engine.add_rule(allow).unwrap();

    // sqlite + query_read -> allowed
    let ok = test_payload("sqlite", "query_read", serde_json::json!({}));
    assert!(engine.evaluate(&ok).is_ok());

    // sqlite + delete_data -> denied (default deny)
    let nope = test_payload("sqlite", "delete_data", serde_json::json!({}));
    assert!(engine.evaluate(&nope).is_err());

    // postgres + query_read -> denied (default deny)
    let nope2 = test_payload("postgres", "query_read", serde_json::json!({}));
    assert!(engine.evaluate(&nope2).is_err());
}

#[test]
fn signed_rule_verification() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut engine = RulesEngine::new(Some(verifying_key));

    let rule = unsigned_rule("r1", Condition::Always, RuleEffect::Allow, 0);
    let signed = sign_rule(rule, &signing_key);

    assert!(engine.add_rule(signed).is_ok());
}

#[test]
fn tampered_rule_rejected() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut engine = RulesEngine::new(Some(verifying_key));

    let rule = unsigned_rule("r1", Condition::Always, RuleEffect::Allow, 0);
    let mut signed = sign_rule(rule, &signing_key);

    // Tamper with the rule after signing
    signed.description = "TAMPERED".into();

    assert!(matches!(
        engine.add_rule(signed),
        Err(RulesError::InvalidSignature { .. })
    ));
}

#[test]
fn unsigned_rule_rejected_when_key_configured() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut engine = RulesEngine::new(Some(verifying_key));

    let rule = unsigned_rule("r1", Condition::Always, RuleEffect::Allow, 0);
    // Don't sign it

    assert!(matches!(
        engine.add_rule(rule),
        Err(RulesError::InvalidSignature { .. })
    ));
}

#[test]
fn wrong_key_rejected() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let other_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = other_key.verifying_key(); // different key!

    let mut engine = RulesEngine::new(Some(verifying_key));

    let rule = unsigned_rule("r1", Condition::Always, RuleEffect::Allow, 0);
    let signed = sign_rule(rule, &signing_key); // signed with wrong key

    assert!(matches!(
        engine.add_rule(signed),
        Err(RulesError::InvalidSignature { .. })
    ));
}

// =============================================================================
// RBAC condition tests — AgentIs, TableIs, RequireApproval, combined
// =============================================================================

fn test_payload_with_agent(
    connector: &str,
    capability: &str,
    params: serde_json::Value,
    agent: &str,
) -> ActionPayload {
    ActionPayload {
        id: ActionId::generate(),
        nonce: rand::random(),
        timestamp: Utc::now(),
        capability: CapabilityId::new(capability),
        connector_id: ConnectorId::new(connector),
        parameters: params,
        agent_id: AgentId::new(agent),
    }
}

#[test]
fn agent_is_matches_correct_agent() {
    let mut engine = RulesEngine::new(None);
    let rule = unsigned_rule(
        "allow-alice",
        Condition::AgentIs {
            agent_id: "alice".into(),
        },
        RuleEffect::Allow,
        0,
    );
    engine.add_rule(rule).unwrap();

    let alice = test_payload_with_agent("sqlite", "query_read", serde_json::json!({}), "alice");
    assert!(engine.evaluate(&alice).is_ok());
}

#[test]
fn agent_is_rejects_wrong_agent() {
    let mut engine = RulesEngine::new(None);
    let rule = unsigned_rule(
        "allow-alice",
        Condition::AgentIs {
            agent_id: "alice".into(),
        },
        RuleEffect::Allow,
        0,
    );
    engine.add_rule(rule).unwrap();

    let bob = test_payload_with_agent("sqlite", "query_read", serde_json::json!({}), "bob");
    assert!(matches!(engine.evaluate(&bob), Err(RulesError::DefaultDeny)));
}

#[test]
fn table_is_matches_context_tables() {
    let mut engine = RulesEngine::new(None);
    let rule = unsigned_rule(
        "allow-users-table",
        Condition::TableIs {
            table_name: "users".into(),
        },
        RuleEffect::Allow,
        0,
    );
    engine.add_rule(rule).unwrap();

    let payload = test_payload("sqlite", "query_read", serde_json::json!({}));
    let context = ActionContext {
        tables: vec!["users".to_string(), "orders".to_string()],
        level: Some(ActionLevel::Read),
    };

    let decision = engine.evaluate_with_context(&payload, &context).unwrap();
    assert_eq!(decision, RuleDecision::Allow);
}

#[test]
fn table_is_case_insensitive() {
    let mut engine = RulesEngine::new(None);
    let rule = unsigned_rule(
        "allow-users-table",
        Condition::TableIs {
            table_name: "USERS".into(),
        },
        RuleEffect::Allow,
        0,
    );
    engine.add_rule(rule).unwrap();

    let payload = test_payload("sqlite", "query_read", serde_json::json!({}));
    let context = ActionContext {
        tables: vec!["users".to_string()],
        level: Some(ActionLevel::Read),
    };

    let decision = engine.evaluate_with_context(&payload, &context).unwrap();
    assert_eq!(decision, RuleDecision::Allow);
}

#[test]
fn table_is_rejects_when_table_not_present() {
    let mut engine = RulesEngine::new(None);
    let rule = unsigned_rule(
        "allow-secrets",
        Condition::TableIs {
            table_name: "secrets".into(),
        },
        RuleEffect::Allow,
        0,
    );
    engine.add_rule(rule).unwrap();

    let payload = test_payload("sqlite", "query_read", serde_json::json!({}));
    let context = ActionContext {
        tables: vec!["users".to_string(), "orders".to_string()],
        level: Some(ActionLevel::Read),
    };

    let result = engine.evaluate_with_context(&payload, &context);
    assert!(matches!(result, Err(RulesError::DefaultDeny)));
}

#[test]
fn require_approval_returns_rule_decision() {
    let mut engine = RulesEngine::new(None);
    let rule = unsigned_rule(
        "approve-destructive",
        Condition::Always,
        RuleEffect::RequireApproval,
        0,
    );
    engine.add_rule(rule).unwrap();

    let payload = test_payload("sqlite", "query_destructive", serde_json::json!({}));
    let context = ActionContext {
        tables: vec!["users".to_string()],
        level: Some(ActionLevel::Destructive),
    };

    let decision = engine.evaluate_with_context(&payload, &context).unwrap();
    assert_eq!(
        decision,
        RuleDecision::RequireApproval {
            rule_id: "approve-destructive".to_string()
        }
    );
}

#[test]
fn combined_agent_table_level_condition() {
    let mut engine = RulesEngine::new(None);

    // RequireApproval when: agent=data-loader AND table=users AND level=destructive
    let combined = unsigned_rule(
        "approve-loader-destructive-users",
        Condition::And {
            conditions: vec![
                Condition::AgentIs {
                    agent_id: "data-loader".into(),
                },
                Condition::TableIs {
                    table_name: "users".into(),
                },
                Condition::ActionLevelIs {
                    level: ActionLevel::Destructive,
                },
            ],
        },
        RuleEffect::RequireApproval,
        10,
    );
    // Low-priority allow-all fallback
    let allow = unsigned_rule("allow-all", Condition::Always, RuleEffect::Allow, 0);
    engine.add_rule(combined).unwrap();
    engine.add_rule(allow).unwrap();

    // data-loader + users + destructive → RequireApproval
    let payload = test_payload_with_agent(
        "sqlite",
        "query_destructive",
        serde_json::json!({}),
        "data-loader",
    );
    let context = ActionContext {
        tables: vec!["users".to_string()],
        level: Some(ActionLevel::Destructive),
    };
    let decision = engine.evaluate_with_context(&payload, &context).unwrap();
    assert_eq!(
        decision,
        RuleDecision::RequireApproval {
            rule_id: "approve-loader-destructive-users".to_string()
        }
    );

    // data-loader + orders + destructive → Allow (table doesn't match, falls to allow-all)
    let context_orders = ActionContext {
        tables: vec!["orders".to_string()],
        level: Some(ActionLevel::Destructive),
    };
    let decision = engine
        .evaluate_with_context(&payload, &context_orders)
        .unwrap();
    assert_eq!(decision, RuleDecision::Allow);

    // different-agent + users + destructive → Allow (agent doesn't match)
    let other_agent = test_payload_with_agent(
        "sqlite",
        "query_destructive",
        serde_json::json!({}),
        "other-agent",
    );
    let decision = engine
        .evaluate_with_context(&other_agent, &context)
        .unwrap();
    assert_eq!(decision, RuleDecision::Allow);

    // data-loader + users + read → Allow (level doesn't match)
    let context_read = ActionContext {
        tables: vec!["users".to_string()],
        level: Some(ActionLevel::Read),
    };
    let decision = engine
        .evaluate_with_context(&payload, &context_read)
        .unwrap();
    assert_eq!(decision, RuleDecision::Allow);
}

#[test]
fn deny_overrides_require_approval() {
    let mut engine = RulesEngine::new(None);

    // High-priority deny for secrets table
    let deny = unsigned_rule(
        "deny-secrets",
        Condition::TableIs {
            table_name: "secrets".into(),
        },
        RuleEffect::Deny,
        100,
    );
    // Medium-priority require-approval for destructive
    let approve = unsigned_rule(
        "approve-destructive",
        Condition::ActionLevelIs {
            level: ActionLevel::Destructive,
        },
        RuleEffect::RequireApproval,
        50,
    );
    // Low-priority allow-all
    let allow = unsigned_rule("allow-all", Condition::Always, RuleEffect::Allow, 0);

    engine.add_rule(deny).unwrap();
    engine.add_rule(approve).unwrap();
    engine.add_rule(allow).unwrap();

    // Destructive on secrets → Denied (deny has higher priority)
    let payload = test_payload("sqlite", "query_destructive", serde_json::json!({}));
    let context = ActionContext {
        tables: vec!["secrets".to_string()],
        level: Some(ActionLevel::Destructive),
    };
    let result = engine.evaluate_with_context(&payload, &context);
    assert!(
        matches!(result, Err(RulesError::Denied { ref rule_id, .. }) if rule_id == "deny-secrets"),
        "expected deny-secrets, got: {result:?}"
    );

    // Destructive on users → RequireApproval (deny doesn't match, approve does)
    let context_users = ActionContext {
        tables: vec!["users".to_string()],
        level: Some(ActionLevel::Destructive),
    };
    let decision = engine
        .evaluate_with_context(&payload, &context_users)
        .unwrap();
    assert_eq!(
        decision,
        RuleDecision::RequireApproval {
            rule_id: "approve-destructive".to_string()
        }
    );

    // Read on users → Allow (neither deny nor approve match)
    let context_read = ActionContext {
        tables: vec!["users".to_string()],
        level: Some(ActionLevel::Read),
    };
    let decision = engine
        .evaluate_with_context(&payload, &context_read)
        .unwrap();
    assert_eq!(decision, RuleDecision::Allow);
}
