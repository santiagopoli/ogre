use chrono::Utc;
use ogre_audit::FileAuditLog;
use ogre_connector_sqlite::SqliteConnector;
use ogre_core::ids::{ActionId, AgentId, CapabilityId, ConnectorId};
use ogre_core::ActionPayload;
use ogre_crypto::keys::{KeyBundle, PublicKeySet};
use ogre_crypto::signature::SignerRole;
use ogre_crypto::signed_request::SignedRequest;
use ogre_proxy::{ProcessResult, Proxy, ProxyConfig, ProxyError};
use ogre_rules::{Condition, Rule, RuleEffect, RulesEngine};
use std::sync::Arc;
use tempfile::tempdir;

fn setup() -> (Proxy, KeyBundle) {
    let dir = tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    // Keep dir alive by leaking it (test only)
    let _dir = Box::leak(Box::new(dir));

    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);

    let audit = Arc::new(FileAuditLog::open(&audit_path).unwrap());

    // No signature verification on rules for tests (pass None for user key)
    let mut rules = RulesEngine::new(None);

    // Default allow-all rule for sqlite read/write
    let allow_rule = Rule {
        id: ogre_core::ids::RuleId::new("allow-all"),
        version: 1,
        description: "Allow all actions".to_string(),
        condition: Condition::Always,
        effect: RuleEffect::Allow,
        priority: 0,
        created_at: Utc::now(),
        signature: None,
    };
    rules.add_rule(allow_rule).unwrap();

    let connector = SqliteConnector::in_memory().unwrap();

    // Create a test table
    {
        let action = ActionPayload {
            id: ActionId::generate(),
            nonce: rand::random(),
            timestamp: Utc::now(),
            capability: CapabilityId::new("query_write"),
            connector_id: ConnectorId::new("sqlite"),
            parameters: serde_json::json!({
                "query": "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
            }),
            agent_id: AgentId::new("test-agent"),
        };
        let request = SignedRequest::new(action)
            .sign_ogre(&bundle.ogre)
            .sign_reviewer(&bundle.reviewer);

        let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
        let mut proxy = Proxy::new(keys, rules, audit, ProxyConfig::default());
        proxy.register_agent("test-agent");
        proxy.register_connector(Arc::new(connector));

        let result = proxy.process(request.into_payload(), &sigs);
        assert!(matches!(result, Ok(ProcessResult::Executed(_))));

        (proxy, bundle)
    }
}

fn make_payload(capability: &str, query: &str) -> ActionPayload {
    ActionPayload {
        id: ActionId::generate(),
        nonce: rand::random(),
        timestamp: Utc::now(),
        capability: CapabilityId::new(capability),
        connector_id: ConnectorId::new("sqlite"),
        parameters: serde_json::json!({ "query": query }),
        agent_id: AgentId::new("test-agent"),
    }
}

// =============================================================================
// Happy path tests
// =============================================================================

#[test]
fn read_query_with_agent_signatures() {
    let (proxy, bundle) = setup();

    let payload = make_payload("query_read", "SELECT * FROM users");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(matches!(result, Ok(ProcessResult::Executed(_))));
}

#[test]
fn write_query_with_agent_signatures() {
    let (proxy, bundle) = setup();

    let payload = make_payload(
        "query_write",
        "INSERT INTO users (name, email) VALUES ('alice', 'alice@test.com')",
    );
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(matches!(result, Ok(ProcessResult::Executed(_))));
}

#[test]
fn destructive_with_all_three_signatures() {
    let (proxy, bundle) = setup();

    let payload = make_payload("query_destructive", "DELETE FROM users WHERE id = 1");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer)
        .sign_user(&bundle.user);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(matches!(result, Ok(ProcessResult::Executed(_))));
}

#[test]
fn destructive_with_only_agent_sigs_goes_pending() {
    let (proxy, bundle) = setup();

    let payload = make_payload("query_destructive", "DELETE FROM users WHERE id = 1");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(matches!(result, Ok(ProcessResult::PendingApproval(_))));
}

#[test]
fn approve_pending_destructive_action() {
    let (proxy, bundle) = setup();

    // Submit destructive with only agent sigs
    let payload = make_payload("query_destructive", "DELETE FROM users WHERE id = 999");
    let request = SignedRequest::new(payload.clone())
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let payload_for_signing = request.payload().clone();
    let result = proxy.process(request.into_payload(), &sigs).unwrap();

    let action_id = match result {
        ProcessResult::PendingApproval(id) => id,
        _ => panic!("expected pending"),
    };

    // User signs and approves
    use ed25519_dalek::Signer;
    let canonical = payload_for_signing.canonical_bytes();
    let user_sig = bundle.user.signing_key().sign(&canonical);
    let user_signature = ogre_crypto::signature::Signature {
        signer: SignerRole::User,
        bytes: user_sig,
    };

    let result = proxy.approve_pending(action_id.as_str(), user_signature);
    assert!(result.is_ok());
}

// =============================================================================
// Security tests — these must ALL fail
// =============================================================================

#[test]
fn reject_read_with_no_signatures() {
    let (proxy, _bundle) = setup();

    let payload = make_payload("query_read", "SELECT 1");
    let result = proxy.process(payload, &[]);

    assert!(result.is_err());
}

#[test]
fn reject_read_with_only_ogre_signature() {
    let (proxy, bundle) = setup();

    let payload = make_payload("query_read", "SELECT 1");
    let request = SignedRequest::new(payload).sign_ogre(&bundle.ogre);

    let sigs = vec![request.ogre_signature().clone()];
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(result.is_err());
}

#[test]
fn destructive_with_wrong_user_key_goes_pending_not_executed() {
    let (proxy, bundle) = setup();
    let other_bundle = KeyBundle::generate();

    let payload = make_payload("query_destructive", "DROP TABLE users");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer)
        .sign_user(&other_bundle.user); // wrong user key!

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    // Wrong user sig means fully_approved fails, but agent sigs are valid,
    // so it goes to pending — NOT executed. The bad user sig is discarded.
    assert!(matches!(result, Ok(ProcessResult::PendingApproval(_))));
}

#[test]
fn reject_replay_same_nonce() {
    let (proxy, bundle) = setup();

    let payload = make_payload("query_read", "SELECT 1");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let payload1 = request.payload().clone();
    let payload2 = request.into_payload();

    // First request succeeds
    let result1 = proxy.process(payload1, &sigs);
    assert!(matches!(result1, Ok(ProcessResult::Executed(_))));

    // Same nonce = replay = rejected
    let result2 = proxy.process(payload2, &sigs);
    assert!(result2.is_err());
}

#[test]
fn reject_expired_request() {
    let (proxy, bundle) = setup();

    let mut payload = make_payload("query_read", "SELECT 1");
    // Set timestamp to 10 minutes ago (outside 5-minute tolerance)
    payload.timestamp = Utc::now() - chrono::Duration::minutes(10);

    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(result.is_err());
}

// =============================================================================
// Rules tests
// =============================================================================

#[test]
fn deny_rule_blocks_before_execution() {
    let dir = tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let _dir = Box::leak(Box::new(dir));

    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let audit = Arc::new(FileAuditLog::open(&audit_path).unwrap());

    let mut rules = RulesEngine::new(None);

    // High-priority deny for anything with .env in the query
    let deny_env = Rule {
        id: ogre_core::ids::RuleId::new("deny-env"),
        version: 1,
        description: "Block access to env files".to_string(),
        condition: Condition::ParameterMatches {
            path: "$.query".into(),
            pattern: ".*\\.env.*".into(),
        },
        effect: RuleEffect::Deny,
        priority: 100,
        created_at: Utc::now(),
        signature: None,
    };
    // Low-priority allow-all
    let allow = Rule {
        id: ogre_core::ids::RuleId::new("allow-all"),
        version: 1,
        description: "Allow all".to_string(),
        condition: Condition::Always,
        effect: RuleEffect::Allow,
        priority: 0,
        created_at: Utc::now(),
        signature: None,
    };
    rules.add_rule(deny_env).unwrap();
    rules.add_rule(allow).unwrap();

    let connector = SqliteConnector::in_memory().unwrap();
    let mut proxy = Proxy::new(keys, rules, audit, ProxyConfig::default());
    proxy.register_agent("test-agent");
    proxy.register_connector(Arc::new(connector));

    // Normal query should work
    let payload = make_payload("query_read", "SELECT * FROM sqlite_master");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);
    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    assert!(proxy.process(request.into_payload(), &sigs).is_ok());

    // Query mentioning .env should be blocked
    let payload = make_payload("query_read", "SELECT * FROM .env.production");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);
    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    assert!(proxy.process(request.into_payload(), &sigs).is_err());
}

#[test]
fn default_deny_blocks_without_allow_rule() {
    let dir = tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let _dir = Box::leak(Box::new(dir));

    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let audit = Arc::new(FileAuditLog::open(&audit_path).unwrap());

    // No rules at all = default deny
    let rules = RulesEngine::new(None);

    let connector = SqliteConnector::in_memory().unwrap();
    let mut proxy = Proxy::new(keys, rules, audit, ProxyConfig::default());
    proxy.register_agent("test-agent");
    proxy.register_connector(Arc::new(connector));

    let payload = make_payload("query_read", "SELECT 1");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);
    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();

    let result = proxy.process(request.into_payload(), &sigs);
    assert!(result.is_err(), "should be denied by default-deny");
}

// =============================================================================
// RBAC integration tests
// =============================================================================

fn make_payload_for_agent(capability: &str, query: &str, agent: &str) -> ActionPayload {
    ActionPayload {
        id: ActionId::generate(),
        nonce: rand::random(),
        timestamp: Utc::now(),
        capability: CapabilityId::new(capability),
        connector_id: ConnectorId::new("sqlite"),
        parameters: serde_json::json!({ "query": query }),
        agent_id: AgentId::new(agent),
    }
}

#[test]
fn unknown_agent_rejected() {
    let (proxy, bundle) = setup();

    let payload = make_payload_for_agent("query_read", "SELECT 1", "unknown-agent");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(
        matches!(result, Err(ProxyError::UnknownAgent(ref agent)) if agent == "unknown-agent"),
        "expected UnknownAgent error"
    );
}

#[test]
fn require_approval_rule_sends_read_to_pending() {
    let dir = tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let _dir = Box::leak(Box::new(dir));

    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let audit = Arc::new(FileAuditLog::open(&audit_path).unwrap());

    let mut rules = RulesEngine::new(None);

    // High-priority RequireApproval for queries on users table
    let require_approval = Rule {
        id: ogre_core::ids::RuleId::new("approve-users"),
        version: 1,
        description: "Require approval for users table".to_string(),
        condition: Condition::ParameterMatches {
            path: "$.query".into(),
            pattern: "(?i).*users.*".into(),
        },
        effect: RuleEffect::RequireApproval,
        priority: 100,
        created_at: Utc::now(),
        signature: None,
    };
    // Low-priority allow-all
    let allow = Rule {
        id: ogre_core::ids::RuleId::new("allow-all"),
        version: 1,
        description: "Allow all".to_string(),
        condition: Condition::Always,
        effect: RuleEffect::Allow,
        priority: 0,
        created_at: Utc::now(),
        signature: None,
    };
    rules.add_rule(require_approval).unwrap();
    rules.add_rule(allow).unwrap();

    let connector = SqliteConnector::in_memory().unwrap();
    let mut proxy = Proxy::new(keys, rules, audit, ProxyConfig::default());
    proxy.register_agent("test-agent");
    proxy.register_connector(Arc::new(connector));

    // Read query on users table → should go to pending (RequireApproval)
    let payload = make_payload("query_read", "SELECT * FROM users");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let result = proxy.process(request.into_payload(), &sigs);

    assert!(
        matches!(result, Ok(ProcessResult::PendingApproval(_))),
        "expected PendingApproval from RequireApproval rule"
    );
}

#[test]
fn approve_pending_require_approval_action() {
    let dir = tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let _dir = Box::leak(Box::new(dir));

    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let audit = Arc::new(FileAuditLog::open(&audit_path).unwrap());

    let mut rules = RulesEngine::new(None);

    // RequireApproval for all queries (catches everything)
    let require_approval = Rule {
        id: ogre_core::ids::RuleId::new("approve-all"),
        version: 1,
        description: "Require approval for everything".to_string(),
        condition: Condition::Always,
        effect: RuleEffect::RequireApproval,
        priority: 0,
        created_at: Utc::now(),
        signature: None,
    };
    rules.add_rule(require_approval).unwrap();

    let connector = SqliteConnector::in_memory().unwrap();
    let mut proxy = Proxy::new(keys, rules, audit, ProxyConfig::default());
    proxy.register_agent("test-agent");
    proxy.register_connector(Arc::new(connector));

    // Submit a read query — goes to pending because RequireApproval
    let payload = make_payload("query_read", "SELECT 1");
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let payload_for_signing = request.payload().clone();
    let result = proxy.process(request.into_payload(), &sigs).unwrap();

    let action_id = match result {
        ProcessResult::PendingApproval(id) => id,
        _ => panic!("expected PendingApproval"),
    };

    // User signs and approves the pending action
    use ed25519_dalek::Signer;
    let canonical = payload_for_signing.canonical_bytes();
    let user_sig = bundle.user.signing_key().sign(&canonical);
    let user_signature = ogre_crypto::signature::Signature {
        signer: SignerRole::User,
        bytes: user_sig,
    };

    let result = proxy.approve_pending(action_id.as_str(), user_signature);
    assert!(result.is_ok(), "expected approval to succeed");
}
