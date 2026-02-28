use ogre_api::{create_router, AppState};
use ogre_audit::FileAuditLog;
use ogre_connector_sqlite::SqliteConnector;
use ogre_crypto::keys::{KeyBundle, PublicKeySet};
use ogre_rules::{Condition, Rule, RuleEffect, RulesEngine};
use ogre_proxy::{Proxy, ProxyConfig};
use std::sync::{Arc, RwLock};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("ogre=info".parse().unwrap()))
        .init();

    tracing::info!("OGRE API starting up");

    // Bootstrap: generate keypairs
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);

    tracing::info!("Generated keypairs");
    tracing::info!("  Ogre public key:     {}", hex(&bundle.ogre.verifying_key().to_bytes()));
    tracing::info!("  Reviewer public key: {}", hex(&bundle.reviewer.verifying_key().to_bytes()));
    tracing::info!("  User public key:     {}", hex(&bundle.user.verifying_key().to_bytes()));

    // Audit log
    let audit = Arc::new(FileAuditLog::open("ogre-audit.jsonl").expect("failed to open audit log"));

    // Rules engine (default-deny, with a bootstrap allow-all for SQLite reads)
    let mut rules = RulesEngine::new(None);
    let allow_sqlite = Rule {
        id: ogre_core::ids::RuleId::new("bootstrap-allow-sqlite"),
        version: 1,
        description: "Bootstrap: allow all SQLite operations".to_string(),
        condition: Condition::ConnectorIs {
            connector_id: "sqlite".into(),
        },
        effect: RuleEffect::Allow,
        priority: 0,
        created_at: chrono::Utc::now(),
        signature: None,
    };
    rules.add_rule(allow_sqlite).expect("failed to add bootstrap rule");

    // Proxy
    let mut proxy = Proxy::new(keys, rules, audit.clone(), ProxyConfig::default());

    // SQLite connector
    let connector = SqliteConnector::new("ogre.db", 30).expect("failed to create SQLite connector");
    proxy.register_connector(Arc::new(connector));

    tracing::info!("Proxy initialized with SQLite connector");

    let state = AppState {
        proxy: Arc::new(RwLock::new(proxy)),
        audit,
    };

    let app = create_router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
