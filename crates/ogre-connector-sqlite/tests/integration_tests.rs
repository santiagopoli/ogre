use std::time::Duration;

use chrono::Utc;
use ogre_connector_sqlite::SqliteConnector;
use ogre_core::ids::{ActionId, AgentId, CapabilityId, ConnectorId};
use ogre_core::{ActionLevel, ActionPayload, Connector, ConnectorError, Outcome};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn create_seeded_connector() -> SqliteConnector {
    let connector =
        SqliteConnector::in_memory().expect("Failed to create in-memory SQLite connector");

    let setup_statements = [
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, active INTEGER NOT NULL DEFAULT 1)",
        "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, price REAL NOT NULL)",
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), product_id INTEGER NOT NULL REFERENCES products(id), quantity INTEGER NOT NULL, created_at TEXT NOT NULL)",
        "INSERT INTO users (id, name, email, active) VALUES (1, 'Alice', 'alice@example.com', 1)",
        "INSERT INTO users (id, name, email, active) VALUES (2, 'Bob', 'bob@example.com', 1)",
        "INSERT INTO users (id, name, email, active) VALUES (3, 'Charlie', 'charlie@example.com', 0)",
        "INSERT INTO users (id, name, email, active) VALUES (4, 'Diana', 'diana@example.com', 1)",
        "INSERT INTO products (id, name, price) VALUES (1, 'Widget', 9.99)",
        "INSERT INTO products (id, name, price) VALUES (2, 'Gadget', 24.99)",
        "INSERT INTO products (id, name, price) VALUES (3, 'Doohickey', 4.50)",
        "INSERT INTO orders (id, user_id, product_id, quantity, created_at) VALUES (1, 1, 1, 2, '2024-01-15T10:30:00Z')",
        "INSERT INTO orders (id, user_id, product_id, quantity, created_at) VALUES (2, 1, 2, 1, '2024-01-16T14:00:00Z')",
        "INSERT INTO orders (id, user_id, product_id, quantity, created_at) VALUES (3, 2, 1, 5, '2024-02-01T09:00:00Z')",
        "INSERT INTO orders (id, user_id, product_id, quantity, created_at) VALUES (4, 2, 3, 3, '2024-02-10T16:45:00Z')",
        "INSERT INTO orders (id, user_id, product_id, quantity, created_at) VALUES (5, 3, 2, 1, '2024-03-01T11:00:00Z')",
        "INSERT INTO orders (id, user_id, product_id, quantity, created_at) VALUES (6, 4, 1, 10, '2024-03-05T08:30:00Z')",
        "INSERT INTO orders (id, user_id, product_id, quantity, created_at) VALUES (7, 4, 3, 2, '2024-03-10T13:15:00Z')",
    ];

    for sql in setup_statements {
        let payload = make_payload("query_write", sql);
        let safe = connector
            .sanitize(&payload)
            .unwrap_or_else(|e| panic!("Setup sanitize failed for '{sql}': {e}"));
        let result = connector
            .execute(&safe)
            .unwrap_or_else(|e| panic!("Setup execute failed for '{sql}': {e}"));
        assert!(
            result.outcome.is_success(),
            "Setup failed for '{sql}': {:?}",
            result.outcome
        );
    }

    connector
}

// ---------------------------------------------------------------------------
// Read operations
// ---------------------------------------------------------------------------

#[test]
fn test_read_select_with_where() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT name, email FROM users WHERE active = 1");

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    assert!(result.duration > Duration::ZERO);

    let data = result.data.unwrap();
    assert_eq!(data["row_count"], 3);

    let columns = data["columns"].as_array().unwrap();
    assert!(columns.contains(&serde_json::json!("name")));
    assert!(columns.contains(&serde_json::json!("email")));

    let rows = data["rows"].as_array().unwrap();
    let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"Alice"));
    assert!(names.contains(&"Bob"));
    assert!(names.contains(&"Diana"));
    assert!(!names.contains(&"Charlie"));
}

#[test]
fn test_read_select_with_join() {
    let connector = create_seeded_connector();
    let query = "\
        SELECT u.name, p.name AS product, o.quantity \
        FROM orders o \
        JOIN users u ON o.user_id = u.id \
        JOIN products p ON o.product_id = p.id \
        WHERE u.name = 'Alice'";
    let payload = make_payload("query_read", query);

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    let data = result.data.unwrap();
    assert_eq!(data["row_count"], 2);

    let rows = data["rows"].as_array().unwrap();
    for row in rows {
        assert_eq!(row["name"].as_str().unwrap(), "Alice");
    }
}

#[test]
fn test_read_select_with_subquery() {
    let connector = create_seeded_connector();
    let query =
        "SELECT name FROM users WHERE id IN (SELECT DISTINCT user_id FROM orders WHERE quantity > 2)";
    let payload = make_payload("query_read", query);

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    let data = result.data.unwrap();
    let rows = data["rows"].as_array().unwrap();
    let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    // quantity > 2: order 3 (Bob, qty 5), order 4 (Bob, qty 3), order 6 (Diana, qty 10), order 7 (Diana, qty 2 — not > 2)
    // So Bob and Diana
    assert!(names.contains(&"Bob"));
    assert!(names.contains(&"Diana"));
    assert_eq!(names.len(), 2);
}

#[test]
fn test_read_select_with_aggregation() {
    let connector = create_seeded_connector();
    let query = "\
        SELECT u.name, COUNT(o.id) AS order_count, SUM(o.quantity) AS total_qty \
        FROM users u \
        LEFT JOIN orders o ON u.id = o.user_id \
        GROUP BY u.id, u.name \
        ORDER BY u.id";
    let payload = make_payload("query_read", query);

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    let data = result.data.unwrap();
    assert_eq!(data["row_count"], 4);

    let rows = data["rows"].as_array().unwrap();
    // Alice: 2 orders, qty 2+1=3
    assert_eq!(rows[0]["name"], "Alice");
    assert_eq!(rows[0]["order_count"], 2);
    assert_eq!(rows[0]["total_qty"], 3);
    // Bob: 2 orders, qty 5+3=8
    assert_eq!(rows[1]["name"], "Bob");
    assert_eq!(rows[1]["order_count"], 2);
    assert_eq!(rows[1]["total_qty"], 8);
    // Charlie: 1 order, qty 1
    assert_eq!(rows[2]["name"], "Charlie");
    assert_eq!(rows[2]["order_count"], 1);
    assert_eq!(rows[2]["total_qty"], 1);
    // Diana: 2 orders, qty 10+2=12
    assert_eq!(rows[3]["name"], "Diana");
    assert_eq!(rows[3]["order_count"], 2);
    assert_eq!(rows[3]["total_qty"], 12);
}

#[test]
fn test_read_select_without_limit_gets_limit_added() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT * FROM users");

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    let safe = connector.sanitize(&payload).unwrap();
    let sanitized_query = safe.sanitized_parameters["query"].as_str().unwrap();
    let upper = sanitized_query.to_uppercase();
    assert!(
        upper.contains("LIMIT"),
        "Sanitized query should contain LIMIT: {sanitized_query}"
    );
    assert!(
        upper.contains("1000"),
        "Sanitized query should contain LIMIT 1000: {sanitized_query}"
    );

    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());
    // All 4 users still returned (4 < 1000)
    assert_eq!(result.data.unwrap()["row_count"], 4);
}

#[test]
fn test_read_select_with_existing_limit_preserved() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT * FROM users LIMIT 2");

    let safe = connector.sanitize(&payload).unwrap();
    let sanitized_query = safe.sanitized_parameters["query"].as_str().unwrap();
    let upper = sanitized_query.to_uppercase();
    assert!(
        !upper.contains("1000"),
        "Sanitized query should preserve original LIMIT, not add 1000: {sanitized_query}"
    );

    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());
    assert_eq!(result.data.unwrap()["row_count"], 2);
}

#[test]
fn test_read_explain() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "EXPLAIN SELECT * FROM users WHERE id = 1");

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    let data = result.data.unwrap();
    assert!(data["columns"].as_array().unwrap().len() > 0);
    assert!(data["rows"].as_array().unwrap().len() > 0);
}

#[test]
fn test_read_select_count() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT COUNT(*) AS cnt FROM orders");

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    let data = result.data.unwrap();
    assert_eq!(data["row_count"], 1);
    assert_eq!(data["rows"][0]["cnt"], 7);
}

// ---------------------------------------------------------------------------
// Write operations
// ---------------------------------------------------------------------------

#[test]
fn test_write_insert_single_row() {
    let connector = create_seeded_connector();
    let payload = make_payload(
        "query_write",
        "INSERT INTO users (name, email) VALUES ('Eve', 'eve@example.com')",
    );

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Write);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    assert_eq!(result.data.unwrap()["rows_affected"], 1);

    // Verify the row exists
    let verify = make_payload("query_read", "SELECT name FROM users WHERE email = 'eve@example.com'");
    let safe = connector.sanitize(&verify).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert_eq!(result.data.unwrap()["rows"][0]["name"], "Eve");
}

#[test]
fn test_write_insert_multiple_rows() {
    let connector = create_seeded_connector();

    let insert1 = make_payload(
        "query_write",
        "INSERT INTO products (name, price) VALUES ('Thingamajig', 15.00)",
    );
    let safe1 = connector.sanitize(&insert1).unwrap();
    let result1 = connector.execute(&safe1).unwrap();
    assert!(result1.outcome.is_success());
    assert_eq!(result1.data.unwrap()["rows_affected"], 1);

    let insert2 = make_payload(
        "query_write",
        "INSERT INTO products (name, price) VALUES ('Whatchamacallit', 7.25)",
    );
    let safe2 = connector.sanitize(&insert2).unwrap();
    let result2 = connector.execute(&safe2).unwrap();
    assert!(result2.outcome.is_success());
    assert_eq!(result2.data.unwrap()["rows_affected"], 1);

    // Verify total count
    let verify = make_payload("query_read", "SELECT COUNT(*) AS cnt FROM products");
    let safe = connector.sanitize(&verify).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert_eq!(result.data.unwrap()["rows"][0]["cnt"], 5);
}

#[test]
fn test_write_update_with_where() {
    let connector = create_seeded_connector();
    let payload = make_payload(
        "query_write",
        "UPDATE users SET active = 0 WHERE name = 'Bob'",
    );

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Write);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    assert_eq!(result.data.unwrap()["rows_affected"], 1);

    // Verify Bob is now inactive
    let verify = make_payload("query_read", "SELECT active FROM users WHERE name = 'Bob'");
    let safe = connector.sanitize(&verify).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert_eq!(result.data.unwrap()["rows"][0]["active"], 0);
}

#[test]
fn test_write_update_without_where() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_write", "UPDATE users SET active = 1");

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Write);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    assert_eq!(result.data.unwrap()["rows_affected"], 4);
}

#[test]
fn test_write_create_table() {
    let connector = create_seeded_connector();
    let payload = make_payload(
        "query_write",
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT NOT NULL, ts TEXT NOT NULL)",
    );

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Write);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());

    // Verify the table works
    let insert = make_payload(
        "query_write",
        "INSERT INTO audit_log (action, ts) VALUES ('test', '2024-01-01T00:00:00Z')",
    );
    let safe = connector.sanitize(&insert).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());
    assert_eq!(result.data.unwrap()["rows_affected"], 1);
}

#[test]
fn test_write_create_index() {
    let connector = create_seeded_connector();
    let payload = make_payload(
        "query_write",
        "CREATE INDEX idx_users_email ON users(email)",
    );

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Write);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());
}

// ---------------------------------------------------------------------------
// Destructive operations
// ---------------------------------------------------------------------------

#[test]
fn test_destructive_delete_with_where() {
    let connector = create_seeded_connector();
    let payload = make_payload(
        "query_destructive",
        "DELETE FROM orders WHERE user_id = 3",
    );

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Destructive);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    assert_eq!(result.data.unwrap()["rows_affected"], 1);

    // Verify Charlie's order is gone
    let verify = make_payload(
        "query_read",
        "SELECT COUNT(*) AS cnt FROM orders WHERE user_id = 3",
    );
    let safe = connector.sanitize(&verify).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert_eq!(result.data.unwrap()["rows"][0]["cnt"], 0);
}

#[test]
fn test_destructive_delete_without_where() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_destructive", "DELETE FROM orders");

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Destructive);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    assert_eq!(result.data.unwrap()["rows_affected"], 7);
}

#[test]
fn test_destructive_drop_table() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_destructive", "DROP TABLE orders");

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Destructive);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());

    // Verify: SELECT from dropped table should produce an error outcome
    let verify = make_payload("query_read", "SELECT * FROM orders");
    let safe = connector.sanitize(&verify).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert!(
        matches!(result.outcome, Outcome::Error { ref code, .. } if code == "SQLITE_ERROR"),
        "Expected SQLITE_ERROR after DROP TABLE, got: {:?}",
        result.outcome
    );
}

#[test]
fn test_destructive_alter_table() {
    let connector = create_seeded_connector();
    let payload = make_payload(
        "query_destructive",
        "ALTER TABLE users ADD COLUMN phone TEXT",
    );

    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Destructive);

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());

    // Verify the new column works
    let insert = make_payload(
        "query_write",
        "INSERT INTO users (name, email, phone) VALUES ('Frank', 'frank@example.com', '555-0100')",
    );
    let safe = connector.sanitize(&insert).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert!(result.outcome.is_success());

    let verify = make_payload(
        "query_read",
        "SELECT phone FROM users WHERE name = 'Frank'",
    );
    let safe = connector.sanitize(&verify).unwrap();
    let result = connector.execute(&safe).unwrap();
    assert_eq!(result.data.unwrap()["rows"][0]["phone"], "555-0100");
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn test_error_multi_statement_injection() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT 1; DROP TABLE users");

    let err = connector.classify(&payload).unwrap_err();
    assert!(
        matches!(err, ConnectorError::MultiStatement),
        "Expected MultiStatement, got: {err:?}"
    );

    let err = connector.sanitize(&payload).unwrap_err();
    assert!(
        matches!(err, ConnectorError::MultiStatement),
        "Expected MultiStatement from sanitize, got: {err:?}"
    );
}

#[test]
fn test_error_empty_query() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "");

    let err = connector.classify(&payload).unwrap_err();
    assert!(
        matches!(err, ConnectorError::ClassificationFailed(..)),
        "Expected ClassificationFailed for empty query, got: {err:?}"
    );
}

#[test]
fn test_error_invalid_sql_syntax() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELETC * FORM users");

    let err = connector.classify(&payload).unwrap_err();
    assert!(
        matches!(err, ConnectorError::ClassificationFailed(..)),
        "Expected ClassificationFailed for invalid SQL, got: {err:?}"
    );
}

#[test]
fn test_error_nonexistent_table() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT * FROM nonexistent_table");

    // Classification succeeds — SQL is syntactically valid
    let level = connector.classify(&payload).unwrap();
    assert_eq!(level, ActionLevel::Read);

    // Sanitize succeeds
    let safe = connector.sanitize(&payload).unwrap();

    // Execute returns an error outcome (not Err(ConnectorError))
    let result = connector.execute(&safe).unwrap();
    assert!(
        matches!(result.outcome, Outcome::Error { ref code, .. } if code == "SQLITE_ERROR"),
        "Expected SQLITE_ERROR for nonexistent table, got: {:?}",
        result.outcome
    );
}

#[test]
fn test_error_missing_query_parameter() {
    let connector = create_seeded_connector();
    let payload = ActionPayload {
        id: ActionId::generate(),
        nonce: rand::random(),
        timestamp: Utc::now(),
        capability: CapabilityId::new("query_read"),
        connector_id: ConnectorId::new("sqlite"),
        parameters: serde_json::json!({}),
        agent_id: AgentId::new("test-agent"),
    };

    let err = connector.classify(&payload).unwrap_err();
    assert!(
        matches!(err, ConnectorError::ClassificationFailed(ref msg) if msg.contains("query")),
        "Expected ClassificationFailed mentioning 'query', got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Pipeline verification
// ---------------------------------------------------------------------------

#[test]
fn test_pipeline_classify_matches_sanitize_classification() {
    let connector = create_seeded_connector();

    let cases = [
        ("query_read", "SELECT * FROM users", ActionLevel::Read),
        (
            "query_write",
            "INSERT INTO users (name, email) VALUES ('Test', 'test@example.com')",
            ActionLevel::Write,
        ),
        (
            "query_destructive",
            "DELETE FROM orders WHERE id = 1",
            ActionLevel::Destructive,
        ),
    ];

    for (capability, query, expected_level) in cases {
        let payload = make_payload(capability, query);
        let classified = connector.classify(&payload).unwrap();
        let safe = connector.sanitize(&payload).unwrap();

        assert_eq!(
            classified, expected_level,
            "classify mismatch for '{query}'"
        );
        assert_eq!(
            safe.classification, expected_level,
            "sanitize classification mismatch for '{query}'"
        );
    }
}

#[test]
fn test_pipeline_sanitize_preserves_action_id() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT 1");
    let payload_id = payload.id.clone();

    let safe = connector.sanitize(&payload).unwrap();
    assert_eq!(safe.original_id, payload_id);

    let result = connector.execute(&safe).unwrap();
    assert_eq!(result.action_id, payload_id);
}

#[test]
fn test_pipeline_duration_is_positive() {
    let connector = create_seeded_connector();
    let payload = make_payload("query_read", "SELECT * FROM users");

    let safe = connector.sanitize(&payload).unwrap();
    let result = connector.execute(&safe).unwrap();

    assert!(result.outcome.is_success());
    assert!(
        result.duration > Duration::ZERO,
        "Expected positive duration, got: {:?}",
        result.duration
    );
}

#[test]
fn test_pipeline_capabilities_declared_correctly() {
    let connector = create_seeded_connector();
    let caps = connector.capabilities();

    assert_eq!(caps.len(), 3);

    for cap in &caps {
        assert_eq!(cap.connector_id, *connector.id());
        assert!(!cap.name.is_empty(), "Capability '{}' has empty name", cap.id.as_str());
        assert!(!cap.description.is_empty(), "Capability '{}' has empty description", cap.id.as_str());
    }

    let read_cap = caps.iter().find(|c| c.id.as_str() == "query_read").unwrap();
    assert_eq!(read_cap.level, ActionLevel::Read);

    let write_cap = caps.iter().find(|c| c.id.as_str() == "query_write").unwrap();
    assert_eq!(write_cap.level, ActionLevel::Write);

    let destructive_cap = caps
        .iter()
        .find(|c| c.id.as_str() == "query_destructive")
        .unwrap();
    assert_eq!(destructive_cap.level, ActionLevel::Destructive);
}
