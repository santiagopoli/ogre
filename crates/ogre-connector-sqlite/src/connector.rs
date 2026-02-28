use crate::classifier::classify_sql;
use crate::sanitizer::sanitize_sql;
use ogre_core::capability::CapabilityDeclaration;
use ogre_core::ids::{CapabilityId, ConnectorId};
use ogre_core::{
    ActionLevel, ActionPayload, ActionResult, Connector, ConnectorError, Outcome, SafeAction,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::time::{Duration, Instant};

pub struct SqliteConnector {
    id: ConnectorId,
    pool: Pool<SqliteConnectionManager>,
    query_timeout: Duration,
}

impl SqliteConnector {
    pub fn new(db_path: &str, query_timeout_secs: u64) -> Result<Self, ConnectorError> {
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::builder()
            .max_size(10)
            .build(manager)
            .map_err(|e| ConnectorError::ExecutionFailed(e.to_string()))?;

        Ok(Self {
            id: ConnectorId::new("sqlite"),
            pool,
            query_timeout: Duration::from_secs(query_timeout_secs),
        })
    }

    pub fn in_memory() -> Result<Self, ConnectorError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1) // in-memory DB is per-connection, so use 1
            .build(manager)
            .map_err(|e| ConnectorError::ExecutionFailed(e.to_string()))?;

        Ok(Self {
            id: ConnectorId::new("sqlite"),
            pool,
            query_timeout: Duration::from_secs(30),
        })
    }

    fn extract_sql(payload: &ActionPayload) -> Result<&str, ConnectorError> {
        payload
            .parameters
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorError::ClassificationFailed(
                    "missing 'query' parameter".to_string(),
                )
            })
    }
}

impl Connector for SqliteConnector {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    fn name(&self) -> &str {
        "SQLite"
    }

    fn classify(&self, action: &ActionPayload) -> Result<ActionLevel, ConnectorError> {
        let sql = Self::extract_sql(action)?;
        classify_sql(sql)
    }

    fn sanitize(&self, action: &ActionPayload) -> Result<SafeAction, ConnectorError> {
        let sql = Self::extract_sql(action)?;
        let classification = classify_sql(sql)?;
        let sanitized = sanitize_sql(sql)?;

        Ok(SafeAction {
            original_id: action.id.clone(),
            connector_id: self.id.clone(),
            classification,
            sanitized_parameters: serde_json::json!({ "query": sanitized }),
        })
    }

    fn execute(&self, action: &SafeAction) -> Result<ActionResult, ConnectorError> {
        let sql = action
            .sanitized_parameters
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorError::ExecutionFailed("missing sanitized query".to_string())
            })?;

        let conn = self
            .pool
            .get()
            .map_err(|_| ConnectorError::PoolExhausted)?;

        let start = Instant::now();

        // Set the timeout on the connection
        conn.busy_timeout(self.query_timeout)
            .map_err(|e| ConnectorError::ExecutionFailed(e.to_string()))?;

        let result = match action.classification {
            ActionLevel::Read => execute_query(&conn, sql),
            _ => execute_statement(&conn, sql),
        };

        let duration = start.elapsed();

        match result {
            Ok(data) => Ok(ActionResult {
                action_id: action.original_id.clone(),
                outcome: Outcome::Success,
                data: Some(data),
                duration,
            }),
            Err(e) => Ok(ActionResult {
                action_id: action.original_id.clone(),
                outcome: Outcome::Error {
                    code: "SQLITE_ERROR".to_string(),
                    message: e.to_string(),
                },
                data: None,
                duration,
            }),
        }
    }

    fn capabilities(&self) -> Vec<CapabilityDeclaration> {
        vec![
            CapabilityDeclaration {
                id: CapabilityId::new("query_read"),
                connector_id: self.id.clone(),
                name: "Read Query".to_string(),
                description: "Execute a read-only SQL query".to_string(),
                level: ActionLevel::Read,
            },
            CapabilityDeclaration {
                id: CapabilityId::new("query_write"),
                connector_id: self.id.clone(),
                name: "Write Query".to_string(),
                description: "Execute a state-modifying SQL query".to_string(),
                level: ActionLevel::Write,
            },
            CapabilityDeclaration {
                id: CapabilityId::new("query_destructive"),
                connector_id: self.id.clone(),
                name: "Destructive Query".to_string(),
                description: "Execute a destructive SQL query".to_string(),
                level: ActionLevel::Destructive,
            },
        ]
    }
}

fn execute_query(
    conn: &rusqlite::Connection,
    sql: &str,
) -> Result<serde_json::Value, ConnectorError> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| ConnectorError::ExecutionFailed(e.to_string()))?;

    let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let mut obj = serde_json::Map::new();
            for (i, col) in column_names.iter().enumerate() {
                let val: rusqlite::types::Value = row.get(i)?;
                let json_val = match val {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(n) => serde_json::json!(n),
                    rusqlite::types::Value::Real(f) => serde_json::json!(f),
                    rusqlite::types::Value::Text(s) => serde_json::json!(s),
                    rusqlite::types::Value::Blob(b) => {
                        serde_json::json!(format!("<blob:{} bytes>", b.len()))
                    }
                };
                obj.insert(col.clone(), json_val);
            }
            Ok(serde_json::Value::Object(obj))
        })
        .map_err(|e| ConnectorError::ExecutionFailed(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ConnectorError::ExecutionFailed(e.to_string()))?;

    Ok(serde_json::json!({
        "columns": column_names,
        "rows": rows,
        "row_count": rows.len(),
    }))
}

fn execute_statement(
    conn: &rusqlite::Connection,
    sql: &str,
) -> Result<serde_json::Value, ConnectorError> {
    let rows_affected = conn
        .execute(sql, [])
        .map_err(|e| ConnectorError::ExecutionFailed(e.to_string()))?;

    Ok(serde_json::json!({
        "rows_affected": rows_affected,
    }))
}
