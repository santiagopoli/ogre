use ogre_core::ConnectorError;
use sqlparser::ast::{Expr, Query, Statement, Value};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

const DEFAULT_LIMIT: u64 = 1000;

/// Sanitize a SQL query:
/// - Reject multi-statement queries
/// - Add LIMIT to unbounded SELECTs
pub fn sanitize_sql(sql: &str) -> Result<String, ConnectorError> {
    let dialect = SQLiteDialect {};
    let mut statements = Parser::parse_sql(&dialect, sql)
        .map_err(|e| ConnectorError::SanitizationFailed(e.to_string()))?;

    if statements.is_empty() {
        return Err(ConnectorError::SanitizationFailed(
            "empty query".to_string(),
        ));
    }

    if statements.len() > 1 {
        return Err(ConnectorError::MultiStatement);
    }

    let stmt = &mut statements[0];
    if let Statement::Query(ref mut query) = stmt {
        add_limit_if_missing(query);
    }

    Ok(stmt.to_string())
}

fn add_limit_if_missing(query: &mut Query) {
    if query.limit.is_none() {
        // Only add LIMIT to simple SELECTs (not UNIONs etc. at top level, which already
        // have the limit field available on the Query struct)
        query.limit = Some(Expr::Value(Value::Number(DEFAULT_LIMIT.to_string(), false)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_limit_to_unbounded_select() {
        let result = sanitize_sql("SELECT * FROM users").unwrap();
        let lower = result.to_lowercase();
        assert!(lower.contains("limit"), "Expected LIMIT in: {result}");
    }

    #[test]
    fn preserves_existing_limit() {
        let result = sanitize_sql("SELECT * FROM users LIMIT 10").unwrap();
        assert!(result.contains("10"));
        // Should not double-add LIMIT
        let limit_count = result.to_lowercase().matches("limit").count();
        assert_eq!(limit_count, 1);
    }

    #[test]
    fn rejects_multi_statement() {
        let result = sanitize_sql("SELECT 1; SELECT 2");
        assert!(matches!(result, Err(ConnectorError::MultiStatement)));
    }

    #[test]
    fn non_select_passes_through() {
        let result = sanitize_sql("INSERT INTO users (name) VALUES ('alice')").unwrap();
        assert!(result.to_lowercase().contains("insert"));
    }
}
