use ogre_core::ActionLevel;
use ogre_core::ConnectorError;
use sqlparser::ast::Statement;
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

/// Classify SQL statements by risk level.
pub fn classify_sql(sql: &str) -> Result<ActionLevel, ConnectorError> {
    let dialect = SQLiteDialect {};
    let statements = Parser::parse_sql(&dialect, sql)
        .map_err(|e| ConnectorError::ClassificationFailed(e.to_string()))?;

    if statements.is_empty() {
        return Err(ConnectorError::ClassificationFailed(
            "empty query".to_string(),
        ));
    }

    if statements.len() > 1 {
        return Err(ConnectorError::MultiStatement);
    }

    Ok(classify_statement(&statements[0]))
}

fn classify_statement(stmt: &Statement) -> ActionLevel {
    match stmt {
        // Read operations
        Statement::Query(_) => ActionLevel::Read,
        Statement::Explain { .. } => ActionLevel::Read,

        // Write operations
        Statement::Insert { .. } => ActionLevel::Write,
        Statement::Update { .. } => ActionLevel::Write,
        Statement::CreateTable { .. } => ActionLevel::Write,
        Statement::CreateIndex { .. } => ActionLevel::Write,
        Statement::CreateView { .. } => ActionLevel::Write,

        // Destructive operations
        Statement::Delete { .. } => ActionLevel::Destructive,
        Statement::Drop { .. } => ActionLevel::Destructive,
        Statement::AlterTable { .. } => ActionLevel::Destructive,
        Statement::Truncate { .. } => ActionLevel::Destructive,

        // Anything unknown is treated as destructive (safe default)
        _ => ActionLevel::Destructive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_is_read() {
        assert_eq!(classify_sql("SELECT * FROM users").unwrap(), ActionLevel::Read);
        assert_eq!(classify_sql("SELECT 1").unwrap(), ActionLevel::Read);
        assert_eq!(
            classify_sql("SELECT * FROM users WHERE id = 1").unwrap(),
            ActionLevel::Read
        );
    }

    #[test]
    fn select_with_cte_is_read() {
        assert_eq!(
            classify_sql("WITH active AS (SELECT * FROM users WHERE active = 1) SELECT * FROM active").unwrap(),
            ActionLevel::Read
        );
    }

    #[test]
    fn insert_is_write() {
        assert_eq!(
            classify_sql("INSERT INTO users (name) VALUES ('alice')").unwrap(),
            ActionLevel::Write
        );
    }

    #[test]
    fn update_is_write() {
        assert_eq!(
            classify_sql("UPDATE users SET name = 'bob' WHERE id = 1").unwrap(),
            ActionLevel::Write
        );
    }

    #[test]
    fn create_table_is_write() {
        assert_eq!(
            classify_sql("CREATE TABLE test (id INTEGER PRIMARY KEY)").unwrap(),
            ActionLevel::Write
        );
    }

    #[test]
    fn delete_is_destructive() {
        assert_eq!(
            classify_sql("DELETE FROM users WHERE id = 1").unwrap(),
            ActionLevel::Destructive
        );
    }

    #[test]
    fn drop_is_destructive() {
        assert_eq!(
            classify_sql("DROP TABLE users").unwrap(),
            ActionLevel::Destructive
        );
    }

    #[test]
    fn alter_is_destructive() {
        assert_eq!(
            classify_sql("ALTER TABLE users ADD COLUMN email TEXT").unwrap(),
            ActionLevel::Destructive
        );
    }

    #[test]
    fn multi_statement_rejected() {
        let result = classify_sql("SELECT 1; DROP TABLE users");
        assert!(matches!(result, Err(ConnectorError::MultiStatement)));
    }

    #[test]
    fn empty_query_rejected() {
        let result = classify_sql("");
        assert!(result.is_err());
    }

    #[test]
    fn explain_is_read() {
        assert_eq!(
            classify_sql("EXPLAIN SELECT * FROM users").unwrap(),
            ActionLevel::Read
        );
    }

    #[test]
    fn select_with_subquery_is_read() {
        assert_eq!(
            classify_sql("SELECT * FROM (SELECT id, name FROM users) AS sub").unwrap(),
            ActionLevel::Read
        );
    }

    #[test]
    fn select_union_is_read() {
        assert_eq!(
            classify_sql("SELECT id FROM users UNION SELECT id FROM admins").unwrap(),
            ActionLevel::Read
        );
    }
}
