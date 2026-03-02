use ogre_core::ActionLevel;
use ogre_core::ConnectorError;
use sqlparser::ast::{FromTable, Query, Select, SelectItem, SetExpr, Statement, TableFactor, TableWithJoins};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;
use std::collections::HashSet;

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

/// Extract all table names referenced in a SQL statement.
/// Returns table names in lowercase.
pub fn extract_tables(sql: &str) -> Result<HashSet<String>, ConnectorError> {
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

    let mut tables = HashSet::new();
    extract_tables_from_statement(&statements[0], &mut tables);
    Ok(tables)
}

fn extract_tables_from_statement(stmt: &Statement, tables: &mut HashSet<String>) {
    match stmt {
        Statement::Query(query) => extract_tables_from_query(query, tables),
        Statement::Insert {
            table_name, source, ..
        } => {
            tables.insert(table_name.to_string().to_lowercase());
            if let Some(ref source) = source {
                extract_tables_from_query(source, tables);
            }
        }
        Statement::Update {
            table, selection, ..
        } => {
            extract_tables_from_table_with_joins(table, tables);
            if let Some(ref expr) = selection {
                extract_tables_from_expr(expr, tables);
            }
        }
        Statement::Delete {
            from,
            using,
            selection,
            ..
        } => {
            let from_tables = match from {
                FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
            };
            for twj in from_tables {
                extract_tables_from_table_with_joins(twj, tables);
            }
            if let Some(ref using_clause) = using {
                for twj in using_clause {
                    extract_tables_from_table_with_joins(twj, tables);
                }
            }
            if let Some(ref expr) = selection {
                extract_tables_from_expr(expr, tables);
            }
        }
        Statement::Drop { names, .. } => {
            for name in names {
                tables.insert(name.to_string().to_lowercase());
            }
        }
        Statement::AlterTable { name, .. } => {
            tables.insert(name.to_string().to_lowercase());
        }
        Statement::Truncate {
            table_name, ..
        } => {
            tables.insert(table_name.to_string().to_lowercase());
        }
        Statement::CreateTable { name, query, .. } => {
            tables.insert(name.to_string().to_lowercase());
            if let Some(ref query) = query {
                extract_tables_from_query(query, tables);
            }
        }
        Statement::Explain { statement, .. } => {
            extract_tables_from_statement(statement, tables);
        }
        _ => {}
    }
}

fn extract_tables_from_query(query: &Query, tables: &mut HashSet<String>) {
    // Handle CTEs (WITH clauses)
    if let Some(ref with) = query.with {
        for cte in &with.cte_tables {
            extract_tables_from_query(&cte.query, tables);
        }
    }

    extract_tables_from_set_expr(&query.body, tables);
}

fn extract_tables_from_set_expr(body: &SetExpr, tables: &mut HashSet<String>) {
    match body {
        SetExpr::Select(select) => extract_tables_from_select(select, tables),
        SetExpr::Query(query) => extract_tables_from_query(query, tables),
        SetExpr::SetOperation { left, right, .. } => {
            extract_tables_from_set_expr(left, tables);
            extract_tables_from_set_expr(right, tables);
        }
        SetExpr::Values(_) => {}
        _ => {}
    }
}

fn extract_tables_from_select(select: &Select, tables: &mut HashSet<String>) {
    for twj in &select.from {
        extract_tables_from_table_with_joins(twj, tables);
    }
    // Check subqueries in projection
    for item in &select.projection {
        if let SelectItem::ExprWithAlias { expr, .. } | SelectItem::UnnamedExpr(expr) = item {
            extract_tables_from_expr(expr, tables);
        }
    }
    // Check WHERE clause for subqueries
    if let Some(ref selection) = select.selection {
        extract_tables_from_expr(selection, tables);
    }
}

fn extract_tables_from_table_with_joins(twj: &TableWithJoins, tables: &mut HashSet<String>) {
    extract_tables_from_table_factor(&twj.relation, tables);
    for join in &twj.joins {
        extract_tables_from_table_factor(&join.relation, tables);
    }
}

fn extract_tables_from_table_factor(factor: &TableFactor, tables: &mut HashSet<String>) {
    match factor {
        TableFactor::Table { name, .. } => {
            tables.insert(name.to_string().to_lowercase());
        }
        TableFactor::Derived { subquery, .. } => {
            extract_tables_from_query(subquery, tables);
        }
        TableFactor::NestedJoin { table_with_joins, .. } => {
            extract_tables_from_table_with_joins(table_with_joins, tables);
        }
        _ => {}
    }
}

fn extract_tables_from_expr(expr: &sqlparser::ast::Expr, tables: &mut HashSet<String>) {
    match expr {
        sqlparser::ast::Expr::Subquery(query) => {
            extract_tables_from_query(query, tables);
        }
        sqlparser::ast::Expr::InSubquery { subquery, expr, .. } => {
            extract_tables_from_query(subquery, tables);
            extract_tables_from_expr(expr, tables);
        }
        sqlparser::ast::Expr::BinaryOp { left, right, .. } => {
            extract_tables_from_expr(left, tables);
            extract_tables_from_expr(right, tables);
        }
        sqlparser::ast::Expr::UnaryOp { expr, .. } => {
            extract_tables_from_expr(expr, tables);
        }
        sqlparser::ast::Expr::Nested(expr) => {
            extract_tables_from_expr(expr, tables);
        }
        sqlparser::ast::Expr::Exists { subquery, .. } => {
            extract_tables_from_query(subquery, tables);
        }
        sqlparser::ast::Expr::Between { expr, low, high, .. } => {
            extract_tables_from_expr(expr, tables);
            extract_tables_from_expr(low, tables);
            extract_tables_from_expr(high, tables);
        }
        sqlparser::ast::Expr::Case { operand, conditions, results, else_result, .. } => {
            if let Some(ref op) = operand {
                extract_tables_from_expr(op, tables);
            }
            for cond in conditions {
                extract_tables_from_expr(cond, tables);
            }
            for result in results {
                extract_tables_from_expr(result, tables);
            }
            if let Some(ref else_r) = else_result {
                extract_tables_from_expr(else_r, tables);
            }
        }
        sqlparser::ast::Expr::Function(func) => {
            for arg in func.args.iter() {
                match arg {
                    sqlparser::ast::FunctionArg::Unnamed(
                        sqlparser::ast::FunctionArgExpr::Expr(e),
                    ) => extract_tables_from_expr(e, tables),
                    sqlparser::ast::FunctionArg::Named {
                        arg: sqlparser::ast::FunctionArgExpr::Expr(e),
                        ..
                    } => extract_tables_from_expr(e, tables),
                    _ => {}
                }
            }
        }
        sqlparser::ast::Expr::InList { expr, list, .. } => {
            extract_tables_from_expr(expr, tables);
            for item in list {
                extract_tables_from_expr(item, tables);
            }
        }
        _ => {}
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

    // -- extract_tables tests --

    #[test]
    fn extract_select_from() {
        let tables = extract_tables("SELECT * FROM users").unwrap();
        assert_eq!(tables, HashSet::from(["users".to_string()]));
    }

    #[test]
    fn extract_select_join() {
        let tables =
            extract_tables("SELECT u.name, o.id FROM users u JOIN orders o ON u.id = o.user_id")
                .unwrap();
        assert_eq!(
            tables,
            HashSet::from(["users".to_string(), "orders".to_string()])
        );
    }

    #[test]
    fn extract_select_subquery() {
        let tables = extract_tables(
            "SELECT name FROM users WHERE id IN (SELECT DISTINCT user_id FROM orders WHERE quantity > 2)",
        )
        .unwrap();
        assert_eq!(
            tables,
            HashSet::from(["users".to_string(), "orders".to_string()])
        );
    }

    #[test]
    fn extract_insert() {
        let tables =
            extract_tables("INSERT INTO users (name, email) VALUES ('alice', 'a@b.com')").unwrap();
        assert_eq!(tables, HashSet::from(["users".to_string()]));
    }

    #[test]
    fn extract_insert_select() {
        let tables =
            extract_tables("INSERT INTO archive SELECT * FROM orders WHERE created_at < '2024-01-01'")
                .unwrap();
        assert_eq!(
            tables,
            HashSet::from(["archive".to_string(), "orders".to_string()])
        );
    }

    #[test]
    fn extract_update() {
        let tables =
            extract_tables("UPDATE users SET active = 0 WHERE id = 1").unwrap();
        assert_eq!(tables, HashSet::from(["users".to_string()]));
    }

    #[test]
    fn extract_delete() {
        let tables = extract_tables("DELETE FROM orders WHERE user_id = 3").unwrap();
        assert_eq!(tables, HashSet::from(["orders".to_string()]));
    }

    #[test]
    fn extract_drop() {
        let tables = extract_tables("DROP TABLE orders").unwrap();
        assert_eq!(tables, HashSet::from(["orders".to_string()]));
    }

    #[test]
    fn extract_alter() {
        let tables = extract_tables("ALTER TABLE users ADD COLUMN phone TEXT").unwrap();
        assert_eq!(tables, HashSet::from(["users".to_string()]));
    }

    #[test]
    fn extract_case_insensitive() {
        let tables = extract_tables("SELECT * FROM Users JOIN ORDERS ON Users.id = ORDERS.user_id").unwrap();
        assert_eq!(
            tables,
            HashSet::from(["users".to_string(), "orders".to_string()])
        );
    }

    #[test]
    fn extract_cte() {
        let tables = extract_tables(
            "WITH active AS (SELECT * FROM users WHERE active = 1) SELECT * FROM active",
        )
        .unwrap();
        // CTE name "active" appears as a table in the outer query
        assert!(tables.contains("users"));
        assert!(tables.contains("active"));
    }

    #[test]
    fn extract_multiple_joins() {
        let tables = extract_tables(
            "SELECT u.name, p.name, o.quantity FROM orders o JOIN users u ON o.user_id = u.id JOIN products p ON o.product_id = p.id",
        )
        .unwrap();
        assert_eq!(
            tables,
            HashSet::from([
                "orders".to_string(),
                "users".to_string(),
                "products".to_string()
            ])
        );
    }

    #[test]
    fn extract_derived_table() {
        let tables = extract_tables(
            "SELECT * FROM (SELECT id, name FROM users) AS sub",
        )
        .unwrap();
        assert!(tables.contains("users"));
    }
}
