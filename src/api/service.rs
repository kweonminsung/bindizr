use crate::database::{DatabaseDriver, Session, SESSION};
use sea_orm::{DbBackend, FromQueryResult, JsonValue, Statement};

pub struct ApiService<'a> {
    pub session: &'a Session,
}

impl<'a> ApiService<'a> {
    pub async fn new() -> Self {
        Self {
            session: SESSION.get().unwrap(),
        }
    }

    pub async fn get_table_names(&self) -> Vec<String> {
        match self.session.driver {
            // DatabaseDriver::Mysql => self.get_table_names_mysql().await,
            DatabaseDriver::Sqlite => self.get_table_names_sqlite().await,
        }
    }

    // async fn get_table_names_mysql(&self) -> Vec<String> {}

    async fn get_table_names_sqlite(&self) -> Vec<String> {
        let tables = JsonValue::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT name FROM sqlite_master;"#,
            [],
        ))
        .all(&self.session.connection)
        .await
        .unwrap();

        dbg!(&tables);

        let mut table_names = Vec::new();
        for table in &tables {
            if let Some(name) = table.get("name").and_then(|v| v.as_str()) {
                table_names.push(name.to_string());
            }
        }

        table_names
    }
}
