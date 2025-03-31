use crate::database::Session;
use crate::env::get_env;
use sea_orm::{DbBackend, FromQueryResult, JsonValue, Statement};

pub struct ApiService {
    pub session: Session,
}

impl ApiService {
    pub async fn new() -> Result<Self, String> {
        let session = Session::new().await?;
        Ok(Self { session })
    }

    pub async fn get_table_names(&self) -> Vec<String> {
        let database_driver = get_env("DATABASE_DRIVER");

        match database_driver.to_lowercase().as_str() {
            // "mysql" => self.get_table_names_mysql().await,
            "sqlite" => self.get_table_names_sqlite().await,
            _ => {
                panic!("Unsupported database driver: {}", database_driver);
            }
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
