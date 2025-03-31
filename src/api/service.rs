use crate::database::Session;
use sea_orm::{DbBackend, FromQueryResult, JsonValue, Statement};

pub struct ApiService {
    pub session: Session,
}

impl ApiService {
    pub async fn new() -> Result<Self, String> {
        let session = Session::new().await?;
        Ok(Self { session })
    }

    pub async fn get_table_names(&self) -> Result<String, String> {
        let tables = JsonValue::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT name FROM sqlite_master;"#,
            [],
        ))
        .all(&self.session.connection)
        .await
        .unwrap();

        dbg!(tables);

        Ok(String::from("test"))
    }
}
