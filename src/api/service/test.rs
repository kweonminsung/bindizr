#[derive(Clone)]
pub(crate) struct TestService;

impl TestService {
    // pub(crate) fn get_table_names(pool: &DatabasePool) -> Vec<String> {
    //     let query = "SHOW TABLES";
    //     pool.get_connection()
    //         .query(query)
    //         .unwrap_or_else(|_| Vec::new())
    // }
}
