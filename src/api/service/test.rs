use crate::rndc::RNDC_CLIENT;

#[derive(Clone)]
pub struct TestService;

impl TestService {
    // pub fn get_table_names(pool: &DatabasePool) -> Vec<String> {
    //     let query = "SHOW TABLES";
    //     pool.get_connection()
    //         .query(query)
    //         .unwrap_or_else(|_| Vec::new())
    // }

    pub fn get_dns_status() -> Result<String, String> {
        let rndc_client = &RNDC_CLIENT;

        let res = rndc_client.rndc_command("status")?;

        if !res.result {
            return Err("Failed to get DNS status".to_string());
        }

        match res.text {
            Some(text) => Ok(text),
            None => Ok("".to_string()),
        }
    }
}
