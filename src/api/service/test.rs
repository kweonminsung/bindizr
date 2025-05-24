use crate::{rndc::RndcClient, serializer::SERIALIZER};

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
        let res = RndcClient::command("status")?;

        if !res.result {
            return Err("Failed to get DNS status".to_string());
        }

        match res.text {
            Some(text) => Ok(text),
            None => Ok("".to_string()),
        }
    }

    pub fn reload_dns() -> Result<String, String> {
        let res = RndcClient::command("reload")?;

        if !res.result {
            return Err("Failed to reload DNS".to_string());
        }

        match res.text {
            Some(text) => Ok(text),
            None => Ok("".to_string()),
        }
    }

    pub fn write_dns_config() -> Result<String, String> {
        let serializer = &SERIALIZER;

        serializer.mpsc_send("write_config");

        Ok("Config write request sent".to_string())
    }
}
