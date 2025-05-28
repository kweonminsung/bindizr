use crate::{rndc::RndcClient, serializer::SERIALIZER};

#[derive(Clone)]
pub(crate) struct TestService;

impl TestService {
    // pub(crate) fn get_table_names(pool: &DatabasePool) -> Vec<String> {
    //     let query = "SHOW TABLES";
    //     pool.get_connection()
    //         .query(query)
    //         .unwrap_or_else(|_| Vec::new())
    // }

    pub(crate) fn get_dns_status() -> Result<String, String> {
        let res = match RndcClient::command("status") {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Failed to get DNS status: {}", e);
                return Err("Failed to get DNS status".to_string());
            }
        };

        if !res.result {
            return Err("Failed to get DNS status".to_string());
        }

        match res.text {
            Some(text) => Ok(text),
            None => Ok("".to_string()),
        }
    }

    pub(crate) fn reload_dns() -> Result<String, String> {
        let res = match RndcClient::command("reload") {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Failed to reload DNS: {}", e);
                return Err("Failed to reload DNS".to_string());
            }
        };

        if !res.result {
            return Err("Failed to reload DNS".to_string());
        }

        match res.text {
            Some(text) => Ok(text),
            None => Ok("".to_string()),
        }
    }

    pub(crate) fn write_dns_config() -> Result<String, String> {
        let serializer = &SERIALIZER;

        serializer.send_message("write_config");

        Ok("Config write request sent".to_string())
    }
}
