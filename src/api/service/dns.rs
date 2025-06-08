use crate::{log_error, rndc::RndcClient, serializer::SERIALIZER};

#[derive(Clone)]
pub(crate) struct DnsService;

impl DnsService {
    pub(crate) fn get_dns_status() -> Result<String, String> {
        let res = match RndcClient::command("status") {
            Ok(response) => response,
            Err(e) => {
                log_error!("Failed to get DNS status: {}", e);
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
                log_error!("Failed to reload DNS: {}", e);
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
        match SERIALIZER.send_message_and_wait("write_config") {
            Ok(_) => Ok("DNS configuration written successfully.".to_string()),
            Err(e) => {
                log_error!("Failed to write DNS configuration: {}", e);
                Err("Failed to write DNS configuration".to_string())
            }
        }
    }
}
