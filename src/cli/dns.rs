use crate::{rndc::RNDC_CLIENT, serializer::SERIALIZER};

pub fn help_message(subcommand: &str) -> String {
    match subcommand {
        "write" => "Usage: bindizr dns write\n\
            \n\
            Write DNS configuration to the server"
            .to_string(),
        "reload" => "Usage: bindizr dns reload\n\
            Reload DNS configuration on the server"
            .to_string(),
        _ => "Usage: bindizr dns COMMAND\n\
            \n\
            Commands:\n\
            write    Write DNS configuration to the server\n\
            reload   Reload DNS configuration on the server"
            .to_string(),
    }
}

pub fn handle_command(args: &crate::cli::Args) -> Result<(), String> {
    match args.subcommand.as_deref() {
        Some("write") => write_dns_config(),
        Some("reload") => reload_dns_config(),
        Some("status") => get_dns_status(),
        _ => Err(help_message("").to_string()),
    }
}

fn write_dns_config() -> Result<(), String> {
    match SERIALIZER.send_message_and_wait("write_config") {
        Ok(_) => {
            println!("DNS configuration written successfully.");
            Ok(())
        }
        Err(e) => Err(format!("Failed to write DNS configuration: {}", e)),
    }
}

fn reload_dns_config() -> Result<(), String> {
    match RNDC_CLIENT.command("reload") {
        Ok(_) => {
            println!("DNS configuration reloaded successfully");
            Ok(())
        }
        Err(e) => Err(format!("Failed to reload DNS configuration: {}", e)),
    }
}

fn get_dns_status() -> Result<(), String> {
    match RNDC_CLIENT.command("status") {
        Ok(response) => {
            if !response.result {
                return Err("Failed to get DNS status".to_string());
            }
            println!(
                "DNS Status: {}",
                response
                    .text
                    .unwrap_or_else(|| "No status text available".to_string())
            );
            Ok(())
        }
        Err(e) => Err(format!("Failed to get DNS status: {}", e)),
    }
}
