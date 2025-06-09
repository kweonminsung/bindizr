use crate::{rndc::RndcClient, serializer::SERIALIZER};

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
        _ => Err(help_message("").to_string()),
    }
}

fn write_dns_config() -> Result<(), String> {
    match SERIALIZER.send_message_and_wait("write_config") {
        Ok(_) => {
            println!("DNS configuration written successfully.");
        }
        Err(e) => return Err(format!("Failed to write DNS configuration: {}", e)),
    }

    Ok(())
}

fn reload_dns_config() -> Result<(), String> {
    match RndcClient::command("reload") {
        Ok(_) => {
            println!("DNS configuration reloaded successfully");
        }
        Err(e) => return Err(format!("Failed to reload DNS configuration: {}", e)),
    }

    Ok(())
}
