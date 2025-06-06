use crate::{rndc::RndcClient, serializer::SERIALIZER};

pub(crate) fn help_message(subcommand: &str) -> String {
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

pub(crate) fn handle_command(args: &crate::cli::Args) -> Result<(), String> {
    match args.subcommand.as_deref() {
        Some("write") => write_dns_config(),
        Some("reload") => reload_dns_config(),
        _ => Err(help_message("").to_string()),
    }
}

fn write_dns_config() -> Result<(), String> {
    // Logic to write DNS configuration
    // This is a placeholder; actual implementation will depend on your application logic
    println!("DNS configuration written successfully.");
    Ok(())
}

fn reload_dns_config() -> Result<(), String> {
    SERIALIZER.send_message("write_config");

    match RndcClient::command("reload") {
        Ok(_) => println!("DNS configuration reloaded successfully"),
        Err(e) => eprintln!("Failed to reload DNS configuration: {}", e),
    }

    Ok(())
}
