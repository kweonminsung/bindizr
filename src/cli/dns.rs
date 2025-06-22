use crate::{
    daemon::{self, socket::client::DAEMON_SOCKET_CLIENT},
    log_debug,
};

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
    daemon::socket::client::initialize();

    match args.subcommand.as_deref() {
        Some("write") => write_dns_config(),
        Some("reload") => reload_dns_config(),
        Some("status") => get_dns_status(),
        _ => Err(help_message("").to_string()),
    }
}

fn write_dns_config() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("dns_write_config", None)?;

    log_debug!("DNS configuration write result: {:?}", res);

    Ok(())
}

fn reload_dns_config() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("dns_reload", None)?;

    log_debug!("DNS configuration reload result: {:?}", res);

    Ok(())
}

fn get_dns_status() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("dns_status", None)?;

    log_debug!("DNS status result: {:?}", res);

    if let Some(status) = res.data.get("status") {
        println!("DNS Status: {}", status);
    } else {
        println!("DNS Status: No status available");
    }

    Ok(())
}
