use crate::{rndc::RndcClient, serializer::SERIALIZER};

pub fn help_message() -> String {
    "Usage: bindizr reload\n\
    \n\
    Reload DNS configuration\n\
    \n\
    Options:\n\
    -h, --help         Show this help message"
        .to_string()
}

pub fn execute(_args: &crate::cli::Args) {
    SERIALIZER.send_message("write_config");

    match RndcClient::command("reload") {
        Ok(_) => println!("DNS configuration reloaded successfully"),
        Err(e) => eprintln!("Failed to reload DNS configuration: {}", e),
    }
}
