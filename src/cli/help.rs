pub fn handle_command() -> Result<(), String> {
    println!("{}", help_message());

    Ok(())
}

pub fn help_message() -> String {
    "Usage: bindizr [COMMAND] [OPTIONS]\n\n\
        Commands:\n\
        start      Start the Bind service\n\
        stop       Stop the Bind service\n\
        status     Show the status of the Bind service\n\
        dns        Manage DNS records\n\
        token      Manage API tokens\n\
        help       Show this help message\n\
        bootstrap  Initialize the application"
        .to_string()
}
