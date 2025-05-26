pub mod daemon;

use std::{env, process::exit};

pub struct Args {
    pub command: String,
    pub foreground: bool,
    pub help: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = env::args().collect();

        if args.len() < 2 {
            return Err(format!("Usage: {} [start|stop|reload] [OPTIONS]", args[0]));
        }

        let command = args[1].clone();
        let mut foreground = false;
        let mut help = false;

        if args.len() > 2 {
            match args[2].as_str() {
                "-f" | "--foreground" => foreground = true,
                "-h" | "--help" => help = true,
                _ => return Err(format!("Unsupported option: {}", args[2])),
            }
        }

        Ok(Args {
            command,
            foreground,
            help,
        })
    }

    fn help_message(program: &str) -> String {
        format!(
            "Usage: {} start [-f|--foreground] [-h|--help]\n\
            Options:\n\
            -f, --foreground   Run in foreground (default is background)\n\
            -h, --help         Show this help message",
            program
        )
    }

    pub fn process_args() -> Self {
        // Parse command line arguments
        let args = match Self::parse() {
            Ok(args) => args,
            Err(msg) => {
                eprintln!("{}", msg);
                exit(1);
            }
        };

        // Show help if requested
        if args.help {
            println!(
                "{}",
                Self::help_message(&env::args().next().unwrap_or_default())
            );
            exit(0);
        }

        args
    }
}
