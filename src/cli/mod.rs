pub mod daemon;
pub mod reload;
pub mod start;
pub mod stop;
pub mod token;

use std::{env, process::exit};

// 명령어 구조체 수정
pub struct Args {
    pub command: String,
    pub subcommand: Option<String>,
    pub subcommand_args: Vec<String>,
    pub options: Vec<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = env::args().collect();

        if args.len() < 2 {
            return Err(format!(
                "Usage: {} [start|stop|reload|token] [OPTIONS]",
                args[0]
            ));
        }

        let command = args[1].clone();
        let mut subcommand = None;
        let mut subcommand_args = Vec::new();
        let mut options = Vec::new();

        // Handle subcommand
        if command == "token" && args.len() > 2 {
            subcommand = Some(args[2].clone());

            // Get subcommand arguments
            if args.len() > 3 {
                subcommand_args = args[3..].to_vec();
            }
        } else if args.len() > 2 {
            for i in 2..args.len() {
                if args[i].starts_with('-') {
                    options.push(args[i].clone());
                } else {
                    subcommand_args.push(args[i].clone());
                }
            }
        }

        Ok(Args {
            command,
            subcommand,
            subcommand_args,
            options,
        })
    }

    fn help_message(program: &str) -> String {
        format!(
            "Usage: {} COMMAND [OPTIONS]\n\
            \n\
            Commands:\n\
            start         Start the bindizr service\n\
            stop          Stop the bindizr service\n\
            reload        Reload DNS configuration\n\
            token         Manage API tokens\n\
            \n\
            Run '{} COMMAND --help' for more information on a command.",
            program, program
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
        if args.options.contains(&"--help".to_string()) || args.options.contains(&"-h".to_string())
        {
            match args.command.as_str() {
                "token" if args.subcommand.is_some() => {
                    println!("{}", token::help_message(&args.subcommand.unwrap()));
                }
                "start" => println!("{}", start::help_message()),
                "stop" => println!("{}", stop::help_message()),
                "reload" => println!("{}", reload::help_message()),
                "token" => println!("{}", token::help_message("")),
                _ => println!(
                    "{}",
                    Self::help_message(&env::args().next().unwrap_or_default())
                ),
            }
            exit(0);
        }

        args
    }

    pub fn has_option(&self, option: &str) -> bool {
        self.options.contains(&option.to_string())
    }
}
