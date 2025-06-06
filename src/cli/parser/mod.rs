use super::{start, stop};
use crate::cli::{dns, token};
use std::{collections::HashMap, env, process::exit};

#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) command: String,
    pub(crate) subcommand: Option<String>,
    pub(crate) subcommand_args: Vec<String>,
    pub(crate) options: Vec<String>,
    pub(crate) option_values: HashMap<String, String>,
}

impl Args {
    fn parse(raw_args: std::env::Args) -> Result<Self, String> {
        let args: Vec<String> = raw_args.collect();

        if args.len() < 2 {
            return Err(format!(
                "Usage: {} [start|stop|dns|token] [OPTIONS]",
                args[0]
            ));
        }

        let command = args[1].clone();
        let mut subcommand = None;
        let mut subcommand_args = Vec::new();
        let mut options = Vec::new();
        let mut option_values = HashMap::new();

        // Handle commands
        if args.len() > 2 {
            // Handle subcommands for the commands with subcommands
            if (command == "token" || command == "dns") && args.len() > 2 {
                subcommand = Some(args[2].clone());

                // Handle options and subcommand arguments
                let mut cur = 3;
                while cur < args.len() {
                    if args[cur].starts_with('-') {
                        let option = args[cur].clone();
                        options.push(option.clone());

                        // If the next argument does not start with '-', treat it as an option value
                        if cur + 1 < args.len() && !args[cur + 1].starts_with('-') {
                            option_values.insert(option, args[cur + 1].clone());
                            cur += 2; // move cursor option and value
                        } else {
                            cur += 1; // move cursor option only
                        }
                    } else {
                        subcommand_args.push(args[cur].clone());
                        cur += 1;
                    }
                }
            } else {
                // Handle options for other commands
                let mut cur = 2;
                while cur < args.len() {
                    if args[cur].starts_with('-') {
                        let option = args[cur].clone();
                        options.push(option.clone());

                        // If the next argument does not start with '-', treat it as an option value
                        if cur + 1 < args.len() && !args[cur + 1].starts_with('-') {
                            option_values.insert(option, args[cur + 1].clone());
                            cur += 2; // move cursor option and value
                        } else {
                            cur += 1; // move cursor option only
                        }
                    } else {
                        subcommand_args.push(args[cur].clone());
                        cur += 1;
                    }
                }
            }
        }

        Ok(Args {
            command,
            subcommand,
            subcommand_args,
            options,
            option_values,
        })
    }

    pub(crate) fn process_args(raw_args: env::Args) -> Self {
        // Parse command line arguments
        let args = match Self::parse(raw_args) {
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
                "token" => println!("{}", token::help_message("")),
                "dns" if args.subcommand.is_some() => {
                    println!("{}", dns::help_message(&args.subcommand.unwrap()));
                }
                "dns" => println!("{}", dns::help_message("")),
                "start" => println!("{}", start::help_message()),
                "stop" => println!("{}", stop::help_message()),
                _ => println!(
                    "{}",
                    Self::help_message(&env::args().next().unwrap_or_default())
                ),
            }
            exit(0);
        }

        args
    }

    pub(crate) fn has_option(&self, option: &str) -> bool {
        self.options.contains(&option.to_string())
    }

    fn help_message(program: &str) -> String {
        format!(
            "Usage: {} COMMAND [OPTIONS]\n\
            \n\
            Commands:\n\
            start         Start the bindizr service\n\
            stop          Stop the bindizr service\n\
            dns           Manage DNS configurations\n\
            token         Manage API tokens\n\
            \n\
            Run '{} COMMAND --help' for more information on a command.",
            program, program
        )
    }
}
