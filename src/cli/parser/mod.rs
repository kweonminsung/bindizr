use super::{start, stop};
use crate::cli::{SUPPORTED_COMMANDS, dns, help, status, token};
use std::{collections::HashMap, env, process::exit};

#[derive(Debug)]
pub struct Args {
    pub command: String,
    pub subcommand: Option<String>,
    pub subcommand_args: Vec<String>,
    pub options: Vec<String>,
    pub option_values: HashMap<String, String>,
}

const SUBCOMMAND_COMMANDS: [&str; 2] = ["dns", "token"];

impl Args {
    fn parse(raw_args: std::env::Args) -> Result<Self, String> {
        let args: Vec<String> = raw_args.collect();

        if args.len() < 2 {
            return Err(format!(
                "Usage: {} [{}] [OPTIONS]",
                args[0],
                SUPPORTED_COMMANDS.join("|")
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
            if SUBCOMMAND_COMMANDS.contains(&command.as_str()) && args.len() > 2 {
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

    pub fn process_args(raw_args: env::Args) -> Self {
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
                "status" => println!("{}", status::help_message()),
                _ => println!("{}", help::help_message()),
            }
            exit(0);
        }

        args
    }

    pub fn has_option(&self, option: &str) -> bool {
        self.options.contains(&option.to_string())
    }

    pub fn get_option_value(&self, option: &str) -> Option<&String> {
        self.option_values.get(option)
    }
}
