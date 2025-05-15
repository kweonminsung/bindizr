use crate::database::model::{record::Record, record::RecordType, zone::Zone};
use crate::database::{DatabasePool, DATABASE_POOL};
use crate::env::get_env;
use lazy_static::lazy_static;
use mysql::prelude::*;
use std::fmt::Write;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

pub fn initialize() {
    SERIALIZER.mpsc_send("initialize".to_string());
    // SERIALIZER.mpsc_send("write_config".to_string());
}

pub struct Serializer {
    tx: Sender<String>,
}

impl Serializer {
    pub fn new() -> Self {
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

        thread::spawn(move || loop {
            match rx.recv() {
                Ok(message) => match message.as_str() {
                    "initialize" => {
                        println!("Serializer initialized");
                    }
                    "write_config" => Serializer::write_config(),
                    "exit" => {
                        println!("Exiting serializer thread");
                        break;
                    }
                    _ => {
                        println!("Received unsupported message: {}", message);
                    }
                },
                Err(_) => {}
            }
        });

        Serializer { tx }
    }

    pub fn mpsc_send(&self, message: String) {
        if let Err(e) = self.tx.send(message) {
            eprintln!("error sending message: {}", e);
        }
    }

    fn write_config() {
        let zones = Serializer::get_zones(&DATABASE_POOL);

        let bind_config_path_env = get_env("BIND_CONFIG_PATH");
        let bind_config_path = Path::new(&bind_config_path_env);
        if !bind_config_path.is_dir() {
            eprintln!(
                "Bind config path is not a directory: {}",
                bind_config_path_env
            );
            return;
        }
        if !bind_config_path.exists() {
            eprintln!("Bind config path does not exist: {}", bind_config_path_env);
            return;
        }

        std::fs::remove_dir_all(&bind_config_path).unwrap_or_else(|_| {
            eprintln!("Failed to remove directory: {}", bind_config_path.display());
        });

        std::fs::create_dir_all(&bind_config_path).unwrap_or_else(|_| {
            eprintln!("Failed to create directory: {}", bind_config_path.display());
        });

        for zone in zones {
            let records = Serializer::get_records(&DATABASE_POOL, Some(zone.id));
            let serialized_data = Serializer::serialize_zone(&zone, &records);

            let file_path = format!("{}/{}.zone", bind_config_path.display(), zone.name);
            std::fs::write(file_path, serialized_data).unwrap_or_else(|_| {
                eprintln!("Failed to write to file: {}", zone.name);
            });
        }
    }

    fn get_zones(pool: &DatabasePool) -> Vec<Zone> {
        let query = "SELECT * FROM zones";
        pool.get_connection()
            .query_map(query, |row: mysql::Row| Zone::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    fn get_records(pool: &DatabasePool, zone_id: Option<i32>) -> Vec<Record> {
        let query = match zone_id {
            Some(id) => format!("SELECT * FROM records WHERE zone_id = {}", id),
            None => "SELECT * FROM records".to_string(),
        };

        pool.get_connection()
            .query_map(query, |row: mysql::Row| Record::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn serialize_zone(zone: &Zone, records: &[Record]) -> String {
        let mut output = String::new();

        // SOA 레코드
        writeln!(
            &mut output,
            r#"
; Automatically generated zone file
$TTL {}
{}.   IN  SOA {} {} (
        {} ; serial
        {} ; refresh
        {} ; retry
        {} ; expire
        {} ) ; minimum TTL
"#,
            zone.ttl,
            zone.name,
            zone.primary_ns,
            zone.admin_email.replace("@", "."),
            zone.serial,
            zone.refresh,
            zone.retry,
            zone.expire,
            zone.minimum_ttl,
        )
        .unwrap();

        // NS 레코드
        writeln!(&mut output, "@   IN  NS  ns1.{}.", zone.name).unwrap();

        for record in records {
            let name = if record.name == "@" {
                "@".to_string()
            } else {
                format!("{}.", record.name)
            };

            match record.record_type {
                RecordType::A
                | RecordType::AAAA
                | RecordType::CNAME
                | RecordType::TXT
                | RecordType::NS
                | RecordType::PTR => {
                    writeln!(
                        &mut output,
                        "{} {} IN {:?} {}",
                        name, record.ttl, record.record_type, record.value
                    )
                    .unwrap();
                }
                RecordType::MX => {
                    let priority = record.priority.unwrap_or(10);
                    writeln!(
                        &mut output,
                        "{} {} IN MX {} {}",
                        name, record.ttl, priority, record.value
                    )
                    .unwrap();
                }
                RecordType::SRV => {
                    // SRV는 priority, weight, port, target 순
                    // 예: _sip._tcp 3600 IN SRV 10 60 5060 sipserver.example.com.
                    let parts: Vec<&str> = record.value.split_whitespace().collect();
                    if parts.len() == 3 {
                        writeln!(
                            &mut output,
                            "{} {} IN SRV {} {} {} {}",
                            name,
                            record.ttl,
                            record.priority.unwrap_or(10), // default priority
                            parts[0],                      // weight
                            parts[1],                      // port
                            parts[2],                      // target
                        )
                        .unwrap();
                    }
                }
                RecordType::SOA => {
                    // 보통 SOA는 자동 생성되므로 무시하거나 따로 처리
                    writeln!(
                        &mut output,
                        "{} {} IN SOA {}",
                        name, record.ttl, record.value
                    )
                    .unwrap();
                }
            }
        }

        output
    }
}

lazy_static! {
    pub static ref SERIALIZER: Serializer = Serializer::new();
}
