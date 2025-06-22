use crate::database::model::{
    record::{Record, RecordType},
    zone::Zone,
};
use crate::database::{DATABASE_POOL, DatabasePool};
use crate::{config, log_error, log_info};
use lazy_static::lazy_static;
use mysql::prelude::*;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::{fs, thread};

struct Message {
    msg: String,
    ack: Option<Sender<()>>, // Optional acknowledgment channel
}

pub fn initialize() {
    log_info!("Serializer initialized");
    lazy_static::initialize(&SERIALIZER);
}

pub fn shutdown() {
    log_info!("Shutting down serializer");

    if let Err(e) = SERIALIZER.send_message_and_wait("exit") {
        log_error!("Failed to send exit message: {}", e);
    }
}

pub struct Serializer {
    tx: Sender<Message>,
}

impl Serializer {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();

        // Spawn worker thread
        thread::spawn(move || Self::worker_thread(rx));

        Serializer { tx }
    }

    // Worker thread that processes messages
    fn worker_thread(rx: Receiver<Message>) {
        loop {
            match rx.recv() {
                Ok(Message { msg, ack }) => match msg.as_str() {
                    "write_config" => {
                        if let Err(e) = Self::write_config() {
                            log_error!("Failed to write config: {}", e);
                        }

                        if let Some(ack) = ack {
                            let _ = ack.send(()); // ACK even on failure
                        }
                    }
                    "exit" => {
                        if let Some(ack) = ack {
                            let _ = ack.send(()); // ACK before exit
                        }
                        break;
                    }
                    _ => {
                        println!("Received unsupported message: {}", msg);
                    }
                },
                Err(e) => {
                    log_error!("Error receiving message: {}", e);
                    break;
                }
            }
        }
    }

    // Send message to worker thread
    pub fn _send_message(&self, message: &str) {
        let msg = Message {
            msg: message.to_string(),
            ack: None,
        };
        if let Err(e) = self.tx.send(msg) {
            log_error!("Error sending message: {}", e);
        }
    }

    // Send message with acknowledgment
    pub fn send_message_and_wait(&self, message: &str) -> Result<(), String> {
        let (ack_tx, ack_rx) = mpsc::channel();

        let msg = Message {
            msg: message.to_string(),
            ack: Some(ack_tx),
        };
        if self.tx.send(msg).is_err() {
            return Err("Failed to send message".to_string());
        }

        // Wait for acknowledgment
        ack_rx
            .recv()
            .map_err(|e| format!("Failed to receive acknowledgment: {}", e))?;
        Ok(())
    }

    // Write DNS configuration files
    fn write_config() -> Result<(), String> {
        let zones = Self::get_zones(&DATABASE_POOL);

        let bind_config_path_str = config::get_config::<String>("bind.bind_config_path");
        let bind_config_path = PathBuf::from(&bind_config_path_str);
        if !bind_config_path.is_dir() {
            return Err(format!(
                "Bind config path is not a directory: {}",
                bind_config_path_str
            ));
        }
        if !bind_config_path.exists() {
            return Err(format!(
                "Bind config path does not exist: {}",
                bind_config_path_str
            ));
        }

        // Prepare directory for writing
        let bindizr_config_path = bind_config_path.join("bindizr");
        if bindizr_config_path.exists() && fs::remove_dir_all(&bindizr_config_path).is_err() {
            return Err(format!(
                "Failed to remove existing bindizr config directory: {}",
                bindizr_config_path.display()
            ));
        }
        if fs::create_dir_all(&bindizr_config_path).is_err() {
            return Err(format!(
                "Failed to create bindizr config directory: {}",
                bindizr_config_path.display()
            ));
        }

        // Write include zone config file
        let include_zone_config =
            Self::serialize_include_zone_config(&bindizr_config_path.display().to_string(), &zones);
        if fs::write(
            bindizr_config_path.join("named.conf.bindizr"),
            include_zone_config,
        )
        .is_err()
        {
            return Err(format!(
                "Failed to write to file: {}",
                bindizr_config_path.join("named.conf.bindizr").display()
            ));
        }

        // Write zone files
        for zone in zones {
            let records = Self::get_records(&DATABASE_POOL, zone.id);
            let serialized_data = Self::serialize_zone(&zone, &records);

            let file_path = bindizr_config_path.join(format!("{}.zone", zone.name));
            if fs::write(file_path, serialized_data).is_err() {
                return Err(format!("Failed to write to file: {}", zone.name));
            }
        }

        Ok(())
    }

    fn get_zones(pool: &DatabasePool) -> Vec<Zone> {
        let mut conn = pool.get_connection();

        conn.exec_map(
            r#"
            SELECT *
            FROM zones
        "#,
            (),
            Zone::from_row,
        )
        .unwrap_or_else(|e| {
            log_error!("Failed to fetch zones: {}", e);
            Vec::new()
        })
    }

    fn get_records(pool: &DatabasePool, zone_id: i32) -> Vec<Record> {
        let mut conn = pool.get_connection();

        conn.exec_map(
            r#"
            SELECT *
            FROM records
            WHERE zone_id = ?
            ORDER BY record_type, name
        "#,
            (zone_id,),
            |row: mysql::Row| Record::from_row(row),
        )
        .unwrap_or_else(|e| {
            log_error!("Failed to fetch records for zone {}: {}", zone_id, e);
            Vec::new()
        })
    }

    fn serialize_include_zone_config(bindizr_config_dir: &str, zones: &[Zone]) -> String {
        let mut output = String::new();

        for zone in zones {
            writeln!(
                &mut output,
                "zone \"{}\" {{ type master; file \"{}/{}.zone\"; }};",
                zone.name, bindizr_config_dir, zone.name
            )
            .unwrap();
        }

        output
    }

    pub fn serialize_zone(zone: &Zone, records: &[Record]) -> String {
        let mut output = String::new();

        // SOA record
        writeln!(
            &mut output,
            r#"; Automatically generated zone file
$TTL {}
{}.   IN  SOA {}. {}. (
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

        // NS record
        writeln!(
            &mut output,
            r#"@   IN  NS  {}.
ns  IN  A   {}
"#,
            zone.primary_ns, zone.primary_ns_ip
        )
        .unwrap();

        for record in records {
            let name = if record.name == "@" {
                "@".to_string()
            } else {
                record.name.to_string()
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
                        "{} {} IN {} {}",
                        name,
                        record.ttl.map(|ttl| ttl.to_string()).unwrap_or_default(),
                        record.record_type,
                        record.value
                    )
                    .unwrap();
                }
                RecordType::MX => {
                    let priority = record.priority.unwrap_or(10);
                    writeln!(
                        &mut output,
                        "{} {} IN MX {} {}",
                        name,
                        record.ttl.map(|ttl| ttl.to_string()).unwrap_or_default(),
                        priority,
                        record.value
                    )
                    .unwrap();
                }
                RecordType::SRV => {
                    // SRV is in the order of priority, weight, port, and target.
                    // e.g.: _sip._tcp 3600 IN SRV 10 60 5060 sipserver.example.com.
                    let parts: Vec<&str> = record.value.split_whitespace().collect();
                    if parts.len() == 3 {
                        writeln!(
                            &mut output,
                            "{} {} IN SRV {} {} {} {}",
                            name,
                            record.ttl.map(|ttl| ttl.to_string()).unwrap_or_default(),
                            record.priority.unwrap_or(10), // default priority
                            parts[0],                      // weight
                            parts[1],                      // port
                            parts[2],                      // target
                        )
                        .unwrap();
                    }
                }
                RecordType::SOA => {
                    // Mostly SOA is automatically generated, so ignore it or process it separately.
                    writeln!(
                        &mut output,
                        "{} {} IN SOA {}",
                        name,
                        record.ttl.map(|ttl| ttl.to_string()).unwrap_or_default(),
                        record.value
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
