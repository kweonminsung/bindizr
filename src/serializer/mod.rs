use crate::config::BINDIZR_CONF_DIR;
use crate::database::get_zone_repository;
use crate::database::{
    get_record_repository,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
};
use crate::{log_error, log_info};
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver, Sender};
use std::{fs, thread};

struct Message {
    msg: String,
    ack: Option<Sender<()>>, // Optional acknowledgment channel
}

pub fn initialize() {
    log_info!("Serializer initialized");
    SERIALIZER.get_or_init(Serializer::new);
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
    async fn worker_thread(rx: Receiver<Message>) {
        loop {
            match rx.recv() {
                Ok(Message { msg, ack }) => match msg.as_str() {
                    "write_config" => {
                        if let Err(e) = Self::write_config().await {
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
                        log_error!("Received unsupported message: {}", msg);
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
    async fn write_config() -> Result<(), String> {
        let zones = Self::get_zones().await;

        let bindizr_config_dir = PathBuf::from(BINDIZR_CONF_DIR);
        if !bindizr_config_dir.exists() {
            return Err(format!(
                "Bindizr config directory does not exist: {}",
                BINDIZR_CONF_DIR
            ));
        }

        println!("====================================1");
        // Prepare directory for writing
        let zone_config_dir = bindizr_config_dir.join("zones");
        if zone_config_dir.exists() && fs::remove_dir_all(&zone_config_dir).is_err() {
            return Err(format!(
                "Failed to remove existing zone config directory: {}",
                zone_config_dir.display()
            ));
        }
        if fs::create_dir_all(&zone_config_dir).is_err() {
            return Err(format!(
                "Failed to create zone config directory: {}",
                zone_config_dir.display()
            ));
        }
        println!("====================================2");
        // Write include zone config file
        let include_zone_config =
            Self::serialize_include_zone_config(&zone_config_dir.display().to_string(), &zones);
        if fs::write(zone_config_dir.join("named.conf"), include_zone_config).is_err() {
            return Err(format!(
                "Failed to write to file: {}",
                zone_config_dir.join("named.conf").display()
            ));
        }
        println!("====================================3");
        // Write zone files
        for zone in zones {
            let records = Self::get_records(zone.id).await;
            let serialized_data = Self::serialize_zone(&zone, &records);

            let file_path = zone_config_dir.join(format!("{}.zone", zone.name));
            if fs::write(file_path, serialized_data).is_err() {
                return Err(format!("Failed to write to file: {}", zone.name));
            }
        }

        Ok(())
    }

    async fn get_zones() -> Vec<Zone> {
        let zone_repository = get_zone_repository();

        zone_repository.get_all().await.unwrap_or_else(|e| {
            log_error!("Failed to fetch zones: {}", e);
            Vec::new()
        })
    }

    async fn get_records(zone_id: i32) -> Vec<Record> {
        let record_repository = get_record_repository();

        record_repository
            .get_by_zone_id(zone_id)
            .await
            .unwrap_or_else(|e| {
                log_error!("Failed to fetch records for zone {}: {}", zone_id, e);
                Vec::new()
            })
    }

    fn serialize_include_zone_config(zone_config_dir: &str, zones: &[Zone]) -> String {
        let mut output = String::new();

        for zone in zones {
            writeln!(
                &mut output,
                "zone \"{}\" {{ type master; file \"{}/{}.zone\"; }};",
                zone.name, zone_config_dir, zone.name
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

pub static SERIALIZER: OnceLock<Serializer> = OnceLock::new();

pub fn get_serializer() -> &'static Serializer {
    SERIALIZER.get().expect("Serializer is not initialized")
}
