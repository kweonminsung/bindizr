use crate::config;
use crate::database::{
    model::{record::Record, record::RecordType, zone::Zone},
    {DatabasePool, DATABASE_POOL},
};
use lazy_static::lazy_static;
use mysql::prelude::*;
use std::fmt::Write;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

pub fn initialize() {
    SERIALIZER.mpsc_send("initialize");
    // SERIALIZER.mpsc_send("write_config");
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

    pub fn mpsc_send(&self, message: &str) {
        if let Err(e) = self.tx.send(message.to_string()) {
            eprintln!("error sending message: {}", e);
        }
    }

    fn write_config() {
        let zones = Serializer::get_zones(&DATABASE_POOL);

        let bind_config_path_env = config::get_config("bind.bind_config_path");
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

        let bindizr_config =
            Serializer::serialize_bindizr_config(&bind_config_path.display().to_string(), &zones);
        std::fs::write(
            format!("{}/named.conf.bindizr", bind_config_path.display()),
            bindizr_config,
        )
        .unwrap_or_else(|_| {
            eprintln!("Failed to write to file: named.conf.bindizr");
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
        let mut conn = pool.get_connection();

        conn.exec_map(
            r#"
            SELECT *
            FROM zones
        "#,
            (),
            |row| Zone::from_row(row),
        )
        .unwrap_or_else(|_| Vec::new())
    }

    fn get_records(pool: &DatabasePool, zone_id: Option<i32>) -> Vec<Record> {
        let mut conn = pool.get_connection();

        match zone_id {
            Some(id) => conn
                .exec_map(
                    r#"
                        SELECT *
                        FROM records
                        WHERE zone_id = ?
                    "#,
                    (id,),
                    |row: mysql::Row| Record::from_row(row),
                )
                .unwrap_or_else(|_| Vec::new()),
            None => conn
                .exec_map(
                    r#"
                    SELECT *
                    FROM records
                "#,
                    (),
                    |row: mysql::Row| Record::from_row(row),
                )
                .unwrap_or_else(|_| Vec::new()),
        }
    }

    fn serialize_bindizr_config(bind_config_dir: &str, zones: &[Zone]) -> String {
        let mut output = String::new();

        for zone in zones {
            writeln!(
                &mut output,
                "zone \"{}\" {{ type master; file \"{}/{}.zone\"; }};",
                zone.name, bind_config_dir, zone.name
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
            r#"
; Automatically generated zone file
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
            r#"
@   IN  NS  {}.
ns  IN  A   {}
"#,
            zone.primary_ns, zone.primary_ns_ip
        )
        .unwrap();

        for record in records {
            let name = if record.name == "@" {
                "@".to_string()
            } else {
                format!("{}", record.name)
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
                    // SRV is in the order of priority, weight, port, and target.
                    // ex: _sip._tcp 3600 IN SRV 10 60 5060 sipserver.example.com.
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
                    // mostly SOA is automatically generated, so ignore it or process it separately.
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
