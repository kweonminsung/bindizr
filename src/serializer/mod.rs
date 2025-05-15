use crate::database::model::{record::Record, record::RecordType, zone::Zone};
// use crate::env::get_env;
use lazy_static::lazy_static;
use std::fmt::Write;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

pub fn initialize() {
    SERIALIZER.mpsc_send("initialize".to_string());
}

pub struct Serializer {
    tx: Sender<String>,
}

impl Serializer {
    pub fn new() -> Self {
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

        // 데몬 스레드 시작
        thread::spawn(move || loop {
            match rx.recv() {
                Ok(message) => {
                    match message.as_str() {
                        "initialize" => {
                            println!("Serializer initialized");
                        }
                        "overwrite" => {}
                        "exit" => {
                            break; // 스레드 종료
                        }
                        _ => {
                            println!("Received unexpected message: {}", message);
                        }
                    }
                }
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

    pub fn serialize_zone(zone: &Zone, records: &[Record]) -> String {
        let mut output = String::new();

        // SOA 레코드
        writeln!(
            &mut output,
            r#"
$TTL {}
{}   IN  SOA {} {} (
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
