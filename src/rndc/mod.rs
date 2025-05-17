mod internal;

use base64::engine::general_purpose;
use base64::Engine;
use hmac::Hmac;
use indexmap::IndexMap;
use internal::{RNDCPayload, RNDCValue};
use sha2::Sha256;
// use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env::get_env;

type HmacSha256 = Hmac<Sha256>;

pub struct Rndc {
    server_url: String,
    secret_key: Vec<u8>,
    nonce: Option<String>,
    stream: Option<TcpStream>,
}

// fn write_hex_to_file(data: &[u8], path: &str) -> std::io::Result<()> {
//     let hex_str = hex::encode(data); // binary -> hex string
//     let mut file = File::create(path)?;
//     file.write_all(hex_str.as_bytes())?;
//     Ok(())
// }

impl Rndc {
    pub fn new() -> Self {
        let server_url = get_env("RNDC_SERVER_URL");
        let secret_key_b64 = get_env("RNDC_SECRET_KEY");

        let secret_key = general_purpose::STANDARD
            .decode(secret_key_b64.as_bytes())
            .expect("Invalid base64 RNDC_SECRET_KEY");

        Rndc {
            server_url,
            secret_key,
            stream: None,
            nonce: None,
        }
    }

    pub fn rndc_handshake(&mut self) {
        println!("Performing RNDC handshake...");
        let msg = build_rndc_message("null", &self.secret_key, None, rand::random());

        // Save the message to a file for debugging
        // let hex_path = "rdata.hex";
        // write_hex_to_file(&msg, hex_path).unwrap();

        self.stream = Some(TcpStream::connect(&self.server_url).unwrap());

        if let Some(ref mut stream) = self.stream {
            stream.write_all(&msg).unwrap();

            let res = read_packet(&mut self.stream.as_mut().unwrap())
                .map_err(|e| format!("Failed to read packet: {}", e))
                .unwrap();

            self.handle_packet(&res).unwrap();
        } else {
            panic!("Failed to create TCP stream");
        }
    }

    pub fn rndc_command(&mut self, command: &str) {
        self.rndc_handshake();

        let msg = build_rndc_message(
            command,
            &self.secret_key,
            self.nonce.as_deref(),
            rand::random(),
        );

        if let Some(ref mut stream) = self.stream {
            println!("Sending RNDC command: {}", command);

            stream.write_all(&msg).unwrap();

            let res = read_packet(&mut self.stream.as_mut().unwrap())
                .map_err(|e| format!("Failed to read packet: {}", e))
                .unwrap();

            self.handle_packet(&res).unwrap();
        } else {
            panic!("Failed to create TCP stream");
        }
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        let resp = internal::decode(packet)?;
        if let Some(ctrl) = resp.get("_ctrl") {
            if let RNDCPayload::Table(ctrl_map) = ctrl {
                if let Some(RNDCPayload::String(new_nonce)) = ctrl_map.get("_nonce") {
                    println!("Received nonce: {:?}", new_nonce);
                    self.nonce = Some(new_nonce.to_string());
                }
            }
        }

        if self.nonce.is_none() {
            return Err("RNDC nonce not received".to_string());
        }

        if let Some(data) = resp.get("_data") {
            dbg!("Received data: {:?}", data);
        }

        Ok(())
    }
}

fn get_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn build_rndc_message(command: &str, secret: &[u8], nonce: Option<&str>, ser: u32) -> Vec<u8> {
    let now = get_timestamp();
    let exp = now + 60;

    let mut ctrl_map = IndexMap::new();
    ctrl_map.insert(
        "_ser".to_string(),
        RNDCValue::Binary(ser.to_string().into_bytes()),
    );
    ctrl_map.insert(
        "_tim".to_string(),
        RNDCValue::Binary(now.to_string().into_bytes()),
    );
    ctrl_map.insert(
        "_exp".to_string(),
        RNDCValue::Binary(exp.to_string().into_bytes()),
    );
    if let Some(nonce) = nonce {
        ctrl_map.insert(
            "_nonce".to_string(),
            RNDCValue::Binary(nonce.as_bytes().to_vec()),
        );
    }

    let mut data_map = IndexMap::new();
    data_map.insert(
        "type".to_string(),
        RNDCValue::Binary(command.as_bytes().to_vec()),
    );

    // message_body = {_ctrl, _data}
    let mut message_body = IndexMap::new();
    message_body.insert("_ctrl".to_string(), RNDCValue::Table(ctrl_map));
    message_body.insert("_data".to_string(), RNDCValue::Table(data_map));

    internal::encode(&mut message_body, secret)
}

fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).unwrap();

    let length_field = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) - 4;
    let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    let mut payload = vec![0u8; length_field as usize];
    stream.read_exact(&mut payload).unwrap();

    let mut full_packet = Vec::with_capacity(8 + payload.len());
    full_packet.extend_from_slice(&header);
    full_packet.extend_from_slice(&payload);

    Ok(full_packet)
}
