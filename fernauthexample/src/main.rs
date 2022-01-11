use fernet::Fernet;
use serde::{Deserialize, Serialize};
use serde_json;

use std::vec::Vec;

struct Service {
    inner_secret: Fernet,
    outer_secret: Fernet,
}

#[derive(Serialize, Deserialize, Debug)]
struct InnerPayload {
    claims: Vec<String>,
    service: String,
}

impl Service {
    pub fn new(inner_secret_str: &str, outer_secret_str: &str) -> Service {
        let is = Fernet::new(inner_secret_str).unwrap();
        let os = Fernet::new(outer_secret_str).unwrap();

        Service {
            inner_secret: is,
            outer_secret: os,
        }
    }

    pub fn gen_magic(&self, claims: Vec<String>, service_name: String) -> String {
        let ip = InnerPayload {
            claims: claims,
            service: service_name,
        };

        let j = serde_json::to_string(&ip).unwrap();

        self.inner_secret.encrypt(j.as_bytes())
    }

    pub fn decode_payload(&self, token: String) -> InnerPayload {
        let encrypted_magic_vec = self.outer_secret.decrypt(token.as_str()).unwrap();
        let encrypted_magic = std::str::from_utf8(&encrypted_magic_vec).unwrap();

        let payload = self.inner_secret.decrypt(encrypted_magic).unwrap();
        let payload_slice = &payload[..];

        let ip: InnerPayload = serde_json::from_slice(payload_slice).unwrap();

        ip
    }
}

struct Client {
    secret: Fernet,
    magic: String,
}

impl Client {
    pub fn new(secret_str: &str, magic: &str) -> Client {
        let os = Fernet::new(secret_str).unwrap();
        Client {
            secret: os,
            magic: String::from(magic),
        }
    }

    pub fn gen_api_token(self) -> String {
        self.secret.encrypt(&self.magic.as_bytes())
    }
}

fn main() {
    let inner_secret = Fernet::generate_key();
    let outer_secret = Fernet::generate_key();

    let serv = Service::new(&inner_secret, &outer_secret);

    let magic = serv.gen_magic(
        vec!["read".to_string(), "write".to_string()],
        "graham".to_string(),
    );

    let client = Client::new(&outer_secret, &magic);

    let apikey = client.gen_api_token();

    println!("Result: {:?}", serv.decode_payload(apikey));
}
