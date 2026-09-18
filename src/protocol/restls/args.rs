use super::utils::Line;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Script(Vec<Line>);

impl Script {
    pub fn get_line(&self, index: usize) -> Option<&Line> {
        self.0.get(index)
    }
}

pub struct Config {
    pub host: String,
    pub port: u16,
    pub password: [u8; 32],
    pub script: Script,
    pub min_record_len: usize,
}

impl Config {
    pub fn new(opts: &HashMap<String, String>) -> Result<Self> {
        let address = opts
            .get("host")
            .or(opts.get("tls"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("ResTLS host is required"))?;
        let (host, port) = match address.rsplit_once(':') {
            Some((host, port)) => (
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
                port.parse::<u16>()?,
            ),
            None => (address.clone(), 443),
        };
        if host.is_empty() || port == 0 {
            return Err(anyhow!("Invalid ResTLS handshake address"));
        }
        let password = opts
            .get("password")
            .or(opts.get("passwd"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("ResTLS password is required"))?;
        let script = opts.get("script").map(String::as_str).unwrap_or(
            "200?100,200?100,1200?200<1,1100~300,1000~100<1,2500~500,1300~50,1300~50,100~1200",
        );
        let script = script
            .replace(' ', "")
            .split(',')
            .map(Line::from_str)
            .collect::<Result<Vec<_>>>()?;
        if script.len() > 1024 {
            return Err(anyhow!("ResTLS script exceeds 1024 records"));
        }
        let min_record_len = opts
            .get("min-record-len")
            .map(String::as_str)
            .unwrap_or("15")
            .parse::<usize>()?;
        if min_record_len == 0 || min_record_len > super::common::BUF_SIZE - 125 {
            return Err(anyhow!("Invalid ResTLS minimum record length"));
        }
        Ok(Self {
            host,
            port,
            password: blake3::derive_key("restls-traffic-key", password.as_bytes()),
            script: Script(script),
            min_record_len,
        })
    }
}
