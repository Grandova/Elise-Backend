use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSConfig {
    #[serde(default = "default_dns_strategy")]
    pub strategy: String,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    #[serde(default)]
    pub servers: Vec<DNSServerConfig>,
    #[serde(default)]
    pub rules: Vec<DNSRuleConfig>,
}

fn default_dns_strategy() -> String {
    "prefer_ipv4".to_string()
}

fn default_cache_ttl() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSServerConfig {
    pub tag: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSRuleConfig {
    #[serde(default)]
    pub domains: Vec<String>,
    pub server: String,
}

impl Default for DNSConfig {
    fn default() -> Self {
        Self {
            strategy: "prefer_ipv4".to_string(),
            cache_ttl: 300,
            servers: vec![
                DNSServerConfig {
                    tag: "domestic".to_string(),
                    address: "udp://223.5.5.5:53".to_string(),
                },
                DNSServerConfig {
                    tag: "google".to_string(),
                    address: "https://dns.google/dns-query".to_string(),
                },
            ],
            rules: vec![DNSRuleConfig {
                domains: vec!["*".to_string()],
                server: "domestic".to_string(),
            }],
        }
    }
}

impl DNSConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Self {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(cfg) = serde_yaml::from_str::<DNSConfig>(&content) {
                return cfg;
            }
        }
        Self::default()
    }
}
