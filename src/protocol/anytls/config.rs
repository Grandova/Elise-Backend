use super::padding::CompiledPaddingScheme;
use crate::panel::types::NodeInfo;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AnyTlsNodeConfig {
    pub protocol: AnyTlsProtocolConfig,
    pub tls: TlsServerConfig,
    pub client_profile: Option<AnyTlsClientProfile>,
}

#[derive(Debug, Clone)]
pub struct AnyTlsProtocolConfig {
    pub padding_scheme: Arc<CompiledPaddingScheme>,
}

#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    pub server_name: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub ech: Option<EchServerConfig>,
}

#[derive(Debug, Clone)]
pub enum EchServerKeySource {
    Inline(Vec<u8>),

    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct EchServerConfig {
    pub key_source: EchServerKeySource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyTlsClientProfile {
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Option<Vec<String>>,
    pub ech: Option<EchClientConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchClientConfig {
    pub enabled: bool,
    pub config: Option<String>,
    pub config_path: Option<String>,
    pub query_server_name: Option<String>,
}

impl AnyTlsNodeConfig {
    pub fn from_node_info(node_info: &NodeInfo) -> Result<Self, String> {
        let raw_scheme = match &node_info.padding_scheme {
            Some(serde_json::Value::Array(arr)) => {
                let lines: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                lines.join("\n")
            }
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => String::new(),
        };

        let padding_scheme = if raw_scheme.trim().is_empty() {
            Arc::new(CompiledPaddingScheme::parse(
                super::padding::DEFAULT_PADDING_SCHEME,
            )?)
        } else {
            Arc::new(CompiledPaddingScheme::parse(&raw_scheme)?)
        };

        let tls_val = node_info.tls_settings.as_ref();
        let server_name = node_info.server_name.clone().or_else(|| {
            tls_val
                .and_then(|v| v.get("server_name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });

        let alpn = tls_val
            .and_then(|v| v.get("alpn"))
            .and_then(|v| {
                if let Some(arr) = v.as_array() {
                    Some(
                        arr.iter()
                            .filter_map(|item| item.as_str().map(|s| s.as_bytes().to_vec()))
                            .collect(),
                    )
                } else if let Some(s) = v.as_str() {
                    Some(vec![s.as_bytes().to_vec()])
                } else {
                    None
                }
            })
            .unwrap_or_else(|| vec![b"h3".to_vec()]);

        let ech_val = tls_val.and_then(|v| v.get("ech"));
        let ech_server = ech_val.and_then(|v| {
            if let Some(key_str) = v.get("key").and_then(|k| k.as_str()) {
                if !key_str.is_empty() {
                    return Some(EchServerConfig {
                        key_source: EchServerKeySource::Inline(key_str.as_bytes().to_vec()),
                    });
                }
            }
            if let Some(path_str) = v.get("key_path").and_then(|k| k.as_str()) {
                if !path_str.is_empty() {
                    return Some(EchServerConfig {
                        key_source: EchServerKeySource::File(PathBuf::from(path_str)),
                    });
                }
            }
            None
        });

        let ech_client = ech_val.and_then(|v| {
            let enabled = v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
            if enabled {
                Some(EchClientConfig {
                    enabled: true,
                    config: v.get("config").and_then(|c| c.as_str()).map(String::from),
                    config_path: v
                        .get("config_path")
                        .and_then(|c| c.as_str())
                        .map(String::from),
                    query_server_name: v
                        .get("query_server_name")
                        .and_then(|q| q.as_str())
                        .map(String::from),
                })
            } else {
                None
            }
        });

        let client_profile = Some(AnyTlsClientProfile {
            server_name: server_name.clone(),
            insecure: tls_val
                .and_then(|v| v.get("allow_insecure"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            alpn: Some(vec!["h3".to_string()]),
            ech: ech_client,
        });

        Ok(Self {
            protocol: AnyTlsProtocolConfig { padding_scheme },
            tls: TlsServerConfig {
                server_name,
                alpn,
                ech: ech_server,
            },
            client_profile,
        })
    }
}
