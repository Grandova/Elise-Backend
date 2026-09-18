use crate::panel::types::{NodeInfo, User};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicProtocolVersion {
    V4,
    V5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicCongestionControl {
    Bbr,
    Cubic,
    NewReno,
}

impl TuicCongestionControl {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "bbr" => Ok(Self::Bbr),
            "cubic" => Ok(Self::Cubic),
            "new_reno" | "newreno" => Ok(Self::NewReno),
            other => Err(format!(
                "Unknown or unsupported congestion control: {}",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}

impl TuicUdpRelayMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "quic" => Self::Quic,
            _ => Self::Native,
        }
    }
}

use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct TuicTlsConfig {
    pub certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub private_key: Arc<rustls::pki_types::PrivateKeyDer<'static>>,
    pub alpn: Vec<Vec<u8>>,
    pub ech_server: Option<EchServerConfig>,
}

#[derive(Debug, Clone)]
pub struct EchServerConfig {
    pub key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EchClientConfig {
    pub enabled: bool,
    pub config: Option<Vec<u8>>,
    pub query_server_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TuicClientProfile {
    pub sni: Option<String>,
    pub allow_insecure: bool,
    pub ech: Option<EchClientConfig>,
    pub alpn: Vec<String>,
    pub udp_relay_mode: TuicUdpRelayMode,
}

#[derive(Debug, Clone)]
pub struct TuicRuntimeConfig {
    pub listen_addr: String,
    pub port: u16,
    pub auth_timeout: Duration,
    pub heartbeat: Duration,
    pub zero_rtt: bool,
    pub max_udp_relay_packet_size: usize,
}

#[derive(Debug, Clone)]
pub enum TuicCredential {
    V4 { token: String, token_hash: [u8; 32] },
    V5 { uuid: [u8; 16], password: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct TuicUsers {
    pub v4_tokens: HashMap<[u8; 32], (User, String)>,
    pub v5_users: HashMap<[u8; 16], (User, Vec<u8>)>,
}

impl Default for TuicUsers {
    fn default() -> Self {
        Self {
            v4_tokens: HashMap::new(),
            v5_users: HashMap::new(),
        }
    }
}

impl TuicUsers {
    pub fn from_users(users: Vec<User>, version: TuicProtocolVersion) -> Self {
        let mut v4_tokens = HashMap::new();
        let mut v5_users = HashMap::new();

        for u in users {
            match version {
                TuicProtocolVersion::V4 => {
                    let token = u.password.clone().unwrap_or_else(|| u.uuid.clone());
                    let hash = *blake3::hash(token.as_bytes()).as_bytes();
                    v4_tokens.insert(hash, (u, token));
                }
                TuicProtocolVersion::V5 => {
                    if let Ok(parsed_uuid) = Uuid::parse_str(&u.uuid) {
                        let uuid_bytes = *parsed_uuid.as_bytes();
                        let pass_bytes = u
                            .password
                            .as_ref()
                            .map(|p| p.as_bytes().to_vec())
                            .unwrap_or_else(|| u.uuid.as_bytes().to_vec());
                        v5_users.insert(uuid_bytes, (u, pass_bytes));
                    }
                }
            }
        }

        Self {
            v4_tokens,
            v5_users,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TuicNodeConfig {
    pub protocol: TuicProtocolVersion,
    pub congestion: TuicCongestionControl,
    pub tls: TuicTlsConfig,
    pub client_profile: TuicClientProfile,
    pub runtime: TuicRuntimeConfig,
}

impl TuicNodeConfig {
    pub fn from_node_info(
        node_info: &NodeInfo,
        listen_addr: &str,
        port: u16,
    ) -> Result<Self, String> {
        // 1. Protocol Version
        let protocol = match node_info.version.unwrap_or(5) {
            4 => TuicProtocolVersion::V4,
            5 => TuicProtocolVersion::V5,
            other => return Err(format!("Unsupported TUIC version: {}", other)),
        };

        // 2. Congestion Control
        let congestion_str = node_info.congestion_control.as_deref().unwrap_or("cubic");
        let congestion = TuicCongestionControl::parse(congestion_str)?;

        // 3. ALPN
        let mut alpn_strings = Vec::new();
        if let Some(alpn_val) = &node_info.alpn {
            if let Some(arr) = alpn_val.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        alpn_strings.push(s.to_string());
                    }
                }
            } else if let Some(s) = alpn_val.as_str() {
                alpn_strings.push(s.to_string());
            }
        }
        if alpn_strings.is_empty() {
            alpn_strings.push("h3".to_string());
        }

        let alpn_bytes: Vec<Vec<u8>> = alpn_strings.iter().map(|s| s.as_bytes().to_vec()).collect();

        // 4. Certificates & Private Key
        let mut certs = Vec::new();
        let mut key_opt = None;

        if let Some(cert_val) = &node_info.cert_config {
            if let Some(cert_str) = cert_val.get("cert").and_then(|v| v.as_str()) {
                if let Ok(c) = crate::security::tls::parse_pem_certificates(cert_str) {
                    certs = c;
                }
            }
            if let Some(key_str) = cert_val.get("key").and_then(|v| v.as_str()) {
                if let Ok(k) = crate::security::tls::parse_pem_private_key(key_str) {
                    key_opt = Some(k);
                }
            }
        }

        if certs.is_empty() || key_opt.is_none() {
            let sni = node_info
                .server_name
                .as_deref()
                .or_else(|| node_info.host.as_deref())
                .unwrap_or("tuic.local");

            let mut params = rcgen::CertificateParams::new(vec![
                sni.to_string(),
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ])
            .map_err(|e| format!("Failed to build certificate params: {}", e))?;
            params.not_before = rcgen::date_time_ymd(2024, 1, 1);
            params.not_after = rcgen::date_time_ymd(2034, 1, 1);

            let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(|e| format!("Failed to generate self-signed key pair: {}", e))?;
            let cert = params
                .self_signed(&key_pair)
                .map_err(|e| format!("Failed to generate self-signed cert: {}", e))?;

            certs = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
            key_opt = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
            ));
        }

        let private_key = Arc::new(key_opt.unwrap());

        // 5. Server ECH
        let mut ech_server = None;
        let mut ech_client = None;

        if let Some(tls_val) = &node_info.tls_settings {
            if let Some(ech_val) = tls_val.get("ech") {
                let enabled = ech_val
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let config = ech_val
                    .get("config")
                    .and_then(|v| v.as_str())
                    .map(|s| s.as_bytes().to_vec());
                let query_server_name = ech_val
                    .get("query_server_name")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                if enabled {
                    ech_client = Some(EchClientConfig {
                        enabled: true,
                        config,
                        query_server_name,
                    });

                    if let Some(key_str) = ech_val.get("key").and_then(|v| v.as_str()) {
                        ech_server = Some(EchServerConfig {
                            key: key_str.as_bytes().to_vec(),
                        });
                    }
                }
            }
        }

        let tls = TuicTlsConfig {
            certificates: certs,
            private_key,
            alpn: alpn_bytes,
            ech_server,
        };

        // 6. Client Profile
        let udp_relay_mode =
            TuicUdpRelayMode::parse(node_info.udp_relay_mode.as_deref().unwrap_or("native"));

        let allow_insecure = node_info
            .tls_settings
            .as_ref()
            .and_then(|v| v.get("allow_insecure"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let client_profile = TuicClientProfile {
            sni: node_info.server_name.clone(),
            allow_insecure,
            ech: ech_client,
            alpn: alpn_strings,
            udp_relay_mode,
        };

        // 7. Runtime Config
        let auth_timeout = node_info
            .auth_timeout
            .as_deref()
            .and_then(|s| parse_duration_string(s))
            .unwrap_or(Duration::from_secs(3));

        let heartbeat = node_info
            .heartbeat
            .as_deref()
            .and_then(|s| parse_duration_string(s))
            .unwrap_or(Duration::from_secs(3));

        let zero_rtt = node_info.zero_rtt_handshake.unwrap_or(false);

        let runtime = TuicRuntimeConfig {
            listen_addr: listen_addr.to_string(),
            port,
            auth_timeout,
            heartbeat,
            zero_rtt,
            max_udp_relay_packet_size: 1400,
        };

        Ok(Self {
            protocol,
            congestion,
            tls,
            client_profile,
            runtime,
        })
    }
}

fn parse_duration_string(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.ends_with('s') {
        s[..s.len() - 1]
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
    } else if s.ends_with("ms") {
        s[..s.len() - 2]
            .parse::<u64>()
            .ok()
            .map(Duration::from_millis)
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}
