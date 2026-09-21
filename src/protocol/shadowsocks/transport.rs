use super::shadowtls::ShadowTls;

pub enum Accepted {
    Stream(BoxedStream),
    Fallback(BoxedStream, BoxedStream),
    Restls(Box<crate::protocol::restls::Session>),
}
use crate::conn::{BoxedStream, PrefixedStream};
use crate::panel::types::NodeInfo;
use crate::security::TLSManager;
use base64::Engine;
use bytes::{Buf, Bytes};
use futures_util::{ready, Sink, Stream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::{
    handshake::server::{Request, Response},
    Message,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    None,
    ObfsHttp,
    ObfsTls,
    Tls,
    WebSocket,
    Http2,
    ShadowTls,
    Restls,
    Quic,
    Kcptun,
}

pub struct Transport {
    pub mux: Option<super::mux::Mux>,
    pub grpc: bool,
    shadow: Option<ShadowTls>,
    restls: Option<crate::protocol::restls::Config>,
    gost: bool,
    mode: Mode,
    tls: Option<TlsAcceptor>,
    host: Option<String>,
    pub path: String,
    pub opts: HashMap<String, String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl Transport {
    pub fn validate(node: &NodeInfo) -> io::Result<()> {
        Self::options(node).map(|_| ())
    }

    pub(crate) fn options(node: &NodeInfo) -> io::Result<(Mode, bool, HashMap<String, String>)> {
        let mut opts = HashMap::new();
        match &node.plugin_opts {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(value)) => {
                for field in value.split(';').filter(|s| !s.is_empty()) {
                    let (key, value) = field.split_once('=').unwrap_or((field, "true"));
                    let key = key.trim().to_string();
                    let value = value
                        .trim()
                        .trim_matches(|c| c == '\'' || c == '"')
                        .trim()
                        .to_string();
                    if opts.insert(key, value).is_some() {
                        return Err(invalid("Duplicate plugin option"));
                    }
                }
            }
            Some(serde_json::Value::Object(value)) => {
                for (key, value) in value {
                    let key = key.trim().to_string();
                    let value = match value {
                        serde_json::Value::String(s) => s
                            .trim()
                            .trim_matches(|c| c == '\'' || c == '"')
                            .trim()
                            .to_string(),
                        serde_json::Value::Bool(v) => v.to_string(),
                        serde_json::Value::Number(v) => v.to_string(),
                        _ => return Err(invalid("Invalid plugin option type")),
                    };
                    opts.insert(key, value);
                }
            }
            _ => return Err(invalid("plugin_opts must be a string or object")),
        }
        let plugin = node
            .plugin
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .replace(' ', "");
        let is_simple_obfs = matches!(
            plugin.as_str(),
            "obfs"
                | "simpleobfs"
                | "simple-obfs"
                | "simple_obfs"
                | "obfs-local"
                | "obfs-server"
                | "obfs_local"
                | "obfs_server"
                | "obfslocal"
                | "obfsserver"
        );
        if is_simple_obfs {
            if let Some(m) = opts.get("obfs").cloned() {
                opts.entry("mode".into()).or_insert(m);
            } else if let Some(m) = opts.get("mode").cloned() {
                opts.entry("obfs".into()).or_insert(m);
            } else {
                opts.insert("mode".into(), "http".into());
                opts.insert("obfs".into(), "http".into());
            }
            if let Some(h) = opts.get("obfs-host").cloned() {
                opts.entry("host".into()).or_insert(h);
            } else if let Some(h) = opts.get("host").cloned() {
                opts.entry("obfs-host".into()).or_insert(h);
            }
        }
        if let Some(s) = opts
            .get("restls-script")
            .cloned()
            .or_else(|| opts.get("restls_script").cloned())
        {
            opts.entry("script".into()).or_insert(s);
        }
        if let Some(s) = opts.get("script").cloned() {
            opts.entry("restls-script".into()).or_insert(s.clone());
            opts.entry("restls_script".into()).or_insert(s);
        }
        let is_kcptun = matches!(
            plugin.as_str(),
            "kcptun" | "kcptunplugin" | "kcptun-plugin" | "kcptun_plugin"
        );
        if is_kcptun {
            if let Some(p) = opts
                .get("password")
                .cloned()
                .or_else(|| opts.get("passwd").cloned())
            {
                opts.entry("key".into()).or_insert(p);
            }
            if let Some(c) = opts.get("crypt").cloned() {
                let lower = c.to_ascii_lowercase();
                let norm: &str = match lower.as_str() {
                    "aes-128-gcm" | "aes-128-cfb" | "aes-128" => "aes-128",
                    "aes-192-gcm" | "aes-192-cfb" | "aes-192" => "aes-192",
                    "aes-256-gcm" | "aes-256-cfb" | "aes-256" | "aes" => "aes",
                    "salsa20" | "chacha20" | "chacha20-ietf-poly1305" => "salsa20",
                    "blowfish" => "blowfish",
                    "twofish" => "twofish",
                    "cast5" => "cast5",
                    "3des" | "tripledes" => "3des",
                    "tea" => "tea",
                    "xtea" => "xtea",
                    "sm4" => "sm4",
                    "xor" | "simplexor" => "xor",
                    "none" | "null" => "none",
                    _ => lower.as_str(),
                };
                opts.insert("crypt".into(), norm.to_string());
            }
        }
        if let Some(c) = opts.get("cert_file").cloned() {
            opts.entry("cert".into()).or_insert(c);
        }
        if let Some(c) = opts.get("certificate").cloned() {
            opts.entry("cert".into()).or_insert(c);
        }
        if let Some(k) = opts.get("key_file").cloned() {
            opts.entry("key".into()).or_insert(k);
        }
        let panel_tls = matches!(node.tls, Some(1 | 2))
            || (node.cert_config.is_some() && node.tls != Some(0))
            || (node.tls_settings.is_some() && node.tls != Some(0));
        let value = |name| opts.get(name).map(String::as_str);
        let (mode, tls, allowed): (Mode, bool, &[&str]) = match plugin.as_str() {
            "" | "none" if opts.is_empty() => (Mode::None, false, &[]),
            "restls" | "restlsplugin" | "restls-plugin" | "restls_plugin" => {
                crate::protocol::restls::Config::new(&opts).map_err(io::Error::other)?;
                (
                    Mode::Restls,
                    false,
                    &[
                        "host",
                        "tls",
                        "password",
                        "passwd",
                        "script",
                        "restls-script",
                        "restls_script",
                        "version-hint",
                        "version_hint",
                        "version",
                        "min-record-len",
                        "min_record_len",
                        "server",
                    ],
                )
            }
            "shadowtls" | "shadow-tls" => {
                ShadowTls::new(&opts)?;
                (
                    Mode::ShadowTls,
                    false,
                    &[
                        "v3", "version", "passwd", "password", "tls", "host", "strict", "server",
                    ],
                )
            }
            "obfs" | "simpleobfs" | "simple-obfs" | "simple_obfs" | "obfs-local"
            | "obfs-server" | "obfs_local" | "obfs_server" | "obfslocal" | "obfsserver" => {
                let mode = match value("obfs").or(value("mode")).unwrap_or("http") {
                    "http" => Mode::ObfsHttp,
                    "tls" => Mode::ObfsTls,
                    _ => return Err(unsupported("Unsupported Simple Obfs mode")),
                };
                (
                    mode,
                    false,
                    &["obfs", "mode", "obfs-host", "host", "server"],
                )
            }
            "v2rayplugin" | "v2ray-plugin" => {
                value("mux")
                    .unwrap_or("1")
                    .parse::<u16>()
                    .map_err(|_| invalid("Invalid V2Ray mux concurrency"))?;
                let mode = match value("mode").unwrap_or("websocket") {
                    "websocket" | "ws" => Mode::WebSocket,
                    "quic" if cfg!(feature = "quic-protocols") => Mode::Quic,
                    _ => return Err(unsupported("Unsupported V2Ray Plugin mode")),
                };
                let tls = match value("tls") {
                    Some(v) => flag(Some(v))?,
                    None => mode == Mode::Quic || panel_tls,
                };
                (
                    mode,
                    tls,
                    &[
                        "mode",
                        "tls",
                        "host",
                        "path",
                        "cert",
                        "key",
                        "cert_file",
                        "key_file",
                        "certificate",
                        "server",
                        "mux",
                    ],
                )
            }
            "gostplugin" | "gost-plugin" => {
                let (mode, mode_tls) = match value("mode").unwrap_or("ws") {
                    "tls" | "mtls" => (Mode::Tls, true),
                    "ws" | "mws" | "websocket" | "mwebsocket" => (Mode::WebSocket, false),
                    "wss" | "mwss" | "websockets" | "mwebsockets" | "websocket-secure" => {
                        (Mode::WebSocket, true)
                    }
                    "h2" | "grpc" | "gun" | "http2" => (Mode::Http2, true),
                    "quic" | "mquic" if cfg!(feature = "quic-protocols") => (Mode::Quic, true),
                    _ => return Err(unsupported("Unsupported GOST transport mode")),
                };
                let tls = match value("tls") {
                    Some(v) => flag(Some(v))?,
                    None => mode_tls || panel_tls,
                };
                (
                    mode,
                    tls,
                    &[
                        "mode",
                        "tls",
                        "host",
                        "path",
                        "cert",
                        "key",
                        "cert_file",
                        "key_file",
                        "certificate",
                        "server",
                        "serviceName",
                        "mux",
                        "nocomp",
                        "insecure",
                        "ed",
                        "fastopen",
                        "fast-open",
                        "logLevel",
                        "loglevel",
                        "vpn",
                    ],
                )
            }
            "kcptun" | "kcptunplugin" | "kcptun-plugin" | "kcptun_plugin" => {
                let crypt = value("crypt").unwrap_or("aes-128");
                match crypt {
                    "aes" | "aes-128" | "aes-192" | "aes-256" | "salsa20" | "blowfish"
                    | "twofish" | "cast5" | "3des" | "tea" | "xtea" | "sm4" | "xor" | "none"
                    | "null" => {}
                    _ => return Err(unsupported("Unsupported KCPTun crypt")),
                }
                (
                    Mode::Kcptun,
                    false,
                    &[
                        "key",
                        "password",
                        "passwd",
                        "crypt",
                        "mode",
                        "nocomp",
                        "mtu",
                        "sndwnd",
                        "rcvwnd",
                        "datashard",
                        "parityshard",
                        "dscp",
                        "nodelay",
                        "interval",
                        "resend",
                        "nc",
                        "sockbuf",
                        "smuxbuf",
                        "framesize",
                        "streambuf",
                        "smuxver",
                        "keepalive",
                        "acknodelay",
                        "server",
                        "target",
                        "ratelimit",
                        "quiet",
                        "pprof",
                        "bin",
                        "server_path",
                    ],
                )
            }
            _ => return Err(unsupported("Unsupported Shadowsocks plugin")),
        };
        if opts.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(unsupported("Unsupported plugin option"));
        }
        if value("server").is_some() && !flag(value("server"))? {
            return Err(invalid("Elise requires server plugin mode"));
        }
        if mode != Mode::Kcptun {
            if !tls && (value("cert").is_some() || value("key").is_some()) {
                return Err(invalid("Certificate configured for plaintext transport"));
            }
            if value("cert").is_some() != value("key").is_some() {
                return Err(invalid("Plugin cert and key must be configured together"));
            }
        }
        if value("serviceName").is_some() && !matches!(value("mode"), Some("grpc" | "gun")) {
            return Err(invalid("serviceName only applies to Gun transport"));
        }
        Ok((mode, tls, opts))
    }

    fn resolve_tls_cert_and_key(
        node: &NodeInfo,
        opts: &HashMap<String, String>,
        host: Option<&str>,
    ) -> Option<(
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        String,
        String,
    )> {
        let opt_cert = opts
            .get("cert")
            .or_else(|| opts.get("cert_file"))
            .or_else(|| opts.get("certificate"));
        let opt_key = opts.get("key").or_else(|| opts.get("key_file"));
        if let (Some(c), Some(k)) = (opt_cert, opt_key) {
            match crate::security::tls::load_cert_and_key(c, k) {
                Ok((certs, key)) => {
                    return Some((certs, key, c.clone(), k.clone()));
                }
                Err(e) => {
                    tracing::warn!(
                        stage = "certificate",
                        error = %e,
                        cert_source = %c,
                        key_source = %k,
                        "Failed to load certificate from plugin options"
                    );
                }
            }
        }

        if let Some((certs, key)) = crate::security::tls::resolve_node_certificate(node, host) {
            return Some((certs, key, "resolved".to_string(), "resolved".to_string()));
        }

        None
    }

    pub async fn new(node: &NodeInfo, manager: &TLSManager) -> io::Result<Self> {
        let (mode, use_tls, opts) = Self::options(node)?;
        let grpc = matches!(opts.get("mode").map(String::as_str), Some("grpc" | "gun"));
        let path = if grpc {
            let service = opts
                .get("serviceName")
                .map(String::as_str)
                .unwrap_or("GunService");
            if service.is_empty()
                || !service
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.')
            {
                return Err(invalid("Invalid Gun serviceName"));
            }
            format!("/{service}/Tun")
        } else {
            opts.get("path").cloned().unwrap_or_else(|| "/".into())
        };
        if !path.starts_with('/') || path.contains(['\r', '\n', '#', '?']) {
            return Err(invalid("Invalid plugin path"));
        }
        let host = opts
            .get("obfs-host")
            .or(opts.get("host"))
            .cloned()
            .filter(|s| !s.is_empty());

        let (tls, cert_path, key_path) = if use_tls {
            if let Some((certs, key, cp, kp)) =
                Self::resolve_tls_cert_and_key(node, &opts, host.as_deref())
            {
                let mut config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to configure TLS server certificate: {e}"),
                        )
                    })?;
                if mode == Mode::WebSocket {
                    config.alpn_protocols = vec![b"http/1.1".to_vec()];
                } else if mode == Mode::Http2 {
                    config.alpn_protocols = vec![b"h2".to_vec()];
                }
                tracing::info!(
                    plugin = ?node.plugin.as_deref().unwrap_or(""),
                    mode = ?mode,
                    tls = true,
                    host = ?host,
                    path = ?path,
                    tls_role = "server",
                    cert_path = %cp,
                    key_path = %kp,
                    alpn = ?config
                        .alpn_protocols
                        .iter()
                        .map(|p| String::from_utf8_lossy(p).to_string())
                        .collect::<Vec<_>>(),
                    "Configured TLS server certificate for transport"
                );
                (
                    Some(TlsAcceptor::from(Arc::new(config))),
                    Some(cp),
                    Some(kp),
                )
            } else {
                let acceptor = manager
                    .get_acceptor()
                    .ok_or_else(|| invalid("TLS transport requires a certificate"))?;
                tracing::warn!(
                    stage = "certificate",
                    host = ?host,
                    plugin = ?node.plugin.as_deref().unwrap_or(""),
                    mode = ?mode,
                    "No matching certificate found in opts, cert_config, tls_settings, or disk paths; falling back to default/self-signed acceptor"
                );
                let mut config = (**acceptor.config()).clone();
                if mode == Mode::WebSocket {
                    config.alpn_protocols = vec![b"http/1.1".to_vec()];
                } else if mode == Mode::Http2 {
                    config.alpn_protocols = vec![b"h2".to_vec()];
                }
                (Some(TlsAcceptor::from(Arc::new(config))), None, None)
            }
        } else {
            (None, None, None)
        };

        Ok(Self {
            restls: if mode == Mode::Restls {
                Some(crate::protocol::restls::Config::new(&opts).map_err(io::Error::other)?)
            } else {
                None
            },
            shadow: if mode == Mode::ShadowTls {
                Some(ShadowTls::new(&opts)?)
            } else {
                None
            },
            grpc,
            gost: matches!(
                node.plugin
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .replace(' ', "")
                    .as_str(),
                "gostplugin" | "gost-plugin"
            ),
            mux: if mode == Mode::WebSocket
                && matches!(
                    node.plugin
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .replace(' ', "")
                        .as_str(),
                    "v2rayplugin" | "v2ray-plugin"
                ) {
                (!matches!(
                    opts.get("mux").map(String::as_str),
                    Some("0" | "false" | "off" | "no")
                ))
                .then_some(super::mux::Mux::Vmess)
            } else if matches!(
                opts.get("mode").map(String::as_str),
                Some("mtls" | "mws" | "mwss" | "mwebsocket" | "mwebsockets")
            ) || (matches!(
                node.plugin
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .replace(' ', "")
                    .as_str(),
                "gostplugin" | "gost-plugin"
            ) && matches!(
                opts.get("mux").map(String::as_str),
                Some("1" | "true" | "on" | "yes")
            )) {
                Some(super::mux::Mux::Smux)
            } else {
                None
            },
            mode,
            tls,
            host,
            path,
            opts,
            cert_path,
            key_path,
        })
    }

    pub async fn accept(
        &self,
        mut stream: BoxedStream,
        ctx: &crate::protocol::InboundContext,
        local_ip: Option<std::net::IpAddr>,
    ) -> io::Result<Accepted> {
        if let Some(shadow) = &self.shadow {
            let outbound = ctx
                .router
                .match_outbound(&crate::proxy::router::MatchContext {
                    node_id: ctx.node_id,
                    network: "tcp",
                    target_host: &shadow.host,
                    target_ip: shadow.host.parse().ok(),
                    target_port: shadow.port,
                    inbound_local_ip: local_ip,
                });
            let decoy = ctx
                .router
                .dialer()
                .dial(&outbound, &shadow.host, shadow.port, local_ip)
                .await?;
            return shadow.accept(stream, Box::new(decoy)).await;
        }
        if let Some(restls) = &self.restls {
            let outbound = ctx
                .router
                .match_outbound(&crate::proxy::router::MatchContext {
                    node_id: ctx.node_id,
                    network: "tcp",
                    target_host: &restls.host,
                    target_ip: restls.host.parse().ok(),
                    target_port: restls.port,
                    inbound_local_ip: local_ip,
                });
            let decoy = ctx
                .router
                .dialer()
                .dial(&outbound, &restls.host, restls.port, local_ip)
                .await?;
            return restls
                .accept(stream, Box::new(decoy))
                .await
                .map_err(io::Error::other);
        }
        if let Some(tls) = &self.tls {
            tracing::debug!(
                milestone = "tls_handshake_started",
                stage = "tls",
                plugin = if self.gost {
                    "gost-plugin"
                } else {
                    "v2ray-plugin"
                },
                mode = ?self.mode,
                tls = true,
                host = ?self.host,
                path = ?self.path,
                tls_role = "server",
                cert_path = ?self.cert_path,
                key_path = ?self.key_path,
                "TLS handshake started"
            );
            let accepted = match tls.accept(stream).await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(
                        stage = "tls",
                        error = %e,
                        plugin = if self.gost {
                            "gost-plugin"
                        } else {
                            "v2ray-plugin"
                        },
                        mode = ?self.mode,
                        host = ?self.host,
                        cert_path = ?self.cert_path,
                        "TLS handshake failed"
                    );
                    return Err(e);
                }
            };
            let (_, ref server_conn) = accepted.get_ref();
            let sni = server_conn.server_name().map(|s| s.to_string());
            let alpn = server_conn
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).to_string());
            tracing::debug!(
                milestone = "tls_handshake_ok",
                stage = "tls",
                plugin = if self.gost {
                    "gost-plugin"
                } else {
                    "v2ray-plugin"
                },
                mode = ?self.mode,
                tls = true,
                host = ?self.host,
                path = ?self.path,
                tls_role = "server",
                sni = ?sni,
                alpn = ?alpn,
                cert_path = ?self.cert_path,
                "TLS handshake succeeded"
            );
            if self.mode == Mode::Http2 && alpn.as_deref() != Some("h2") {
                tracing::warn!(
                    stage = "alpn",
                    alpn = ?alpn,
                    "HTTP/2 ALPN was not negotiated"
                );
                return Err(invalid("HTTP/2 ALPN was not negotiated"));
            }
            stream = Box::new(accepted);
        }
        let stream = match self.mode {
            Mode::None | Mode::Tls | Mode::Http2 | Mode::Kcptun => Ok(stream),
            Mode::ObfsHttp => super::simple_obfs::accept_http(stream, self.host.as_deref()).await,
            Mode::ObfsTls => super::simple_obfs::accept_tls(stream, self.host.as_deref()).await,
            Mode::WebSocket => {
                tracing::debug!(
                    milestone = "websocket_upgrade_started",
                    stage = "websocket_upgrade",
                    plugin = if self.gost {
                        "gost-plugin"
                    } else {
                        "v2ray-plugin"
                    },
                    mode = "websocket",
                    tls = self.tls.is_some(),
                    host = ?self.host,
                    path = ?self.path,
                    "WebSocket HTTP upgrade started"
                );
                let mut early = Vec::new();
                #[allow(clippy::result_large_err)]
                let callback = |request: &Request, mut response: Response| {
                    let host = request.headers().get("host").and_then(|v| v.to_str().ok());
                    let host_matches = self.host.as_deref().map_or(true, |expected| {
                        host.is_some_and(|actual| {
                            let actual_host = actual
                                .rsplit_once(':')
                                .filter(|(_, port)| port.parse::<u16>().is_ok())
                                .map_or(actual, |(h, _)| h);
                            actual_host.eq_ignore_ascii_case(expected)
                        })
                    });
                    if request.uri().path() != self.path || !host_matches {
                        tracing::warn!(
                            stage = "websocket_upgrade",
                            expected_path = ?self.path,
                            actual_path = ?request.uri().path(),
                            expected_host = ?self.host,
                            actual_host = ?host,
                            "WebSocket upgrade request rejected: path or host mismatch"
                        );
                        return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                            .status(404)
                            .body(None)
                            .unwrap());
                    }
                    let sec_proto = request.headers().get("sec-websocket-protocol");
                    if let Some(value) = sec_proto {
                        let ws_early_data_base64_len = value.as_bytes().len();
                        let trimmed = value.to_str().unwrap_or("").trim();
                        let plugin_name = if self.gost {
                            "gost-plugin"
                        } else {
                            "v2ray-plugin"
                        };

                        let decoded_res = if self.gost {
                            base64::engine::general_purpose::STANDARD
                                .decode(trimmed.as_bytes())
                                .or_else(|_| {
                                    base64::engine::general_purpose::STANDARD_NO_PAD
                                        .decode(trimmed.as_bytes())
                                })
                                .or_else(|_| {
                                    base64::engine::general_purpose::URL_SAFE
                                        .decode(trimmed.as_bytes())
                                })
                                .or_else(|_| {
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .decode(trimmed.as_bytes())
                                })
                        } else {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(trimmed.as_bytes())
                        };

                        match decoded_res {
                            Ok(bytes) if bytes.len() <= 8192 => {
                                let ws_early_data_decoded_len = bytes.len();
                                tracing::debug!(
                                    stage = "websocket_upgrade",
                                    ws_sec_websocket_protocol_present = true,
                                    ws_early_data_base64_len,
                                    ws_early_data_decoded_len,
                                    plugin = plugin_name,
                                    "WebSocket early data extracted from Sec-WebSocket-Protocol"
                                );
                                early = bytes;
                                response
                                    .headers_mut()
                                    .insert("Sec-WebSocket-Protocol", value.clone());
                            }
                            _ => {
                                tracing::warn!(
                                    stage = "websocket_upgrade",
                                    ws_sec_websocket_protocol_present = true,
                                    ws_early_data_base64_len,
                                    plugin = plugin_name,
                                    "WebSocket upgrade: Sec-WebSocket-Protocol could not be decoded as early data"
                                );
                                if !self.gost {
                                    return Err(
                                        tokio_tungstenite::tungstenite::http::Response::builder()
                                            .status(400)
                                            .body(None)
                                            .unwrap(),
                                    );
                                }
                            }
                        }
                    } else {
                        tracing::debug!(
                            stage = "websocket_upgrade",
                            ws_sec_websocket_protocol_present = false,
                            ws_early_data_base64_len = 0,
                            ws_early_data_decoded_len = 0,
                            plugin = if self.gost {
                                "gost-plugin"
                            } else {
                                "v2ray-plugin"
                            },
                            "No Sec-WebSocket-Protocol header present in WebSocket upgrade request"
                        );
                    }
                    Ok(response)
                };
                let mut config =
                    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
                config.max_message_size = Some(1024 * 1024);
                config.max_frame_size = Some(1024 * 1024);
                let socket = match tokio_tungstenite::accept_hdr_async_with_config(
                    stream,
                    callback,
                    Some(config),
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            stage = "websocket_upgrade",
                            error = %e,
                            "WebSocket HTTP upgrade handshake failed"
                        );
                        return Err(io::Error::other(e));
                    }
                };
                tracing::debug!(
                    milestone = "websocket_upgrade_ok",
                    stage = "websocket_upgrade",
                    plugin = if self.gost {
                        "gost-plugin"
                    } else {
                        "v2ray-plugin"
                    },
                    mode = "websocket",
                    tls = self.tls.is_some(),
                    host = ?self.host,
                    path = ?self.path,
                    "WebSocket HTTP upgrade completed"
                );
                let inner = WebSocket {
                    socket,
                    buffered: Bytes::new(),
                };
                if early.is_empty() {
                    Ok(Box::new(inner) as BoxedStream)
                } else {
                    Ok(Box::new(PrefixedStream::new(inner, Some(early))) as BoxedStream)
                }
            }
            Mode::ShadowTls | Mode::Restls | Mode::Quic => unreachable!(),
        }?;
        Ok(Accepted::Stream(stream))
    }

    pub fn is_quic(&self) -> bool {
        self.mode == Mode::Quic
    }

    pub(super) fn kcptun_args(&self, listen: &str, target: &str) -> io::Result<Vec<String>> {
        let mut args = vec![
            "--listen".into(),
            listen.into(),
            "--target".into(),
            self.opts
                .get("target")
                .map(String::as_str)
                .unwrap_or(target)
                .into(),
        ];
        for (name, default) in [
            ("key", "testkey"),
            ("crypt", "aes-128"),
            ("mode", "fast"),
            ("datashard", "10"),
            ("parityshard", "3"),
            ("smuxver", "1"),
        ] {
            args.push(format!("--{name}"));
            args.push(
                self.opts
                    .get(name)
                    .map(String::as_str)
                    .unwrap_or(default)
                    .into(),
            );
        }
        for name in ["nocomp", "acknodelay"] {
            if let Some(value) = self.opts.get(name) {
                args.push(format!("--{name}={}", flag(Some(value))?));
            }
        }
        for name in [
            "mtu",
            "sndwnd",
            "rcvwnd",
            "dscp",
            "nodelay",
            "interval",
            "resend",
            "nc",
            "sockbuf",
            "smuxbuf",
            "framesize",
            "streambuf",
            "keepalive",
            "ratelimit",
        ] {
            if let Some(value) = self.opts.get(name) {
                args.push(format!("--{name}"));
                args.push(value.clone());
            }
        }
        Ok(args)
    }

    pub fn is_kcptun(&self) -> bool {
        self.mode == Mode::Kcptun
    }

    pub fn is_obfs(&self) -> bool {
        matches!(self.mode, Mode::ObfsHttp | Mode::ObfsTls)
    }

    pub fn is_obfs_http(&self) -> bool {
        self.mode == Mode::ObfsHttp
    }

    pub fn is_obfs_tls(&self) -> bool {
        self.mode == Mode::ObfsTls
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    #[cfg(feature = "quic-protocols")]
    pub fn quic_tls(&self) -> Option<&rustls::ServerConfig> {
        self.tls.as_ref().map(|tls| &**tls.config())
    }

    pub fn is_http2(&self) -> bool {
        self.mode == Mode::Http2
    }

    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub fn is_websocket(&self) -> bool {
        self.mode == Mode::WebSocket
    }

    pub fn is_gost(&self) -> bool {
        self.gost
    }

    pub fn cert_path(&self) -> Option<&str> {
        self.cert_path.as_deref()
    }

    pub fn key_path(&self) -> Option<&str> {
        self.key_path.as_deref()
    }
}

fn flag(value: Option<&str>) -> io::Result<bool> {
    match value.map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"').trim()) {
        None | Some("false" | "0" | "off" | "no") => Ok(false),
        Some("true" | "1" | "on" | "yes" | "") => Ok(true),
        _ => Err(invalid("Invalid plugin boolean")),
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

struct WebSocket {
    socket: tokio_tungstenite::WebSocketStream<BoxedStream>,
    buffered: Bytes,
}

impl AsyncRead for WebSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let n = output.remaining().min(self.buffered.len());
                output.put_slice(&self.buffered[..n]);
                self.buffered.advance(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => self.buffered = data,
                None | Some(Ok(Message::Close(_))) => return Poll::Ready(Ok(())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected binary WebSocket frame",
                    )))
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
    }
}

impl AsyncWrite for WebSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.socket).poll_ready(cx)).map_err(io::Error::other)?;
        let n = data.len().min(16384);
        Pin::new(&mut self.socket)
            .start_send(Message::Binary(Bytes::copy_from_slice(&data[..n])))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}
