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
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
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
}

impl Transport {
    pub fn validate(node: &NodeInfo) -> io::Result<()> {
        Self::options(node).map(|_| ())
    }

    fn options(node: &NodeInfo) -> io::Result<(Mode, bool, HashMap<String, String>)> {
        let mut opts = HashMap::new();
        match &node.plugin_opts {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(value)) => {
                for field in value.split(';').filter(|s| !s.is_empty()) {
                    let (key, value) = field.split_once('=').unwrap_or((field, "true"));
                    if opts.insert(key.to_owned(), value.to_owned()).is_some() {
                        return Err(invalid("Duplicate plugin option"));
                    }
                }
            }
            Some(serde_json::Value::Object(value)) => {
                for (key, value) in value {
                    let value = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Bool(v) => v.to_string(),
                        serde_json::Value::Number(v) => v.to_string(),
                        _ => return Err(invalid("Invalid plugin option type")),
                    };
                    opts.insert(key.clone(), value);
                }
            }
            _ => return Err(invalid("plugin_opts must be a string or object")),
        }
        let plugin = node
            .plugin
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .replace(' ', "");
        let value = |name| opts.get(name).map(String::as_str);
        let (mode, tls, allowed): (Mode, bool, &[&str]) = match plugin.as_str() {
            "" | "none" if opts.is_empty() => (Mode::None, false, &[]),
            "restls" => {
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
                        "min-record-len",
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
            "simpleobfs" | "simple-obfs" | "obfs-local" | "obfs-server" => {
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
                (
                    mode,
                    flag(value("tls"))? || mode == Mode::Quic,
                    &[
                        "mode", "tls", "host", "path", "cert", "key", "server", "mux",
                    ],
                )
            }
            "gostplugin" | "gost-plugin" => {
                let (mode, tls) = match value("mode").unwrap_or("ws") {
                    "tls" | "mtls" => (Mode::Tls, true),
                    "ws" | "mws" => (Mode::WebSocket, false),
                    "wss" | "mwss" => (Mode::WebSocket, true),
                    "h2" | "grpc" | "gun" => (Mode::Http2, true),
                    "quic" if cfg!(feature = "quic-protocols") => (Mode::Quic, true),
                    _ => return Err(unsupported("Unsupported GOST transport mode")),
                };
                (
                    mode,
                    tls,
                    &[
                        "mode",
                        "host",
                        "path",
                        "cert",
                        "key",
                        "server",
                        "serviceName",
                    ],
                )
            }
            "kcptun" => {
                let crypt = value("crypt").unwrap_or("aes-128");
                match crypt {
                    "aes" | "aes-128" | "aes-192" | "none" | "null" => {}
                    _ => return Err(unsupported("Unsupported KCPTun crypt")),
                }
                (
                    Mode::Kcptun,
                    false,
                    &[
                        "key",
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

    pub async fn new(node: &NodeInfo, manager: &TLSManager) -> io::Result<Self> {
        let (mode, use_tls, opts) = Self::options(node)?;
        let tls = if use_tls {
            if let (Some(cert), Some(key)) = (opts.get("cert"), opts.get("key")) {
                let cert = tokio::fs::read(cert).await?;
                let key = tokio::fs::read(key).await?;
                let chain = CertificateDer::pem_slice_iter(&cert)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(io::Error::other)?;
                let key = PrivateKeyDer::from_pem_slice(&key).map_err(io::Error::other)?;
                let mut config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(chain, key)
                    .map_err(io::Error::other)?;
                if mode == Mode::Http2 {
                    config.alpn_protocols = vec![b"h2".to_vec()];
                }
                Some(TlsAcceptor::from(Arc::new(config)))
            } else {
                let acceptor = manager
                    .get_acceptor()
                    .ok_or_else(|| invalid("TLS transport requires a certificate"))?;
                if mode == Mode::Http2 {
                    let mut config = (**acceptor.config()).clone();
                    config.alpn_protocols = vec![b"h2".to_vec()];
                    Some(TlsAcceptor::from(Arc::new(config)))
                } else {
                    Some(acceptor)
                }
            }
        } else {
            None
        };
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
                (opts.get("mux").map(String::as_str).unwrap_or("1") != "0")
                    .then_some(super::mux::Mux::Vmess)
            } else if matches!(
                opts.get("mode").map(String::as_str),
                Some("mtls" | "mws" | "mwss")
            ) {
                Some(super::mux::Mux::Smux)
            } else {
                None
            },
            mode,
            tls,
            host,
            path,
            opts,
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
            let accepted = tls.accept(stream).await?;
            if self.mode == Mode::Http2 && accepted.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(invalid("HTTP/2 ALPN was not negotiated"));
            }
            stream = Box::new(accepted);
        }
        let stream = match self.mode {
            Mode::None | Mode::Tls | Mode::Http2 | Mode::Kcptun => Ok(stream),
            Mode::ObfsHttp => super::simple_obfs::accept_http(stream, self.host.as_deref()).await,
            Mode::ObfsTls => super::simple_obfs::accept_tls(stream, self.host.as_deref()).await,
            Mode::WebSocket => {
                let mut early = Vec::new();
                #[allow(clippy::result_large_err)]
                let callback = |request: &Request, response: Response| {
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
                        return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                            .status(404)
                            .body(None)
                            .unwrap());
                    }
                    if let Some(value) = request.headers().get("sec-websocket-protocol") {
                        let encoding = if self.gost {
                            &base64::engine::general_purpose::STANDARD
                        } else {
                            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                        };
                        match encoding.decode(value.as_bytes()) {
                            Ok(bytes) if bytes.len() <= 8192 => early = bytes,
                            _ => {
                                return Err(
                                    tokio_tungstenite::tungstenite::http::Response::builder()
                                        .status(400)
                                        .body(None)
                                        .unwrap(),
                                )
                            }
                        }
                    }
                    Ok(response)
                };
                let mut config =
                    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
                config.max_message_size = Some(1024 * 1024);
                config.max_frame_size = Some(1024 * 1024);
                let socket =
                    tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(config))
                        .await
                        .map_err(io::Error::other)?;
                Ok(Box::new(PrefixedStream::new(
                    WebSocket {
                        socket,
                        buffered: Bytes::new(),
                    },
                    Some(early),
                )) as BoxedStream)
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
            "smuxver",
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

    #[cfg(feature = "quic-protocols")]
    pub fn quic_tls(&self) -> Option<&rustls::ServerConfig> {
        self.tls.as_ref().map(|tls| &**tls.config())
    }

    pub fn is_http2(&self) -> bool {
        self.mode == Mode::Http2
    }
}

fn flag(value: Option<&str>) -> io::Result<bool> {
    match value {
        None | Some("false" | "0") => Ok(false),
        Some("true" | "1" | "") => Ok(true),
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
