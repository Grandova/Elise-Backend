pub mod config;
pub mod padding;
pub mod session;
pub mod stream;
pub mod uot;

pub use config::{
    AnyTlsClientProfile, AnyTlsNodeConfig, AnyTlsProtocolConfig, EchClientConfig, EchServerConfig,
    TlsServerConfig,
};
pub use padding::{
    CompiledPaddingScheme, PaddingRange, DEFAULT_PADDING_SCHEME, FRAME_OVERHEAD, MAX_FRAME_SIZE,
};
pub use session::{
    handle_anytls_session, make_frame, CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE,
    CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME,
    CMD_WASTE, MAX_CONCURRENT_STREAMS,
};

use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream};
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use async_trait::async_trait;
use parking_lot::RwLock;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub const PASSWORD_LEN: usize = 32;

pub struct AnytlsInbound {
    users: Arc<RwLock<Arc<HashMap<[u8; PASSWORD_LEN], Arc<User>>>>>,
    padding_scheme: Arc<RwLock<Arc<CompiledPaddingScheme>>>,
}

impl Default for AnytlsInbound {
    fn default() -> Self {
        let default_scheme = CompiledPaddingScheme::parse(DEFAULT_PADDING_SCHEME)
            .expect("Valid default padding scheme");
        Self {
            users: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
            padding_scheme: Arc::new(RwLock::new(Arc::new(default_scheme))),
        }
    }
}

impl AnytlsInbound {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_padding_scheme(&self, raw: &str) -> Result<(), String> {
        let compiled = CompiledPaddingScheme::parse(raw)?;
        *self.padding_scheme.write() = Arc::new(compiled);
        info!("AnyTLS padding scheme successfully updated via hot reload");
        Ok(())
    }
}

#[async_trait]
impl Inbound for AnytlsInbound {
    fn protocol_type(&self) -> &'static str {
        "anytls"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::with_capacity(users.len());
        for u in users {
            let pass = u.password.as_deref().unwrap_or(&u.uuid);
            let mut hasher = Sha256::new();
            Sha2Digest::update(&mut hasher, pass.as_bytes());
            let hash: [u8; PASSWORD_LEN] = Sha2Digest::finalize(hasher).into();
            map.insert(hash, Arc::new(u));
        }
        *self.users.write() = Arc::new(map);
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        // [Requirement ⑪]: Standard AnyTLS requires TLS; never silently downgrade to plaintext!
        if ctx.tls_manager.get_acceptor().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "AnyTLS inbound requires valid TLS configuration; plaintext AnyTLS is forbidden in standard mode",
            ));
        }

        // [Requirement ⑤]: Parse panel padding_scheme if provided
        match AnyTlsNodeConfig::from_node_info(&node_info) {
            Ok(cfg) => {
                *self.padding_scheme.write() = cfg.protocol.padding_scheme;
                info!("AnyTLS configuration loaded successfully from node info");
            }
            Err(e) => {
                warn!("Using default AnyTLS padding scheme: {e}");
            }
        }

        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        info!("AnyTLS inbound listening on {}", bind_addr);

        let users = self.users.clone();
        let padding_scheme = self.padding_scheme.clone();

        // [Requirement ⑩]: Top-level Connection tasks managed via CancellationToken + JoinSet
        let top_cancel = CancellationToken::new();
        let mut connection_tasks = JoinSet::new();

        loop {
            // Clean up completed connection tasks
            while connection_tasks.try_join_next().is_some() {}

            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("AnyTLS inbound on port {} stopping", ctx.port);
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("AnyTLS accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let users = users.clone();
                    let padding_scheme = padding_scheme.clone();
                    let session_cancel = top_cancel.child_token();

                    connection_tasks.spawn(async move {
                        let _ = handle_connection(
                            stream,
                            remote_addr,
                            ctx,
                            users,
                            padding_scheme,
                            session_cancel,
                        ).await;
                    });
                }
            }
        }

        // Graceful shutdown
        top_cancel.cancel();
        let graceful_timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(graceful_timeout);
        loop {
            tokio::select! {
                _ = &mut graceful_timeout => {
                    connection_tasks.abort_all();
                    break;
                }
                res = connection_tasks.join_next() => {
                    if res.is_none() {
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<HashMap<[u8; PASSWORD_LEN], Arc<User>>>>>,
    padding_scheme: Arc<RwLock<Arc<CompiledPaddingScheme>>>,
    session_cancel: CancellationToken,
) -> std::io::Result<()> {
    // [Requirement ①]: 15-second timeout covers ONLY the handshake phase
    // (PROXY / TLS / Auth / initial padding length), NEVER the entire session!
    let handshake_fut = perform_handshake(stream, remote_addr, &ctx, &users);
    let (stream, user, client_ip, local_ip, conn_guard) =
        match tokio::time::timeout(Duration::from_secs(15), handshake_fut).await {
            Ok(Ok(parts)) => parts,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "AnyTLS handshake timed out after 15s",
                ));
            }
        };

    // Enter multiplexed session WITHOUT 15-second handshake timeout!
    handle_anytls_session(
        stream,
        user,
        ctx,
        client_ip,
        local_ip,
        conn_guard,
        padding_scheme,
        session_cancel,
    )
    .await
}

async fn perform_handshake(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: &InboundContext,
    users: &Arc<RwLock<Arc<HashMap<[u8; PASSWORD_LEN], Arc<User>>>>>,
) -> std::io::Result<(
    BoxedStream,
    Arc<User>,
    IpAddr,
    Option<IpAddr>,
    crate::limiter::ConnGuard,
)> {
    let local_ip = stream.local_addr().ok().map(|s| s.ip());

    // 1. PROXY Protocol
    let (src_opt, stream) =
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Client IP banned by defense manager",
        ));
    }

    // 2. TLS Handshake (strictly required, plaintext forbidden!)
    let acceptor = ctx.tls_manager.get_acceptor().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AnyTLS requires TLS configuration; plaintext AnyTLS is forbidden in standard mode",
        )
    })?;

    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => Box::new(s) as BoxedStream,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("AnyTLS TLS handshake failed: {e}"),
            ));
        }
    };

    let mut stream = tls_stream;

    // 3. Auth: Read 32-byte SHA-256 password hash
    let mut password_hash = [0u8; PASSWORD_LEN];
    stream.read_exact(&mut password_hash).await?;

    let users_snapshot = users.read().clone();
    let user = match users_snapshot.get(&password_hash).cloned() {
        Some(u) => {
            ctx.defense.record_success(client_ip);
            u
        }
        None => {
            ctx.defense.record_failure(client_ip);
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "AnyTLS authentication failed",
            ));
        }
    };

    // 4. Device limit
    if !ctx.device_limiter.check_and_record_async(user.id, client_ip).await {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Device limit reached",
        ));
    }

    // 5. Connection limit
    let conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Connection limit reached",
            ));
        }
    };

    // 6. Padding 0: 2-byte big-endian padding length
    let mut pad_len_bytes = [0u8; 2];
    stream.read_exact(&mut pad_len_bytes).await?;
    let pad_len = u16::from_be_bytes(pad_len_bytes) as usize;
    if pad_len > 0 {
        let mut discard = [0u8; 1024];
        let mut rem = pad_len;
        while rem > 0 {
            let to_read = rem.min(discard.len());
            stream.read_exact(&mut discard[..to_read]).await?;
            rem -= to_read;
        }
    }

    Ok((stream, user, client_ip, local_ip, conn_guard))
}
