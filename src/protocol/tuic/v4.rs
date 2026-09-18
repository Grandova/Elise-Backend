use super::quic::QuicStream;
use crate::observability::AuditRecord;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

pub const TUIC_V4_VERSION: u8 = 0x04;

pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;
pub const CMD_RESPONSE: u8 = 0xff;

pub const REP_SUCCEED: u8 = 0x00;
pub const REP_FAILED: u8 = 0xff;

pub const ERR_PROTOCOL_ERROR: u32 = 0xfffffff0;
pub const ERR_AUTHENTICATION_FAILED: u32 = 0xfffffff1;
pub const ERR_AUTHENTICATION_TIMEOUT: u32 = 0xfffffff2;
pub const ERR_BAD_COMMAND: u32 = 0xfffffff3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicV4RelayMode {
    Native,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuicV4Address {
    Domain(String, u16),
    IPv4(Ipv4Addr, u16),
    IPv6(Ipv6Addr, u16),
}

impl TuicV4Address {
    pub async fn read_from(reader: &mut quinn::RecvStream) -> io::Result<Self> {
        let mut atyp_buf = [0u8; 1];
        reader
            .read_exact(&mut atyp_buf)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        let atyp = atyp_buf[0];

        match atyp {
            0x00 => {
                let mut len_buf = [0u8; 1];
                reader
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let len = len_buf[0] as usize;
                let mut buf = vec![0u8; len];
                reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let host = String::from_utf8_lossy(&buf).to_string();
                let mut port_buf = [0u8; 2];
                reader
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let port = u16::from_be_bytes(port_buf);
                Ok(Self::Domain(host, port))
            }
            0x01 => {
                let mut buf = [0u8; 4];
                reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let ip = Ipv4Addr::from(buf);
                let mut port_buf = [0u8; 2];
                reader
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let port = u16::from_be_bytes(port_buf);
                Ok(Self::IPv4(ip, port))
            }
            0x02 => {
                let mut buf = [0u8; 16];
                reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let ip = Ipv6Addr::from(buf);
                let mut port_buf = [0u8; 2];
                reader
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let port = u16::from_be_bytes(port_buf);
                Ok(Self::IPv6(ip, port))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid TUIC V4 address type: 0x{:02x}", other),
            )),
        }
    }

    pub fn read_from_cursor(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Self> {
        let mut atyp_buf = [0u8; 1];
        io::Read::read_exact(cursor, &mut atyp_buf)?;
        let atyp = atyp_buf[0];

        match atyp {
            0x00 => {
                let mut len_buf = [0u8; 1];
                io::Read::read_exact(cursor, &mut len_buf)?;
                let len = len_buf[0] as usize;
                let mut buf = vec![0u8; len];
                io::Read::read_exact(cursor, &mut buf)?;
                let host = String::from_utf8_lossy(&buf).to_string();
                let mut port_buf = [0u8; 2];
                io::Read::read_exact(cursor, &mut port_buf)?;
                let port = u16::from_be_bytes(port_buf);
                Ok(Self::Domain(host, port))
            }
            0x01 => {
                let mut buf = [0u8; 4];
                io::Read::read_exact(cursor, &mut buf)?;
                let ip = Ipv4Addr::from(buf);
                let mut port_buf = [0u8; 2];
                io::Read::read_exact(cursor, &mut port_buf)?;
                let port = u16::from_be_bytes(port_buf);
                Ok(Self::IPv4(ip, port))
            }
            0x02 => {
                let mut buf = [0u8; 16];
                io::Read::read_exact(cursor, &mut buf)?;
                let ip = Ipv6Addr::from(buf);
                let mut port_buf = [0u8; 2];
                io::Read::read_exact(cursor, &mut port_buf)?;
                let port = u16::from_be_bytes(port_buf);
                Ok(Self::IPv6(ip, port))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid TUIC V4 address type: 0x{:02x}", other),
            )),
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Domain(host, port) => {
                buf.push(0x00);
                buf.push(host.len() as u8);
                buf.extend_from_slice(host.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::IPv4(ip, port) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::IPv6(ip, port) => {
                buf.push(0x02);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::IPv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Self::IPv6(*v6.ip(), v6.port()),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Domain(h, _) => h.clone(),
            Self::IPv4(ip, _) => ip.to_string(),
            Self::IPv6(ip, _) => ip.to_string(),
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Domain(..) => None,
            Self::IPv4(ip, _) => Some(IpAddr::V4(*ip)),
            Self::IPv6(ip, _) => Some(IpAddr::V6(*ip)),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, p) | Self::IPv4(_, p) | Self::IPv6(_, p) => *p,
        }
    }
}

pub struct TuicV4Session {
    quic_conn: quinn::Connection,
    ctx: InboundContext,
    v4_tokens: Arc<HashMap<[u8; 32], (User, String)>>,
    auth_timeout: Duration,
    remote_addr: SocketAddr,
    auth_done: Arc<Notify>,
    auth_ok: Arc<AtomicBool>,
    authenticated_user: Arc<Mutex<Option<User>>>,
    udp_sessions: Arc<Mutex<HashMap<u32, mpsc::Sender<(TuicV4Address, Vec<u8>, TuicV4RelayMode)>>>>,
    cancel: CancellationToken,
    tasks: Mutex<tokio::task::JoinSet<()>>,
}

impl TuicV4Session {
    pub fn new(
        quic_conn: quinn::Connection,
        ctx: InboundContext,
        v4_tokens: Arc<HashMap<[u8; 32], (User, String)>>,
        auth_timeout: Duration,
        remote_addr: SocketAddr,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            quic_conn,
            ctx,
            v4_tokens,
            auth_timeout,
            remote_addr,
            auth_done: Arc::new(Notify::new()),
            auth_ok: Arc::new(AtomicBool::new(false)),
            authenticated_user: Arc::new(Mutex::new(None)),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            cancel: cancel.child_token(),
            tasks: Mutex::new(tokio::task::JoinSet::new()),
        }
    }

    pub async fn run(self: Arc<Self>) {
        let _cancel = self.cancel.clone().drop_guard();
        let auth_timeout = self.auth_timeout;
        let session = self.clone();

        self.spawn(async move {
            tokio::select! {
                _ = session.cancel.cancelled() => {}
                _ = tokio::time::sleep(auth_timeout) => {
                    if !session.auth_ok.load(Ordering::Acquire) {
                        debug!("TUIC V4 session auth timeout from {}", session.remote_addr);
                        let _ = session.quic_conn.close(
                            quinn::VarInt::from_u32(ERR_AUTHENTICATION_TIMEOUT),
                            b"AuthenticationTimeout",
                        );
                    }
                }
                _ = session.auth_done.notified() => {}
            }
        });

        let s1 = self.clone();
        let s2 = self.clone();
        let s3 = self.clone();

        tokio::select! {
            _ = self.cancel.cancelled() => {}
            _ = s1.loop_bidi_streams() => {}
            _ = s2.loop_uni_streams() => {}
            _ = s3.loop_datagrams() => {}
        }
        self.cancel.cancel();
        self.quic_conn
            .close(quinn::VarInt::from_u32(0), b"Session closed");
        let mut tasks = std::mem::take(&mut *self.tasks.lock());
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                warn!(error = %e, "TUIC worker failed");
            }
        }
        self.udp_sessions.lock().clear();
    }

    fn spawn(
        &self,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> tokio::task::AbortHandle {
        let cancel = self.cancel.clone();
        let mut tasks = self.tasks.lock();
        while let Some(result) = tasks.try_join_next() {
            if let Err(e) = result {
                warn!(error = %e, "TUIC worker failed");
            }
        }
        tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {},
                _ = future => {},
            }
        })
    }

    async fn loop_bidi_streams(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                res = self.quic_conn.accept_bi() => {
                    let (send, recv) = match res {
                        Ok(streams) => streams,
                        Err(e) => {
                            debug!("TUIC V4 accept_bi error: {:?}", e);
                            break;
                        }
                    };
                    let session = self.clone();
                    self.spawn(async move {
                        session.handle_bidi_stream(send, recv).await;
                    });
                }
            }
        }
    }

    async fn loop_uni_streams(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                res = self.quic_conn.accept_uni() => {
                    let recv = match res {
                        Ok(stream) => stream,
                        Err(e) => {
                            debug!("TUIC V4 accept_uni error: {:?}", e);
                            break;
                        }
                    };
                    let session = self.clone();
                    self.spawn(async move {
                        session.handle_uni_stream(recv).await;
                    });
                }
            }
        }
    }

    async fn loop_datagrams(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                res = self.quic_conn.read_datagram() => {
                    let data = match res {
                        Ok(d) => d,
                        Err(e) => {
                            debug!("TUIC V4 read_datagram error: {:?}", e);
                            break;
                        }
                    };
                    let session = self.clone();
                    self.spawn(async move {
                        session.handle_datagram(data).await;
                    });
                }
            }
        }
    }

    async fn handle_uni_stream(self: Arc<Self>, mut recv: quinn::RecvStream) {
        let read_res = tokio::time::timeout(Duration::from_secs(5), async {
            let mut hdr = [0u8; 2];
            recv.read_exact(&mut hdr)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            Ok::<_, io::Error>(hdr)
        })
        .await;

        let [ver, cmd] = match read_res {
            Ok(Ok(h)) => h,
            _ => return,
        };

        if ver != TUIC_V4_VERSION {
            let _ = self.quic_conn.close(
                quinn::VarInt::from_u32(ERR_PROTOCOL_ERROR),
                b"ProtocolError",
            );
            return;
        }

        match cmd {
            CMD_AUTHENTICATE => {
                let mut token_buf = [0u8; 32];
                if recv.read_exact(&mut token_buf).await.is_err() {
                    return;
                }

                let client_ip = self.remote_addr.ip();
                let matched_user = self.v4_tokens.get(&token_buf).cloned();

                match matched_user {
                    Some((user, _)) => {
                        self.ctx.defense.record_success(client_ip);
                        if !self
                            .ctx
                            .device_limiter
                            .check_and_record_async(user.id, client_ip)
                            .await
                        {
                            let _ = self.quic_conn.close(
                                quinn::VarInt::from_u32(ERR_AUTHENTICATION_FAILED),
                                b"DeviceLimitExceeded",
                            );
                            return;
                        }

                        *self.authenticated_user.lock() = Some(user);
                        self.auth_ok.store(true, Ordering::Release);
                        self.auth_done.notify_waiters();
                    }
                    None => {
                        self.ctx.defense.record_failure(client_ip);
                        let _ = self.quic_conn.close(
                            quinn::VarInt::from_u32(ERR_AUTHENTICATION_FAILED),
                            b"AuthenticationFailed",
                        );
                    }
                }
            }
            CMD_PACKET => {
                if !self.wait_auth().await {
                    return;
                }
                let mut assoc_buf = [0u8; 4];
                if recv.read_exact(&mut assoc_buf).await.is_err() {
                    return;
                }
                let assoc_id = u32::from_be_bytes(assoc_buf);

                let mut len_buf = [0u8; 2];
                if recv.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let data_len = u16::from_be_bytes(len_buf) as usize;

                let addr = match TuicV4Address::read_from(&mut recv).await {
                    Ok(a) => a,
                    Err(_) => return,
                };

                let mut data = vec![0u8; data_len];
                if recv.read_exact(&mut data).await.is_err() {
                    return;
                }

                self.route_udp_packet(assoc_id, addr, data, TuicV4RelayMode::Quic)
                    .await;
            }
            CMD_DISSOCIATE => {
                if !self.wait_auth().await {
                    return;
                }
                let mut assoc_buf = [0u8; 4];
                if recv.read_exact(&mut assoc_buf).await.is_err() {
                    return;
                }
                let assoc_id = u32::from_be_bytes(assoc_buf);
                self.udp_sessions.lock().remove(&assoc_id);
            }
            CMD_HEARTBEAT => {}
            _ => {
                let _ = self
                    .quic_conn
                    .close(quinn::VarInt::from_u32(ERR_BAD_COMMAND), b"BadCommand");
            }
        }
    }

    async fn handle_bidi_stream(
        self: Arc<Self>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        let read_res = tokio::time::timeout(Duration::from_secs(5), async {
            let mut hdr = [0u8; 2];
            recv.read_exact(&mut hdr)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            let addr = TuicV4Address::read_from(&mut recv).await?;
            Ok::<_, io::Error>((hdr, addr))
        })
        .await;

        let ([ver, cmd], addr) = match read_res {
            Ok(Ok(res)) => res,
            _ => {
                let _ = send.finish();
                return;
            }
        };

        if ver != TUIC_V4_VERSION || cmd != CMD_CONNECT {
            let _ = send
                .write_all(&[TUIC_V4_VERSION, CMD_RESPONSE, REP_FAILED])
                .await;
            let _ = send.finish();
            return;
        }

        if !self.wait_auth().await {
            let _ = send
                .write_all(&[TUIC_V4_VERSION, CMD_RESPONSE, REP_FAILED])
                .await;
            let _ = send.finish();
            return;
        }

        let user = {
            let guard = self.authenticated_user.lock();
            guard.clone()
        };
        let user = match user {
            Some(u) => u,
            None => {
                let _ = send
                    .write_all(&[TUIC_V4_VERSION, CMD_RESPONSE, REP_FAILED])
                    .await;
                let _ = send.finish();
                return;
            }
        };

        let Some(_conn_guard) = self.ctx.conn_limiter.try_acquire(user.id) else {
            return;
        };
        let target_host = addr.host();
        let target_ip = addr.ip();
        let target_port = addr.port();

        if self
            .ctx
            .audit
            .should_block(&target_host, target_ip, target_port)
        {
            let _ = send
                .write_all(&[TUIC_V4_VERSION, CMD_RESPONSE, REP_FAILED])
                .await;
            let _ = send.finish();
            return;
        }

        let mctx = MatchContext {
            node_id: self.ctx.node_id,
            network: "tcp",
            target_host: &target_host,
            target_ip,
            target_port,
            inbound_local_ip: None,
        };
        let outbound = self.ctx.router.match_outbound(&mctx);

        let mut out_stream = match self
            .ctx
            .router
            .dialer()
            .dial(&outbound, &target_host, target_port, None)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "TUIC V4 outbound connect failed to {}: {:?}",
                    target_host, e
                );
                let _ = send
                    .write_all(&[TUIC_V4_VERSION, CMD_RESPONSE, REP_FAILED])
                    .await;
                let _ = send.finish();
                return;
            }
        };

        // TUIC V4 requirement: Server MUST send ResponseSucceed [04][ff][00]
        if let Err(e) = send
            .write_all(&[TUIC_V4_VERSION, CMD_RESPONSE, REP_SUCCEED])
            .await
        {
            debug!("TUIC V4 failed to send response succeed: {:?}", e);
            let _ = send.finish();
            return;
        }

        let mut client_stream = crate::conn::MonitoredStream::new(
            QuicStream::new(recv, send),
            user.id,
            self.remote_addr,
        );
        let _traffic = client_stream.traffic_guard(self.ctx.on_traffic.clone());
        let started = std::time::Instant::now();
        let result = crate::conn::copy_bidirectional_throttled(
            &mut client_stream,
            &mut out_stream,
            user.id,
            Some(&self.ctx.rate_limiter),
            self.ctx.global_config.tcp_timeout,
        )
        .await;
        let (up, down) = client_stream.stats();
        self.ctx.audit_logger.record(AuditRecord::new(
            self.ctx.node_id,
            user.id,
            "tuic",
            "tcp",
            &self.remote_addr.ip().to_string(),
            &target_host,
            target_port,
            up,
            down,
            started.elapsed().as_millis() as i64,
            &outbound.tag,
            if result.is_ok() { "completed" } else { "error" },
        ));
    }

    async fn handle_datagram(self: Arc<Self>, data: bytes::Bytes) {
        if data.len() < 2 {
            return;
        }
        let ver = data[0];
        let cmd = data[1];

        if ver != TUIC_V4_VERSION {
            return;
        }

        match cmd {
            CMD_PACKET => {
                if !self.wait_auth().await {
                    return;
                }
                if data.len() < 8 {
                    return;
                }
                let assoc_id = u32::from_be_bytes(data[2..6].try_into().unwrap());
                let data_len = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;

                let mut cursor = io::Cursor::new(&data[8..]);
                let addr = match TuicV4Address::read_from_cursor(&mut cursor) {
                    Ok(a) => a,
                    Err(_) => return,
                };
                let consumed = cursor.position() as usize;
                let payload_start = 8 + consumed;

                if data.len() < payload_start + data_len {
                    return;
                }

                let payload = data[payload_start..payload_start + data_len].to_vec();
                self.route_udp_packet(assoc_id, addr, payload, TuicV4RelayMode::Native)
                    .await;
            }
            CMD_HEARTBEAT => {}
            _ => {}
        }
    }

    async fn wait_auth(&self) -> bool {
        let authenticated = self.auth_done.notified();
        tokio::pin!(authenticated);
        authenticated.as_mut().enable();
        if self.auth_ok.load(Ordering::Acquire) {
            return true;
        }
        tokio::select! {
            _ = self.cancel.cancelled() => false,
            _ = authenticated => self.auth_ok.load(Ordering::Acquire),
            _ = tokio::time::sleep(self.auth_timeout) => false,
        }
    }

    async fn route_udp_packet(
        self: &Arc<Self>,
        assoc_id: u32,
        addr: TuicV4Address,
        payload: Vec<u8>,
        mode: TuicV4RelayMode,
    ) {
        let user = match self.authenticated_user.lock().clone() {
            Some(u) => u,
            None => return,
        };

        let tx = {
            let mut sessions = self.udp_sessions.lock();
            let tx_opt = sessions
                .get(&assoc_id)
                .filter(|tx| !tx.is_closed())
                .cloned();
            match tx_opt {
                Some(tx) => tx,
                None => {
                    let (tx, rx) = mpsc::channel(256);
                    sessions.insert(assoc_id, tx.clone());

                    let session = self.clone();
                    self.spawn(async move {
                        session
                            .clone()
                            .run_udp_association(assoc_id, user, rx, mode)
                            .await;
                        let mut sessions = session.udp_sessions.lock();
                        if sessions.get(&assoc_id).is_some_and(|tx| tx.is_closed()) {
                            sessions.remove(&assoc_id);
                        }
                    });

                    tx
                }
            }
        };

        let _ = tx.send((addr, payload, mode)).await;
    }

    async fn run_udp_association(
        self: Arc<Self>,
        assoc_id: u32,
        user: User,
        mut rx: mpsc::Receiver<(TuicV4Address, Vec<u8>, TuicV4RelayMode)>,
        initial_mode: TuicV4RelayMode,
    ) {
        let (responses, mut response_rx) = mpsc::channel::<(
            Vec<u8>,
            shadowsocks::relay::socks5::Address,
            tokio::sync::oneshot::Sender<()>,
        )>(256);
        let mut sessions: HashMap<(String, u16), mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut workers = tokio::task::JoinSet::new();
        let association_cancel = self.cancel.child_token();
        let _cancel = association_cancel.clone().drop_guard();
        let quic_conn = self.quic_conn.clone();
        let cancel = association_cancel.clone();
        let activity = Arc::new(Notify::new());
        let sent = activity.clone();
        let current_mode = Arc::new(parking_lot::RwLock::new(initial_mode));
        let current_mode_send = current_mode.clone();

        // Acknowledge only complete protocol responses to the shared accounting core.
        let send_task = self.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = response_rx.recv() => {
                        let Some((data, address, ack)) = res else { break; };
                        let len = data.len();
                        let data = data.as_slice();
                        let addr = match address {
                            shadowsocks::relay::socks5::Address::SocketAddress(addr) => TuicV4Address::from_socket_addr(addr),
                            shadowsocks::relay::socks5::Address::DomainNameAddress(host, port) => TuicV4Address::Domain(host, port),
                        };

                        let mut packet_buf = Vec::with_capacity(8 + 18 + len);
                        packet_buf.push(TUIC_V4_VERSION);
                        packet_buf.push(CMD_PACKET);
                        packet_buf.extend_from_slice(&assoc_id.to_be_bytes());
                        packet_buf.extend_from_slice(&(len as u16).to_be_bytes());
                        addr.write_to(&mut packet_buf);
                        packet_buf.extend_from_slice(data);

                        let mode = *current_mode_send.read();
                        match mode {
                            TuicV4RelayMode::Native => {
                                if quic_conn.send_datagram(packet_buf.into()).is_ok() {
                                    let _ = ack.send(());
                                        sent.notify_one();
                                }
                            }
                            TuicV4RelayMode::Quic => {
                                if let Ok(mut uni_stream) = quic_conn.open_uni().await {
                                    if uni_stream.write_all(&packet_buf).await.is_ok() {
                                        let _ = uni_stream.finish();
                                        let _ = ack.send(());
                                        sent.notify_one();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let idle_timeout = if self.ctx.global_config.udp_timeout == 0 {
            Duration::from_secs(u32::MAX as u64)
        } else {
            Duration::from_secs(self.ctx.global_config.udp_timeout)
        };
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                _ = activity.notified() => { idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout); },
                _ = &mut idle => break,
                result = workers.join_next(), if !workers.is_empty() => {
                    if let Some(Err(e)) = result { warn!(error = %e, "TUIC UDP worker failed"); }
                    sessions.retain(|_, tx| !tx.is_closed());
                },
                packet = rx.recv() => {
                    let Some((addr, payload, mode)) = packet else { break; };
                    *current_mode.write() = mode;
                    let key = (addr.host(), addr.port());
                    if key.1 == 0 { continue; }
                    if sessions.get(&key).is_none_or(|tx| tx.is_closed()) {
                        let session = match crate::conn::udp::UdpSession::connect(
                            self.ctx.clone(), user.id, self.remote_addr,
                            key.0.clone(), key.1, None, "tuic",
                        ).await {
                            Ok(session) => session,
                            Err(e) => { debug!(error = %e, "TUIC UDP rejected"); continue; }
                        };
                        let (tx, requests) = mpsc::channel(256);
                        sessions.insert(key.clone(), tx);
                        let responses = responses.clone();
                        let cancel = association_cancel.clone();
                        workers.spawn(async move { let _ = session.relay(requests, responses, cancel).await; });
                    }
                    if let Some(tx) = sessions.get(&key) {
                        tokio::select! {
                            _ = self.cancel.cancelled() => break,
                            _ = &mut idle => break,
                            _ = tx.send(payload) => {},
                        }
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                }
            }
        }
        association_cancel.cancel();
        while workers.join_next().await.is_some() {}

        send_task.abort();
    }
}
