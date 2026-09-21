use super::quic::QuicStream;
use crate::observability::AuditRecord;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

pub const TUIC_V5_VERSION: u8 = 0x05;

pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicV5RelayMode {
    Native,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuicV5Address {
    None,
    Domain(String, u16),
    IPv4(Ipv4Addr, u16),
    IPv6(Ipv6Addr, u16),
}

impl TuicV5Address {
    pub async fn read_from(reader: &mut quinn::RecvStream) -> io::Result<Self> {
        let mut atyp_buf = [0u8; 1];
        reader
            .read_exact(&mut atyp_buf)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        let atyp = atyp_buf[0];

        match atyp {
            0xff => Ok(Self::None),
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
                format!("Invalid TUIC V5 address type: 0x{:02x}", other),
            )),
        }
    }

    pub fn read_from_cursor(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Self> {
        let mut atyp_buf = [0u8; 1];
        io::Read::read_exact(cursor, &mut atyp_buf)?;
        let atyp = atyp_buf[0];

        match atyp {
            0xff => Ok(Self::None),
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
                format!("Invalid TUIC V5 address type: 0x{:02x}", other),
            )),
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        match self {
            Self::None => {
                buf.push(0xff);
            }
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
            Self::None => String::new(),
            Self::Domain(h, _) => h.clone(),
            Self::IPv4(ip, _) => ip.to_string(),
            Self::IPv6(ip, _) => ip.to_string(),
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::None | Self::Domain(..) => None,
            Self::IPv4(ip, _) => Some(IpAddr::V4(*ip)),
            Self::IPv6(ip, _) => Some(IpAddr::V6(*ip)),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::None => 0,
            Self::Domain(_, p) | Self::IPv4(_, p) | Self::IPv6(_, p) => *p,
        }
    }
}

struct V5DefragEntry {
    fragments: Vec<Option<Vec<u8>>>,
    received_count: usize,
    total_count: usize,
    deadline: Instant,
    addr: Option<TuicV5Address>,
    total_bytes: usize,
}

pub struct V5Defragmenter {
    entries: Mutex<HashMap<(u16, u16), V5DefragEntry>>,
    total_memory: Mutex<usize>,
}

const MAX_DEFRAG_ENTRIES: usize = 512;
const MAX_DEFRAG_MEMORY: usize = 16 * 1024 * 1024;

impl Default for V5Defragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl V5Defragmenter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            total_memory: Mutex::new(0),
        }
    }

    pub fn insert(
        &self,
        assoc_id: u16,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        addr: TuicV5Address,
        payload: Vec<u8>,
    ) -> Option<(TuicV5Address, Vec<u8>)> {
        let total = frag_total as usize;
        let index = frag_id as usize;

        if total == 0 || index >= total {
            return None;
        }

        if total == 1 {
            return Some((addr, payload));
        }

        let key = (assoc_id, pkt_id);
        let payload_len = payload.len();

        let mut mem_lock = self.total_memory.lock();
        if *mem_lock + payload_len > MAX_DEFRAG_MEMORY {
            return None;
        }

        let mut entries_lock = self.entries.lock();
        let now = Instant::now();

        entries_lock.retain(|_, v| {
            if v.deadline <= now {
                *mem_lock = mem_lock.saturating_sub(v.total_bytes);
                false
            } else {
                true
            }
        });

        if entries_lock.len() >= MAX_DEFRAG_ENTRIES && !entries_lock.contains_key(&key) {
            return None;
        }

        let entry = entries_lock.entry(key).or_insert_with(|| V5DefragEntry {
            fragments: vec![None; total],
            received_count: 0,
            total_count: total,
            deadline: now + Duration::from_secs(10),
            addr: None,
            total_bytes: 0,
        });

        if entry.total_count != total {
            return None;
        }

        if index == 0 && entry.addr.is_none() {
            entry.addr = Some(addr);
        }

        if entry.fragments[index].is_none() {
            entry.fragments[index] = Some(payload);
            entry.received_count += 1;
            entry.total_bytes += payload_len;
            *mem_lock += payload_len;
        }

        if entry.received_count == entry.total_count {
            let complete_entry = entries_lock.remove(&key).unwrap();
            *mem_lock = mem_lock.saturating_sub(complete_entry.total_bytes);

            let complete_addr = complete_entry.addr.unwrap_or(TuicV5Address::None);
            let mut assembled = Vec::with_capacity(complete_entry.total_bytes);
            for frag in complete_entry.fragments {
                if let Some(data) = frag {
                    assembled.extend_from_slice(&data);
                }
            }
            Some((complete_addr, assembled))
        } else {
            None
        }
    }
}

pub struct TuicV5Session {
    quic_conn: quinn::Connection,
    ctx: InboundContext,
    v5_users: Arc<HashMap<[u8; 16], (User, Vec<u8>)>>,
    auth_timeout: Duration,
    remote_addr: SocketAddr,
    auth_done: Arc<Notify>,
    auth_ok: Arc<AtomicBool>,
    authenticated_user: Arc<Mutex<Option<User>>>,
    udp_sessions: Arc<Mutex<HashMap<u16, mpsc::Sender<(TuicV5Address, Vec<u8>, TuicV5RelayMode)>>>>,
    defragmenter: Arc<V5Defragmenter>,
    cancel: CancellationToken,
    tasks: Mutex<tokio::task::JoinSet<()>>,
}

impl TuicV5Session {
    pub fn new(
        quic_conn: quinn::Connection,
        ctx: InboundContext,
        v5_users: Arc<HashMap<[u8; 16], (User, Vec<u8>)>>,
        auth_timeout: Duration,
        remote_addr: SocketAddr,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            quic_conn,
            ctx,
            v5_users,
            auth_timeout,
            remote_addr,
            auth_done: Arc::new(Notify::new()),
            auth_ok: Arc::new(AtomicBool::new(false)),
            authenticated_user: Arc::new(Mutex::new(None)),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            defragmenter: Arc::new(V5Defragmenter::new()),
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
                        debug!("TUIC V5 session auth timeout from {}", session.remote_addr);
                        let _ = session.quic_conn.close(
                            quinn::VarInt::from_u32(0x101),
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
                            debug!("TUIC V5 accept_bi error: {:?}", e);
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
                            debug!("TUIC V5 accept_uni error: {:?}", e);
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
                            debug!("TUIC V5 read_datagram error: {:?}", e);
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

        if ver != TUIC_V5_VERSION {
            let _ = self
                .quic_conn
                .close(quinn::VarInt::from_u32(0x100), b"ProtocolError");
            return;
        }

        match cmd {
            CMD_AUTHENTICATE => {
                let mut auth_body = [0u8; 48];
                if recv.read_exact(&mut auth_body).await.is_err() {
                    return;
                }

                let mut uuid_bytes = [0u8; 16];
                uuid_bytes.copy_from_slice(&auth_body[0..16]);
                let client_token = &auth_body[16..48];

                let client_ip = self.remote_addr.ip();
                let matched_user = self.v5_users.get(&uuid_bytes).cloned();

                match matched_user {
                    Some((user, password)) => {
                        let mut expected_token = [0u8; 32];
                        let export_res = self.quic_conn.export_keying_material(
                            &mut expected_token,
                            &uuid_bytes,
                            &password,
                        );

                        if export_res.is_ok() && constant_time_eq(&expected_token, client_token) {
                            self.ctx.defense.record_success(client_ip);
                            if !self
                                .ctx
                                .device_limiter
                                .check_and_record_async(user.id, client_ip)
                                .await
                            {
                                let _ = self
                                    .quic_conn
                                    .close(quinn::VarInt::from_u32(0x101), b"DeviceLimitExceeded");
                                return;
                            }

                            *self.authenticated_user.lock() = Some(user);
                            self.auth_ok.store(true, Ordering::Release);
                            self.auth_done.notify_waiters();
                        } else {
                            self.ctx.defense.record_failure(client_ip);
                            let _ = self
                                .quic_conn
                                .close(quinn::VarInt::from_u32(0x101), b"AuthenticationFailed");
                        }
                    }
                    None => {
                        self.ctx.defense.record_failure(client_ip);
                        let _ = self
                            .quic_conn
                            .close(quinn::VarInt::from_u32(0x101), b"AuthenticationFailed");
                    }
                }
            }
            CMD_PACKET => {
                if !self.wait_auth().await {
                    return;
                }
                let mut pkt_hdr = [0u8; 8];
                if recv.read_exact(&mut pkt_hdr).await.is_err() {
                    return;
                }
                let assoc_id = u16::from_be_bytes([pkt_hdr[0], pkt_hdr[1]]);
                let pkt_id = u16::from_be_bytes([pkt_hdr[2], pkt_hdr[3]]);
                let frag_total = pkt_hdr[4];
                let frag_id = pkt_hdr[5];
                let size = u16::from_be_bytes([pkt_hdr[6], pkt_hdr[7]]) as usize;

                let addr = match TuicV5Address::read_from(&mut recv).await {
                    Ok(a) => a,
                    Err(_) => return,
                };

                let mut data = vec![0u8; size];
                if recv.read_exact(&mut data).await.is_err() {
                    return;
                }

                if let Some((assembled_addr, assembled_data)) = self
                    .defragmenter
                    .insert(assoc_id, pkt_id, frag_total, frag_id, addr, data)
                {
                    self.route_udp_packet(
                        assoc_id,
                        assembled_addr,
                        assembled_data,
                        TuicV5RelayMode::Quic,
                    )
                    .await;
                }
            }
            CMD_DISSOCIATE => {
                if !self.wait_auth().await {
                    return;
                }
                let mut assoc_buf = [0u8; 2];
                if recv.read_exact(&mut assoc_buf).await.is_err() {
                    return;
                }
                let assoc_id = u16::from_be_bytes(assoc_buf);
                self.udp_sessions.lock().remove(&assoc_id);
            }
            CMD_HEARTBEAT => {}
            _ => {
                let _ = self
                    .quic_conn
                    .close(quinn::VarInt::from_u32(0x102), b"BadCommand");
            }
        }
    }

    async fn handle_bidi_stream(
        self: Arc<Self>,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        let read_res = tokio::time::timeout(Duration::from_secs(5), async {
            let mut hdr = [0u8; 2];
            recv.read_exact(&mut hdr)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            let addr = TuicV5Address::read_from(&mut recv).await?;
            Ok::<_, io::Error>((hdr, addr))
        })
        .await;

        let ([ver, cmd], addr) = match read_res {
            Ok(Ok(res)) => res,
            _ => {
                let mut send = send;
                let _ = send.finish();
                return;
            }
        };

        if ver != TUIC_V5_VERSION || cmd != CMD_CONNECT {
            let mut send = send;
            let _ = send.finish();
            return;
        }

        if !self.wait_auth().await {
            let mut send = send;
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
                let mut send = send;
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
            let mut send = send;
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
                    "TUIC V5 outbound connect failed to {}: {:?}",
                    target_host, e
                );
                let mut send = send;
                let _ = send.finish();
                return;
            }
        };

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

        if ver != TUIC_V5_VERSION {
            return;
        }

        match cmd {
            CMD_PACKET => {
                if !self.wait_auth().await {
                    return;
                }
                if data.len() < 10 {
                    return;
                }
                let assoc_id = u16::from_be_bytes([data[2], data[3]]);
                let pkt_id = u16::from_be_bytes([data[4], data[5]]);
                let frag_total = data[6];
                let frag_id = data[7];
                let size = u16::from_be_bytes([data[8], data[9]]) as usize;

                let mut cursor = io::Cursor::new(&data[10..]);
                let addr = match TuicV5Address::read_from_cursor(&mut cursor) {
                    Ok(a) => a,
                    Err(_) => return,
                };
                let consumed = cursor.position() as usize;
                let payload_start = 10 + consumed;

                if data.len() < payload_start + size {
                    return;
                }

                let payload = data[payload_start..payload_start + size].to_vec();

                if let Some((assembled_addr, assembled_data)) = self
                    .defragmenter
                    .insert(assoc_id, pkt_id, frag_total, frag_id, addr, payload)
                {
                    self.route_udp_packet(
                        assoc_id,
                        assembled_addr,
                        assembled_data,
                        TuicV5RelayMode::Native,
                    )
                    .await;
                }
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
        assoc_id: u16,
        addr: TuicV5Address,
        payload: Vec<u8>,
        mode: TuicV5RelayMode,
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
        assoc_id: u16,
        user: User,
        mut rx: mpsc::Receiver<(TuicV5Address, Vec<u8>, TuicV5RelayMode)>,
        initial_mode: TuicV5RelayMode,
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
        let current_mode = Arc::new(RwLock::new(initial_mode));
        let current_mode_send = current_mode.clone();
        let packet_id_seq = Arc::new(AtomicU16::new(0));
        let packet_id_seq_recv = packet_id_seq.clone();

        let send_task = self.spawn(async move {
            let max_packet_size = 1200 - 3;

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = response_rx.recv() => {
                        let Some((data, address, ack)) = res else { break; };
                        let len = data.len();
                        let data = data.as_slice();
                        let addr = match address {
                            shadowsocks::relay::socks5::Address::SocketAddress(addr) => TuicV5Address::from_socket_addr(addr),
                            shadowsocks::relay::socks5::Address::DomainNameAddress(host, port) => TuicV5Address::Domain(host, port),
                        };
                        let pkt_id = packet_id_seq_recv.fetch_add(1, Ordering::Relaxed);
                        let mode = *current_mode_send.read();

                        match mode {
                            TuicV5RelayMode::Native => {

                                let mut dummy_hdr = Vec::new();
                                addr.write_to(&mut dummy_hdr);
                                let header_overhead = 10 + dummy_hdr.len();

                                if len + header_overhead <= max_packet_size {
                                    let mut packet_buf = Vec::with_capacity(header_overhead + len);
                                    packet_buf.push(TUIC_V5_VERSION);
                                    packet_buf.push(CMD_PACKET);
                                    packet_buf.extend_from_slice(&assoc_id.to_be_bytes());
                                    packet_buf.extend_from_slice(&pkt_id.to_be_bytes());
                                    packet_buf.push(1);
                                    packet_buf.push(0);
                                    packet_buf.extend_from_slice(&(len as u16).to_be_bytes());
                                    addr.write_to(&mut packet_buf);
                                    packet_buf.extend_from_slice(data);

                                    if quic_conn.send_datagram(packet_buf.into()).is_ok() {
                                        let _ = ack.send(());
                                        sent.notify_one();
                                    }
                                } else {

                                    let fragment_data_mtu = max_packet_size.saturating_sub(header_overhead);
                                    if fragment_data_mtu == 0 {
                                        continue;
                                    }
                                    let chunks: Vec<&[u8]> = data.chunks(fragment_data_mtu).collect();
                                    let frag_total = chunks.len() as u8;

                                    let mut sent_all = true;
                                    for (i, chunk) in chunks.into_iter().enumerate() {
                                        let mut frag_buf = Vec::with_capacity(12 + chunk.len());
                                        frag_buf.push(TUIC_V5_VERSION);
                                        frag_buf.push(CMD_PACKET);
                                        frag_buf.extend_from_slice(&assoc_id.to_be_bytes());
                                        frag_buf.extend_from_slice(&pkt_id.to_be_bytes());
                                        frag_buf.push(frag_total);
                                        frag_buf.push(i as u8);
                                        frag_buf.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                                        if i == 0 {
                                            addr.write_to(&mut frag_buf);
                                        } else {
                                            TuicV5Address::None.write_to(&mut frag_buf);
                                        }
                                        frag_buf.extend_from_slice(chunk);

                                        if quic_conn.send_datagram(frag_buf.into()).is_err() {
                                            sent_all = false;
                                            break;
                                        }
                                    }
                                    if sent_all {
                                        let _ = ack.send(());
                                        sent.notify_one();
                                    }
                                }
                            }
                            TuicV5RelayMode::Quic => {

                                let mut packet_buf = Vec::with_capacity(10 + 18 + len);
                                packet_buf.push(TUIC_V5_VERSION);
                                packet_buf.push(CMD_PACKET);
                                packet_buf.extend_from_slice(&assoc_id.to_be_bytes());
                                packet_buf.extend_from_slice(&pkt_id.to_be_bytes());
                                packet_buf.push(1);
                                packet_buf.push(0);
                                packet_buf.extend_from_slice(&(len as u16).to_be_bytes());
                                addr.write_to(&mut packet_buf);
                                packet_buf.extend_from_slice(data);

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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconsistent_fragment_count_does_not_index_out_of_bounds() {
        let fragments = V5Defragmenter::new();
        let address = TuicV5Address::None;
        assert!(fragments
            .insert(1, 2, 2, 0, address.clone(), vec![1])
            .is_none());
        assert!(fragments
            .insert(1, 2, 3, 2, address.clone(), vec![2])
            .is_none());
        let (_, payload) = fragments.insert(1, 2, 2, 1, address, vec![3]).unwrap();
        assert_eq!(payload, vec![1, 3]);
        assert_eq!(*fragments.total_memory.lock(), 0);
    }
}
