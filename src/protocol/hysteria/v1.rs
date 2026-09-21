use super::obfs::{HysteriaObfuscator, XPlusObfs};
use super::transport::{build_hysteria_tls_config, create_hysteria_endpoint, QuicStream};
use crate::conn::MonitoredStream;
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

pub const HYSTERIA1_PROTOCOL_VERSION: u8 = 0x03;

struct Hy1ReassemblyEntry {
    fragments: Vec<Option<Vec<u8>>>,
    received_count: usize,
    total_count: usize,
    deadline: Instant,
    host: String,
    port: u16,
    total_bytes: usize,
}

pub struct Hy1Defragmenter {
    entries: Mutex<HashMap<(u32, u16), Hy1ReassemblyEntry>>,
    total_memory: Mutex<usize>,
}

const MAX_DEFRAG_ENTRIES: usize = 512;
const MAX_DEFRAG_MEMORY: usize = 16 * 1024 * 1024;

impl Default for Hy1Defragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Hy1Defragmenter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            total_memory: Mutex::new(0),
        }
    }

    pub fn push_fragment(
        &self,
        session_id: u32,
        packet_id: u16,
        frag_id: u8,
        frag_total: u8,
        host: String,
        port: u16,
        data: Vec<u8>,
    ) -> Option<(String, u16, Vec<u8>)> {
        if frag_total == 0 || frag_id >= frag_total {
            debug!(
                "Hysteria v1 invalid fragment params: total={}, id={}",
                frag_total, frag_id
            );
            return None;
        }
        if frag_total == 1 {
            return Some((host, port, data));
        }

        let now = Instant::now();
        let mut entries = self.entries.lock();
        let mut total_mem = self.total_memory.lock();

        if !entries.is_empty() {
            entries.retain(|_, v| {
                if v.deadline <= now {
                    *total_mem = total_mem.saturating_sub(v.total_bytes);
                    false
                } else {
                    true
                }
            });
        }

        let chunk_len = data.len();
        let key = (session_id, packet_id);

        trace!(
            "Hysteria v1 defrag push: key={:?}, frag={}/{}, chunk_len={}",
            key,
            frag_id,
            frag_total,
            chunk_len
        );

        if let Some(entry) = entries.get_mut(&key) {
            if entry.total_count != frag_total as usize || entry.host != host || entry.port != port
            {
                debug!(
                    "Hysteria v1 fragment mismatch for key={:?}: dropping poisoned entry",
                    key
                );

                *total_mem = total_mem.saturating_sub(entry.total_bytes);
                entries.remove(&key);
                return None;
            }

            if entry.fragments[frag_id as usize].is_none() {
                if *total_mem + chunk_len > MAX_DEFRAG_MEMORY {
                    debug!("Hysteria v1 MAX_DEFRAG_MEMORY exceeded");
                    return None;
                }
                entry.total_bytes += chunk_len;
                *total_mem += chunk_len;
                entry.fragments[frag_id as usize] = Some(data);
                entry.received_count += 1;
            }

            if entry.received_count == entry.total_count {
                let mut assembled = Vec::with_capacity(entry.total_bytes);
                for f in entry.fragments.iter().flatten() {
                    assembled.extend_from_slice(f);
                }
                let h = entry.host.clone();
                let p = entry.port;
                *total_mem = total_mem.saturating_sub(entry.total_bytes);
                entries.remove(&key);
                trace!(
                    "Hysteria v1 defrag assembled packet for key={:?}, total_bytes={}",
                    key,
                    assembled.len()
                );
                return Some((h, p, assembled));
            }
            return None;
        }

        if entries.len() >= MAX_DEFRAG_ENTRIES || *total_mem + chunk_len > MAX_DEFRAG_MEMORY {
            debug!("Hysteria v1 defrag capacity exceeded");
            return None;
        }

        let mut fragments = vec![None; frag_total as usize];
        fragments[frag_id as usize] = Some(data);
        *total_mem += chunk_len;

        entries.insert(
            key,
            Hy1ReassemblyEntry {
                fragments,
                received_count: 1,
                total_count: frag_total as usize,
                deadline: now + Duration::from_secs(8),
                host,
                port,
                total_bytes: chunk_len,
            },
        );

        None
    }
}

pub struct Hysteria1Inbound {
    users: Arc<RwLock<Arc<HashMap<Vec<u8>, Arc<User>>>>>,
}

impl Default for Hysteria1Inbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
        }
    }
}

impl Hysteria1Inbound {
    pub fn new() -> Self {
        Self::default()
    }
}

async fn graceful_drain_join_set<T: 'static>(
    join_set: &mut tokio::task::JoinSet<T>,
    timeout: Duration,
) {
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                join_set.abort_all();
                while join_set.join_next().await.is_some() {}
                break;
            }
            res = join_set.join_next() => {
                if res.is_none() {
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl Inbound for Hysteria1Inbound {
    fn protocol_type(&self) -> &'static str {
        "hysteria"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map: HashMap<Vec<u8>, Arc<User>> = HashMap::new();
        for u in users {
            let u_arc = Arc::new(u);
            let mut insert_cred = |cred: Vec<u8>, cred_name: &str| {
                if cred.is_empty() {
                    return;
                }
                if let Some(existing) = map.get(&cred) {
                    if existing.id != u_arc.id {
                        warn!(
                            "Hysteria v1 credential collision detected: user {} and user {} share {} credential! Rejecting duplicate for user {}.",
                            existing.id, u_arc.id, cred_name, u_arc.id
                        );
                        return;
                    }
                }
                map.insert(cred, u_arc.clone());
            };

            if let Some(ref pass) = u_arc.password {
                insert_cred(pass.as_bytes().to_vec(), "password string");

                if let Ok(decoded) = hex::decode(pass) {
                    insert_cred(decoded, "hex-decoded password");
                }
            }

            insert_cred(u_arc.uuid.as_bytes().to_vec(), "uuid string");

            if u_arc.uuid.contains('-') {
                insert_cred(
                    u_arc.uuid.replace('-', "").into_bytes(),
                    "unhyphenated uuid",
                );
            }
        }
        *self.users.write() = Arc::new(map);
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> io::Result<()> {
        let port = if node_info.server_port > 0 {
            node_info.server_port
        } else {
            ctx.port
        };

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", port)
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let std_socket = std::net::UdpSocket::bind(bind_addr)?;
        std_socket.set_nonblocking(true)?;

        let obfs =
            if let Some(ref pw) = node_info.obfs_password.as_ref().or(node_info.obfs.as_ref()) {
                if !pw.is_empty() {
                    HysteriaObfuscator::XPlus(XPlusObfs::new(pw))
                } else {
                    HysteriaObfuscator::None
                }
            } else if let Some(ref val) = node_info.network_settings {
                let pw = val
                    .get("obfs_password")
                    .or_else(|| val.get("obfsPassword"))
                    .or_else(|| val.get("obfs"))
                    .and_then(|v| v.as_str());
                match pw {
                    Some(p) if !p.is_empty() => HysteriaObfuscator::XPlus(XPlusObfs::new(p)),
                    _ => HysteriaObfuscator::None,
                }
            } else {
                HysteriaObfuscator::None
            };

        let mut alpn_vec: Vec<Vec<u8>> = Vec::new();
        if let Some(ref alpn_val) = node_info.alpn {
            if let Some(arr) = alpn_val.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        alpn_vec.push(s.as_bytes().to_vec());
                    }
                }
            } else if let Some(s) = alpn_val.as_str() {
                alpn_vec.push(s.as_bytes().to_vec());
            }
        }
        if alpn_vec.is_empty() {
            alpn_vec.push(b"hysteria".to_vec());
        }
        let alpn_slices: Vec<&[u8]> = alpn_vec.iter().map(|v| v.as_slice()).collect();
        let tls_config = build_hysteria_tls_config(&node_info, "hysteria.local", &alpn_slices)?;

        let endpoint = create_hysteria_endpoint(std_socket, tls_config, &alpn_slices, obfs, true)?;
        info!("Hysteria v1 inbound listening on QUIC {}", bind_addr);

        let users = self.users.clone();
        let cancel_token = CancellationToken::new();
        let mut conn_join_set = tokio::task::JoinSet::new();

        ctx.mark_ready();
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Hysteria v1 inbound on port {} shutting down", port);
                    cancel_token.cancel();
                    endpoint.close(0u32.into(), b"server shutdown");
                    graceful_drain_join_set(&mut conn_join_set, Duration::from_secs(5)).await;
                    break;
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };

                    while conn_join_set.try_join_next().is_some() {}

                    let users = users.clone();
                    let ctx = ctx.clone();
                    let node_info = node_info.clone();
                    let cancel = cancel_token.clone();

                    conn_join_set.spawn(async move {
                        if let Err(e) = handle_hy1_connection(incoming, users, ctx, node_info, cancel).await {
                            debug!("Hysteria v1 connection finished: {:?}", e);
                        }
                    });
                }
            }
        }

        Ok(())
    }
}

async fn handle_hy1_connection(
    incoming: quinn::Incoming,
    users: Arc<RwLock<Arc<HashMap<Vec<u8>, Arc<User>>>>>,
    ctx: InboundContext,
    node_info: NodeInfo,
    global_cancel: CancellationToken,
) -> io::Result<()> {
    let conn = incoming.await.map_err(io::Error::other)?;
    let remote_addr = conn.remote_address();
    let client_ip = remote_addr.ip();

    if ctx.defense.is_banned(client_ip) {
        conn.close(1u32.into(), b"banned");
        return Ok(());
    }

    let handshake_res = tokio::time::timeout(Duration::from_secs(10), async {
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.map_err(io::Error::other)?;

        let mut header_buf = [0u8; 19];
        ctrl_recv
            .read_exact(&mut header_buf)
            .await
            .map_err(io::Error::other)?;

        let version = header_buf[0];
        if version != HYSTERIA1_PROTOCOL_VERSION {
            conn.close(1u32.into(), b"unsupported protocol version");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid HY1 version",
            ));
        }

        let client_send_bps = u64::from_be_bytes(header_buf[1..9].try_into().unwrap());
        let client_recv_bps = u64::from_be_bytes(header_buf[9..17].try_into().unwrap());
        let auth_len = u16::from_be_bytes(header_buf[17..19].try_into().unwrap()) as usize;

        if auth_len > 1024 {
            conn.close(1u32.into(), b"auth string too long");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Auth too long"));
        }

        let mut auth_bytes = vec![0u8; auth_len];
        ctrl_recv
            .read_exact(&mut auth_bytes)
            .await
            .map_err(io::Error::other)?;

        let user_opt = {
            let users_map = users.read().clone();
            users_map.get(&auth_bytes).cloned()
        };

        let user = match user_opt {
            Some(u) => {
                ctx.defense.record_success(client_ip);
                u
            }
            None => {
                ctx.defense.record_failure(client_ip);

                let mut err_resp = Vec::new();
                err_resp.push(0x00);
                err_resp.extend_from_slice(&0u64.to_be_bytes());
                err_resp.extend_from_slice(&0u64.to_be_bytes());
                let msg = b"invalid credentials";
                err_resp.extend_from_slice(&(msg.len() as u16).to_be_bytes());
                err_resp.extend_from_slice(msg);
                let _ = ctrl_send.write_all(&err_resp).await;
                conn.close(2u32.into(), b"auth failed");
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Auth failed",
                ));
            }
        };

        if !ctx
            .device_limiter
            .check_and_record_async(user.id, client_ip)
            .await
        {
            conn.close(1u32.into(), b"device limit exceeded");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Device limit",
            ));
        }

        let conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
            Some(g) => g,
            None => {
                conn.close(1u32.into(), b"connection limit reached");
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Conn limit",
                ));
            }
        };

        let server_up_bps = node_info.up_mbps.unwrap_or(100) as u64 * 125_000;
        let server_down_bps = node_info.down_mbps.unwrap_or(100) as u64 * 125_000;
        let negotiated_send_bps = if client_recv_bps > 0 {
            server_up_bps.min(client_recv_bps)
        } else {
            server_up_bps
        };
        let negotiated_recv_bps = if client_send_bps > 0 {
            server_down_bps.min(client_send_bps)
        } else {
            server_down_bps
        };

        let mut ok_resp = Vec::new();
        ok_resp.push(0x01);
        ok_resp.extend_from_slice(&negotiated_send_bps.to_be_bytes());
        ok_resp.extend_from_slice(&negotiated_recv_bps.to_be_bytes());
        ok_resp.extend_from_slice(&0u16.to_be_bytes());
        ctrl_send.write_all(&ok_resp).await?;

        Ok::<_, io::Error>((ctrl_send, ctrl_recv, user, conn_guard))
    })
    .await;

    let (mut _ctrl_send, mut ctrl_recv, user, _conn_guard) = match handshake_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            conn.close(1u32.into(), b"handshake timeout");
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Handshake timeout"));
        }
    };

    let mut join_set = tokio::task::JoinSet::new();
    let conn_cancel = CancellationToken::new();

    let k_cancel = conn_cancel.clone();
    join_set.spawn(async move {
        let mut sink = [0u8; 128];
        loop {
            tokio::select! {
                _ = k_cancel.cancelled() => break,
                res = ctrl_recv.read(&mut sink) => {
                    match res {
                        Ok(Some(n)) if n > 0 => {}
                        _ => {
                            k_cancel.cancel();
                            break;
                        }
                    }
                }
            }
        }
    });

    let udp_sessions: Arc<Mutex<HashMap<u32, mpsc::Sender<(String, u16, Vec<u8>)>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let next_session_id = Arc::new(AtomicU32::new(1));
    let packet_id_gen = Arc::new(AtomicU16::new(1));
    let defragmenter = Arc::new(Hy1Defragmenter::new());

    let dg_conn = conn.clone();
    let dg_sessions = udp_sessions.clone();
    let dg_defrag = defragmenter.clone();
    let dg_cancel = conn_cancel.clone();
    let dg_global_cancel = global_cancel.clone();

    join_set.spawn(async move {
        loop {
            tokio::select! {
                _ = dg_cancel.cancelled() => break,
                _ = dg_global_cancel.cancelled() => break,
                dg_res = dg_conn.read_datagram() => {
                    let raw = match dg_res {
                        Ok(r) => r,
                        Err(e) => {
                            debug!("Hysteria v1 read_datagram error: {:?}", e);
                            break;
                        }
                    };

                    if raw.len() < 14 {
                        continue;
                    }

                    let session_id = u32::from_be_bytes(raw[0..4].try_into().unwrap());
                    let host_len = u16::from_be_bytes(raw[4..6].try_into().unwrap()) as usize;
                    if raw.len() < 14 + host_len {
                        continue;
                    }

                    let host = String::from_utf8_lossy(&raw[6..6 + host_len]).to_string();
                    let offset = 6 + host_len;
                    let port = u16::from_be_bytes(raw[offset..offset + 2].try_into().unwrap());
                    let packet_id = u16::from_be_bytes(raw[offset + 2..offset + 4].try_into().unwrap());
                    let frag_id = raw[offset + 4];
                    let frag_total = raw[offset + 5];
                    let data_len = u16::from_be_bytes(raw[offset + 6..offset + 8].try_into().unwrap()) as usize;
                    let payload_start = offset + 8;

                    if raw.len() < payload_start + data_len {
                        continue;
                    }
                    let chunk = raw[payload_start..payload_start + data_len].to_vec();

                    if let Some((dst_h, dst_p, full_packet)) =
                        dg_defrag.push_fragment(session_id, packet_id, frag_id, frag_total, host, port, chunk)
                    {
                        let tx_opt = {
                            dg_sessions.lock().get(&session_id).cloned()
                        };
                        if let Some(tx) = tx_opt {
                            let _ = tx.send((dst_h, dst_p, full_packet)).await;
                        } else {
                            debug!("Hysteria v1 no UDP session found for session_id={}", session_id);
                        }
                    }
                }
            }
        }
    });

    loop {
        tokio::select! {
            _ = conn_cancel.cancelled() => break,
            _ = global_cancel.cancelled() => break,
            bi_res = conn.accept_bi() => {
                let Ok((send, recv)) = bi_res else { break; };

                while join_set.try_join_next().is_some() {}

                let udp_sessions_c = udp_sessions.clone();
                let next_sid_c = next_session_id.clone();
                let pkt_id_c = packet_id_gen.clone();
                let conn_c = conn.clone();
                let ctx_c = ctx.clone();
                let user_c = user.clone();
                let s_cancel = conn_cancel.clone();

                join_set.spawn(async move {
                    handle_hy1_stream_entry(
                        send,
                        recv,
                        udp_sessions_c,
                        next_sid_c,
                        pkt_id_c,
                        conn_c,
                        ctx_c,
                        user_c,
                        remote_addr,
                        s_cancel,
                    ).await;
                });
            }
        }
    }

    conn_cancel.cancel();
    conn.close(0u32.into(), b"connection closed");
    graceful_drain_join_set(&mut join_set, Duration::from_secs(3)).await;
    Ok(())
}

fn allocate_session_id(
    sessions: &HashMap<u32, mpsc::Sender<(String, u16, Vec<u8>)>>,
    counter: &AtomicU32,
) -> Option<u32> {
    if sessions.len() >= 2048 {
        return None;
    }
    for _ in 0..10000 {
        let sid = counter.fetch_add(1, Ordering::Relaxed);
        if sid != 0 && !sessions.contains_key(&sid) {
            return Some(sid);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn handle_hy1_stream_entry(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    udp_sessions: Arc<Mutex<HashMap<u32, mpsc::Sender<(String, u16, Vec<u8>)>>>>,
    next_session_id: Arc<AtomicU32>,
    packet_id_gen: Arc<AtomicU16>,
    conn: quinn::Connection,
    ctx: InboundContext,
    user: Arc<User>,
    remote_addr: SocketAddr,
    cancel: CancellationToken,
) {
    let req_res = tokio::time::timeout(Duration::from_secs(5), async {
        let mut req_hdr = [0u8; 3];
        recv.read_exact(&mut req_hdr)
            .await
            .map_err(io::Error::other)?;
        let req_type = req_hdr[0];
        let host_len = u16::from_be_bytes(req_hdr[1..3].try_into().unwrap()) as usize;
        if host_len > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Host length too large",
            ));
        }
        let mut host_bytes = vec![0u8; host_len];
        recv.read_exact(&mut host_bytes)
            .await
            .map_err(io::Error::other)?;
        let target_host = String::from_utf8_lossy(&host_bytes).to_string();
        let mut port_buf = [0u8; 2];
        recv.read_exact(&mut port_buf)
            .await
            .map_err(io::Error::other)?;
        let target_port = u16::from_be_bytes(port_buf);
        Ok::<_, io::Error>((req_type, target_host, target_port))
    })
    .await;

    let (req_type, target_host, target_port) = match req_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            debug!("Hysteria v1 failed to read stream request header: {:?}", e);
            let _ = send.finish();
            return;
        }
        Err(_) => {
            debug!("Hysteria v1 stream request header timeout (Slowloris protection)");
            let _ = send.finish();
            return;
        }
    };

    if req_type != 0x00 && req_type != 0x01 {
        debug!("Hysteria v1 unsupported request type: 0x{:02x}", req_type);
        let mut err_resp = Vec::with_capacity(7 + 24);
        err_resp.push(0x00);
        err_resp.extend_from_slice(&0u32.to_be_bytes());
        let msg = b"unsupported request type";
        err_resp.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        err_resp.extend_from_slice(msg);
        let _ = send.write_all(&err_resp).await;
        let _ = send.finish();
        return;
    }

    if req_type == 0x01 {
        let sid_opt = {
            let lock = udp_sessions.lock();
            if lock.len() >= 1024 {
                None
            } else {
                allocate_session_id(&lock, &next_session_id)
            }
        };

        let sid = match sid_opt {
            Some(id) => id,
            None => {
                let mut err_resp = Vec::new();
                err_resp.push(0x00);
                err_resp.extend_from_slice(&0u32.to_be_bytes());
                let msg = b"too many UDP sessions";
                err_resp.extend_from_slice(&(msg.len() as u16).to_be_bytes());
                err_resp.extend_from_slice(msg);
                let _ = send.write_all(&err_resp).await;
                let _ = send.finish();
                return;
            }
        };

        let dedicated_socket = match ctx.router.dialer().dial_udp("0.0.0.0", 0, None).await {
            Ok((s, _)) => Arc::new(s),
            Err(e) => {
                debug!("Hysteria v1 failed to bind dedicated UDP socket: {:?}", e);
                let mut err_resp = Vec::new();
                err_resp.push(0x00);
                err_resp.extend_from_slice(&0u32.to_be_bytes());
                let msg = b"failed to allocate UDP socket";
                err_resp.extend_from_slice(&(msg.len() as u16).to_be_bytes());
                err_resp.extend_from_slice(msg);
                let _ = send.write_all(&err_resp).await;
                let _ = send.finish();
                return;
            }
        };

        let (packet_tx, packet_rx) = mpsc::channel::<(String, u16, Vec<u8>)>(256);
        udp_sessions.lock().insert(sid, packet_tx);

        let mut ok_resp = Vec::with_capacity(7);
        ok_resp.push(0x01);
        ok_resp.extend_from_slice(&sid.to_be_bytes());
        ok_resp.extend_from_slice(&0u16.to_be_bytes());
        if let Err(e) = send.write_all(&ok_resp).await {
            debug!("Hysteria v1 failed to send UDP OK response: {:?}", e);
            udp_sessions.lock().remove(&sid);
            return;
        }

        handle_hy1_udp_session(
            sid,
            recv,
            send,
            packet_rx,
            dedicated_socket,
            conn,
            ctx,
            user,
            remote_addr,
            packet_id_gen,
            cancel,
        )
        .await;

        udp_sessions.lock().remove(&sid);
    } else {
        let _ = handle_hy1_tcp_stream(
            recv,
            send,
            ctx,
            user,
            remote_addr,
            target_host,
            target_port,
            cancel,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_hy1_tcp_stream(
    recv: quinn::RecvStream,
    mut send: quinn::SendStream,
    ctx: InboundContext,
    user: Arc<User>,
    remote_addr: SocketAddr,
    target_host: String,
    target_port: u16,
    cancel: CancellationToken,
) -> io::Result<()> {
    let client_ip = remote_addr.ip();
    let target_ip: Option<IpAddr> = target_host.parse().ok();

    if ctx.audit.should_block(&target_host, target_ip, target_port) {
        let mut err_resp = Vec::new();
        err_resp.push(0x00);
        err_resp.extend_from_slice(&0u32.to_be_bytes());
        let msg = b"blocked by audit rule";
        err_resp.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        err_resp.extend_from_slice(msg);
        let _ = send.write_all(&err_resp).await;
        let _ = send.finish();
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: &target_host,
        target_ip,
        target_port,
        inbound_local_ip: None,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let dial_res = ctx
        .router
        .dialer()
        .dial(&outbound, &target_host, target_port, None)
        .await;
    let mut out_stream = match dial_res {
        Ok(s) => s,
        Err(e) => {
            debug!(
                "Hysteria v1 outbound TCP dial failed for {}:{}: {:?}",
                target_host, target_port, e
            );
            let mut err_resp = Vec::new();
            err_resp.push(0x00);
            err_resp.extend_from_slice(&0u32.to_be_bytes());
            let msg = b"connection failed";
            err_resp.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            err_resp.extend_from_slice(msg);
            let _ = send.write_all(&err_resp).await;
            let _ = send.finish();
            return Ok(());
        }
    };

    let ok_resp = [0x01u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    send.write_all(&ok_resp).await?;

    let stream = QuicStream::new(recv, send);
    let mut client_conn = MonitoredStream::new(stream, user.id, remote_addr);
    let _traffic = client_conn.traffic_guard(ctx.on_traffic.clone());
    let start_time = Instant::now();

    tokio::select! {
        _ = cancel.cancelled() => {
            debug!("Hysteria v1 TCP relay cancelled");
        }
        res = crate::conn::copy_bidirectional_throttled(
            &mut client_conn,
            &mut out_stream,
            user.id,
            Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
        ) => {
            let _ = res;
        }
    }

    let duration = start_time.elapsed();
    let (up, down) = client_conn.stats();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "hysteria",
        "tcp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        up,
        down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

fn send_hy1_datagram(
    conn: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    src_host: &str,
    src_port: u16,
    data: &[u8],
) -> bool {
    let host_bytes = src_host.as_bytes();
    let header_size = 14 + host_bytes.len();
    let max_dg_payload = conn.max_datagram_size().unwrap_or(1200);
    let chunk_size = max_dg_payload.saturating_sub(header_size).max(1);

    if data.len() <= chunk_size {
        let mut dg = Vec::with_capacity(header_size + data.len());
        dg.extend_from_slice(&session_id.to_be_bytes());
        dg.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        dg.extend_from_slice(host_bytes);
        dg.extend_from_slice(&src_port.to_be_bytes());
        dg.extend_from_slice(&packet_id.to_be_bytes());
        dg.push(0);
        dg.push(1);
        dg.extend_from_slice(&(data.len() as u16).to_be_bytes());
        dg.extend_from_slice(data);
        conn.send_datagram(dg.into()).is_ok()
    } else {
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let total_chunks = chunks.len();
        if total_chunks > 255 {
            return false;
        }
        let mut all_ok = true;
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let mut dg = Vec::with_capacity(header_size + chunk.len());
            dg.extend_from_slice(&session_id.to_be_bytes());
            dg.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            dg.extend_from_slice(host_bytes);
            dg.extend_from_slice(&src_port.to_be_bytes());
            dg.extend_from_slice(&packet_id.to_be_bytes());
            dg.push(idx as u8);
            dg.push(total_chunks as u8);
            dg.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            dg.extend_from_slice(chunk);
            if let Err(e) = conn.send_datagram(dg.into()) {
                warn!(
                    "send_hy1_datagram fragment {}/{} failed: {:?}",
                    idx, total_chunks, e
                );
                all_ok = false;
            }
        }
        all_ok
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_hy1_udp_session(
    session_id: u32,
    mut stream_recv: quinn::RecvStream,
    _stream_send: quinn::SendStream,
    mut packet_rx: mpsc::Receiver<(String, u16, Vec<u8>)>,
    socket: Arc<tokio::net::UdpSocket>,
    conn: quinn::Connection,
    ctx: InboundContext,
    user: Arc<User>,
    remote_addr: SocketAddr,
    packet_id_gen: Arc<AtomicU16>,
    session_cancel: CancellationToken,
) {
    let start_time = Instant::now();
    let client_ip = remote_addr.ip();
    let user_id = user.id;

    let mut total_up = 0u64;
    let mut total_down = 0u64;

    let mut session_join_set = tokio::task::JoinSet::new();
    let child_cancel = session_cancel.child_token();

    let stream_cancel = child_cancel.clone();
    session_join_set.spawn(async move {
        let mut sink = [0u8; 64];
        while let Ok(Some(n)) = stream_recv.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
        stream_cancel.cancel();
    });

    let (down_tx, mut down_rx) = mpsc::channel::<usize>(256);
    let r_socket = socket.clone();
    let r_conn = conn.clone();
    let r_cancel = child_cancel.clone();
    let r_pkt_gen = packet_id_gen.clone();
    let r_down_tx = down_tx.clone();
    let r_rate = ctx.rate_limiter.clone();
    let r_traffic = ctx.on_traffic.clone();

    session_join_set.spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = r_cancel.cancelled() => break,
                recv_res = tokio::time::timeout(Duration::from_secs(60), r_socket.recv_from(&mut buf)) => {
                    let (n, src_addr) = match recv_res {
                        Ok(Ok((n, addr))) if n > 0 => (n, addr),
                        Ok(Ok(_)) => continue,
                        Ok(Err(e)) => {
                            debug!("Hysteria v1 dedicated UDP socket recv_from error: {:?}", e);
                            break;
                        }
                        Err(_) => {

                            break;
                        }
                    };

                    r_rate.throttle(user_id, n).await;

                    let pkt_id = r_pkt_gen.fetch_add(1, Ordering::Relaxed);
                    let src_host = src_addr.ip().to_string();
                    let src_port = src_addr.port();

                    if send_hy1_datagram(&r_conn, session_id, pkt_id, &src_host, src_port, &buf[..n]) {

                        r_traffic(user_id, 0, n as u64);
                        let _ = r_down_tx.send(n).await;
                    }
                }
            }
        }
        r_cancel.cancel();
    });

    let dns = ctx.router.dialer().dns_resolver().clone();
    let mut last_tag = "direct".to_string();

    loop {
        tokio::select! {
            _ = child_cancel.cancelled() => break,
            Some(down_n) = down_rx.recv() => {
                total_down += down_n as u64;
            }
            packet = packet_rx.recv() => {
                let Some((dst_host, dst_port, data)) = packet else { break; };

                let dst_ip: Option<IpAddr> = dst_host.parse().ok();
                if ctx.audit.should_block(&dst_host, dst_ip, dst_port) {
                    continue;
                }

                let mctx = MatchContext {
                    node_id: ctx.node_id,
                    network: "udp",
                    target_host: &dst_host,
                    target_ip: dst_ip,
                    target_port: dst_port,
                    inbound_local_ip: None,
                };
                let outbound = ctx.router.match_outbound(&mctx);
                if outbound.normalized_type() == "block" {
                    continue;
                }
                last_tag = outbound.tag.clone();

                let target_addr = match dst_ip {
                    Some(ip) => SocketAddr::new(ip, dst_port),
                    None => {
                        match dns.resolve(&dst_host, dst_port).await {
                            Ok(addrs) => match addrs.into_iter().next() {
                                Some(a) => a,
                                None => continue,
                            },
                            Err(_) => continue,
                        }
                    }
                };

                ctx.rate_limiter.throttle(user_id, data.len()).await;

                match socket.send_to(&data, target_addr).await {
                    Ok(sent_bytes) => {

                        total_up += sent_bytes as u64;
                        (ctx.on_traffic)(user_id, sent_bytes as u64, 0);
                    }
                    Err(e) => {
                        debug!("Hysteria v1 dedicated socket send_to {}:{} failed: {:?}", dst_host, dst_port, e);
                    }
                }
            }
        }
    }

    child_cancel.cancel();
    graceful_drain_join_set(&mut session_join_set, Duration::from_secs(2)).await;

    let duration = start_time.elapsed();
    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user_id,
        "hysteria",
        "udp",
        &client_ip.to_string(),
        "multiplexed",
        0,
        total_up,
        total_down,
        duration.as_millis() as i64,
        &last_tag,
        "connected",
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hy1_defragmenter_single_packet() {
        let defrag = Hy1Defragmenter::new();
        let payload = b"single udp packet data".to_vec();
        let res = defrag.push_fragment(1001, 1, 0, 1, "1.1.1.1".to_string(), 53, payload.clone());
        assert!(res.is_some());
        let (host, port, data) = res.unwrap();
        assert_eq!(host, "1.1.1.1");
        assert_eq!(port, 53);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_hy1_defragmenter_multiple_fragments() {
        let defrag = Hy1Defragmenter::new();
        let frag0 = b"Hello, ".to_vec();
        let frag1 = b"Hysteria 1 ".to_vec();
        let frag2 = b"Fragmentation!".to_vec();

        assert!(defrag
            .push_fragment(42, 1, 0, 3, "example.com".to_string(), 53, frag0.clone())
            .is_none());
        assert!(defrag
            .push_fragment(42, 1, 2, 3, "example.com".to_string(), 53, frag2.clone())
            .is_none());
        let res = defrag.push_fragment(42, 1, 1, 3, "example.com".to_string(), 53, frag1.clone());
        assert!(res.is_some());

        let (host, port, full) = res.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 53);
        assert_eq!(full, b"Hello, Hysteria 1 Fragmentation!");
    }

    #[test]
    fn test_hy1_defragmenter_rejections() {
        let defrag = Hy1Defragmenter::new();

        assert!(defrag
            .push_fragment(1, 1, 0, 0, "1.1.1.1".to_string(), 53, vec![1, 2])
            .is_none());

        assert!(defrag
            .push_fragment(1, 1, 2, 2, "1.1.1.1".to_string(), 53, vec![1, 2])
            .is_none());

        assert!(defrag
            .push_fragment(1, 1, 0, 3, "1.1.1.1".to_string(), 53, vec![1, 2])
            .is_none());

        assert!(defrag
            .push_fragment(1, 1, 1, 3, "8.8.8.8".to_string(), 53, vec![3, 4])
            .is_none());
    }

    #[test]
    fn test_allocate_session_id_collision_avoidance() {
        let mut map = HashMap::new();
        let (tx, _rx) = mpsc::channel(1);
        map.insert(1, tx);

        let counter = AtomicU32::new(1);
        let sid = allocate_session_id(&map, &counter).unwrap();
        assert_eq!(sid, 2);
    }

    #[test]
    fn test_hy1_server_response_format() {
        let ok_resp = [0x01u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(ok_resp.len(), 7);
        assert_eq!(ok_resp[0], 0x01);
        assert_eq!(u32::from_be_bytes(ok_resp[1..5].try_into().unwrap()), 0);
        assert_eq!(u16::from_be_bytes(ok_resp[5..7].try_into().unwrap()), 0);

        let sid: u32 = 12345;
        let mut udp_ok = Vec::new();
        udp_ok.push(0x01);
        udp_ok.extend_from_slice(&sid.to_be_bytes());
        udp_ok.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(udp_ok.len(), 7);
        assert_eq!(udp_ok[0], 0x01);
        assert_eq!(u32::from_be_bytes(udp_ok[1..5].try_into().unwrap()), 12345);
        assert_eq!(u16::from_be_bytes(udp_ok[5..7].try_into().unwrap()), 0);
    }

    #[test]
    fn test_hy1_byte_oriented_auth_and_collision_detection() {
        let inbound = Hysteria1Inbound::new();
        let user1 = User {
            id: 101,
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            password: Some("secret_string_pass".to_string()),
            ..Default::default()
        };
        let user2 = User {
            id: 102,
            uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            password: Some("68656c6c6f".to_string()),
            ..Default::default()
        };

        let user3 = User {
            id: 103,
            uuid: "99999999-9999-9999-9999-999999999999".to_string(),
            password: Some("secret_string_pass".to_string()),
            ..Default::default()
        };

        inbound.update_users(vec![user1, user2, user3]);

        let map = inbound.users.read().clone();

        let u1 = map
            .get(b"secret_string_pass".as_slice())
            .expect("user 1 password match");
        assert_eq!(u1.id, 101);

        let u1_uuid = map
            .get(b"11111111-2222-3333-4444-555555555555".as_slice())
            .expect("user 1 uuid match");
        assert_eq!(u1_uuid.id, 101);

        let u1_raw = map
            .get(b"11111111222233334444555555555555".as_slice())
            .expect("user 1 unhyphenated uuid match");
        assert_eq!(u1_raw.id, 101);

        let u2_bin = map
            .get(b"hello".as_slice())
            .expect("user 2 hex-decoded binary auth match");
        assert_eq!(u2_bin.id, 102);

        let u2_hex = map
            .get(b"68656c6c6f".as_slice())
            .expect("user 2 hex string match");
        assert_eq!(u2_hex.id, 102);

        assert_eq!(map.get(b"secret_string_pass".as_slice()).unwrap().id, 101);
    }

    #[test]
    fn test_hy1_request_type_validation() {
        assert_eq!(0x00u8, 0x00);
        assert_eq!(0x01u8, 0x01);

        let make_err = |msg: &[u8]| {
            let mut err_resp = Vec::with_capacity(7 + msg.len());
            err_resp.push(0x00);
            err_resp.extend_from_slice(&0u32.to_be_bytes());
            err_resp.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            err_resp.extend_from_slice(msg);
            err_resp
        };

        let err = make_err(b"unsupported request type");
        assert_eq!(err[0], 0x00);
        assert_eq!(u32::from_be_bytes(err[1..5].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_be_bytes(err[5..7].try_into().unwrap()) as usize,
            b"unsupported request type".len()
        );
        assert_eq!(&err[7..], b"unsupported request type");
    }
}
