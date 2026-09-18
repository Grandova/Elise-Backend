//! Hysteria v2 Inbound Server
//! Strictly follows the official Hysteria 2 Protocol Specification.
//! Implements RFC 9114 HTTP/3 server lifecycle with control stream and QPACK authentication (Status 233),
//! Masquerade fallback (404), QUIC Varint 0x401 TCP proxy streams, QUIC unreliable datagrams with
//! dynamic destination routing, true source address responses, fragmentation, and hardened defragmentation.

use super::obfs::{GeckoObfs, HysteriaObfuscator, SalamanderObfs};
use super::qpack::{
    encode_h3_control_stream, encode_h3_response, parse_qpack_headers, quic_varint_len,
    read_quic_varint_async, write_quic_varint, H3_FRAME_DATA, H3_FRAME_HEADERS, H3_FRAME_SETTINGS,
    HYSTERIA_AUTH_HEADER, HYSTERIA_CC_RX_HEADER, HYSTERIA_PADDING_HEADER, HYSTERIA_UDP_HEADER,
};
use super::transport::{build_hysteria_tls_config, create_hysteria_endpoint, QuicStream};
use crate::conn::MonitoredStream;
use crate::limiter::ConnGuard;
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{self, Cursor};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub const HYSTERIA2_TCP_FRAME_TYPE: u64 = 0x401;

// ============================================================================
// Hysteria 2 Datagram Reassembly (Session isolated, TTL, Bounded)
// ============================================================================

struct Hy2ReassemblyEntry {
    fragments: Vec<Option<Vec<u8>>>,
    received_count: usize,
    total_count: usize,
    deadline: Instant,
    dest: String,
    total_bytes: usize,
}

pub struct Hy2Defragmenter {
    entries: Mutex<HashMap<(u32, u16), Hy2ReassemblyEntry>>, // (session_id, packet_id) -> Entry
    total_memory: Mutex<usize>,
}

const MAX_DEFRAG_ENTRIES: usize = 512;
const MAX_DEFRAG_MEMORY: usize = 16 * 1024 * 1024; // 16 MB

impl Default for Hy2Defragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Hy2Defragmenter {
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
        dest: String,
        data: Vec<u8>,
    ) -> Option<(String, Vec<u8>)> {
        // 1. Invalid checks: frag_total cannot be 0, frag_id must be < frag_total
        if frag_total == 0 || frag_id >= frag_total {
            debug!(
                "Hysteria v2 invalid fragment params: total={}, id={}",
                frag_total, frag_id
            );
            return None;
        }
        if frag_total == 1 {
            return Some((dest, data));
        }

        let now = Instant::now();
        let mut entries = self.entries.lock();
        let mut total_mem = self.total_memory.lock();

        // 2. Unconditional TTL cleanup
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

        // 3. Existing entry validation
        if let Some(entry) = entries.get_mut(&key) {
            if entry.total_count != frag_total as usize || entry.dest != dest {
                debug!(
                    "Hysteria v2 fragment mismatch for key={:?}: dropping poisoned entry",
                    key
                );
                *total_mem = total_mem.saturating_sub(entry.total_bytes);
                entries.remove(&key);
                return None;
            }

            if entry.fragments[frag_id as usize].is_none() {
                if *total_mem + chunk_len > MAX_DEFRAG_MEMORY {
                    debug!("Hysteria v2 MAX_DEFRAG_MEMORY exceeded");
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
                let d = entry.dest.clone();
                *total_mem = total_mem.saturating_sub(entry.total_bytes);
                entries.remove(&key);
                return Some((d, assembled));
            }
            return None;
        }

        // 4. Capacity checks for new entry
        if entries.len() >= MAX_DEFRAG_ENTRIES || *total_mem + chunk_len > MAX_DEFRAG_MEMORY {
            debug!("Hysteria v2 defrag capacity exceeded");
            return None;
        }

        let mut fragments = vec![None; frag_total as usize];
        fragments[frag_id as usize] = Some(data);
        *total_mem += chunk_len;

        entries.insert(
            key,
            Hy2ReassemblyEntry {
                fragments,
                received_count: 1,
                total_count: frag_total as usize,
                deadline: now + Duration::from_secs(8),
                dest,
                total_bytes: chunk_len,
            },
        );

        None
    }
}

// ============================================================================
// Hysteria 2 Inbound
// ============================================================================

pub struct Hysteria2Inbound {
    users: Arc<parking_lot::RwLock<HashMap<String, User>>>,
}

impl Default for Hysteria2Inbound {
    fn default() -> Self {
        Self {
            users: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }
}

impl Hysteria2Inbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for Hysteria2Inbound {
    fn protocol_type(&self) -> &'static str {
        "hysteria2"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::new();
        for u in users {
            if let Some(ref pass) = u.password {
                if !pass.is_empty() {
                    map.insert(pass.clone(), u.clone());
                }
            }
            map.insert(u.uuid.clone(), u);
        }
        *self.users.write() = map;
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

        // Obfuscation configuration (Salamander / Gecko)
        let (obfs_type, pw, min_pkt, max_pkt) = if let Some(ref val) = node_info.network_settings {
            let t = val
                .get("obfs_type")
                .or_else(|| val.get("obfsType"))
                .and_then(|v| v.as_str())
                .or_else(|| node_info.obfs.as_deref())
                .unwrap_or("none");
            let p = val
                .get("obfs_password")
                .or_else(|| val.get("obfsPassword"))
                .or_else(|| val.get("obfs"))
                .and_then(|v| v.as_str())
                .or_else(|| node_info.obfs_password.as_deref());

            let min_p = val
                .get("min_packet_size")
                .or_else(|| val.get("minPacketSize"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(512);
            let max_p = val
                .get("max_packet_size")
                .or_else(|| val.get("maxPacketSize"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(1200);

            (t, p, min_p, max_p)
        } else {
            let t = node_info.obfs.as_deref().unwrap_or("none");
            let p = node_info.obfs_password.as_deref();
            (t, p, 512, 1200)
        };

        let obfs = match (obfs_type.to_ascii_lowercase().as_str(), pw) {
            ("gecko", Some(p)) if !p.is_empty() => {
                HysteriaObfuscator::Gecko(GeckoObfs::new(p, min_pkt, max_pkt))
            }
            ("salamander", Some(p)) if !p.is_empty() => {
                HysteriaObfuscator::Salamander(SalamanderObfs::new(p))
            }
            _ => HysteriaObfuscator::None,
        };

        let alpn = [b"h3".as_slice()];
        let tls_config = build_hysteria_tls_config(&node_info, "hysteria2.local", &alpn)?;

        let endpoint = create_hysteria_endpoint(std_socket, tls_config, &alpn, obfs, true)?;
        info!("Hysteria v2 inbound listening on QUIC {}", bind_addr);

        let users = self.users.clone();
        let cancel_token = CancellationToken::new();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Hysteria v2 inbound on port {} shutting down", port);
                    cancel_token.cancel();
                    endpoint.close(0u32.into(), b"server shutdown");
                    break;
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    let users = users.clone();
                    let ctx = ctx.clone();
                    let node_info = node_info.clone();
                    let cancel = cancel_token.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_hy2_connection(incoming, users, ctx, node_info, cancel).await {
                            debug!("Hysteria v2 connection finished: {:?}", e);
                        }
                    });
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Hysteria v2 Connection & HTTP/3 Authentication Handler
// ============================================================================

async fn handle_hy2_connection(
    incoming: quinn::Incoming,
    users: Arc<parking_lot::RwLock<HashMap<String, User>>>,
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

    // Bandwidth configuration from Panel (bps = bits/s per Hysteria 2 specification)
    let _server_send_bps = node_info.up_mbps.unwrap_or(0) as u64 * 1_000_000;
    let server_recv_bps = node_info.down_mbps.unwrap_or(0) as u64 * 1_000_000;

    let conn_cancel = CancellationToken::new();

    // Send HTTP/3 Server Control Stream (Uni-stream 0x00 + SETTINGS 0x04)
    // RFC 9114 Section 6.2.1: Control Stream MUST NOT be closed at any point during connection.
    if let Ok(mut uni) = conn.open_uni().await {
        let _ = uni.write_all(&encode_h3_control_stream()).await;
        let _ = uni.flush().await;
        let ctrl_cancel = conn_cancel.clone();
        let ctrl_global = global_cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = ctrl_cancel.cancelled() => {},
                _ = ctrl_global.cancelled() => {},
            }
            let _ = uni.finish();
        });
    }

    // Consume and acknowledge incoming client Uni-streams
    let uni_conn = conn.clone();
    let uni_cancel = conn_cancel.clone();
    let uni_global_cancel = global_cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = uni_cancel.cancelled() => break,
                _ = uni_global_cancel.cancelled() => break,
                res = uni_conn.accept_uni() => {
                    let Ok(mut stream) = res else { break; };
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        while let Ok(Some(_)) = stream.read(&mut buf).await {}
                    });
                }
            }
        }
    });

    let auth_done = Arc::new(Notify::new());
    let auth_ok = Arc::new(AtomicBool::new(false));
    let authenticated_user: Arc<Mutex<Option<User>>> = Arc::new(Mutex::new(None));
    let conn_guard: Arc<Mutex<Option<ConnGuard>>> = Arc::new(Mutex::new(None));

    let udp_sessions: Arc<Mutex<HashMap<u32, mpsc::Sender<(String, Vec<u8>)>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let defragmenter = Arc::new(Hy2Defragmenter::new());

    // Datagram Receiver Task
    let dg_conn = conn.clone();
    let dg_sessions = udp_sessions.clone();
    let dg_defrag = defragmenter.clone();
    let dg_cancel = conn_cancel.clone();
    let dg_ctx = ctx.clone();
    let dg_auth_user = authenticated_user.clone();
    let dg_auth_ok = auth_ok.clone();
    let dg_remote = remote_addr;
    let dg_global_cancel = global_cancel.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = dg_cancel.cancelled() => break,
                _ = dg_global_cancel.cancelled() => break,
                dg_res = dg_conn.read_datagram() => {
                    let Ok(raw) = dg_res else { break; };
                    if raw.len() < 8 { continue; }

                    if !dg_auth_ok.load(Ordering::Acquire) {
                        continue;
                    }
                    let user = match dg_auth_user.lock().clone() {
                        Some(u) => u,
                        None => continue,
                    };

                    let session_id = u32::from_be_bytes(raw[0..4].try_into().unwrap());
                    let packet_id = u16::from_be_bytes(raw[4..6].try_into().unwrap());
                    let frag_id = raw[6];
                    let frag_total = raw[7];

                    let mut cursor = Cursor::new(&raw[8..]);
                    let dest_len = match read_quic_varint_sync(&mut cursor) {
                        Ok(l) => l as usize,
                        Err(_) => continue,
                    };

                    let dest_start = 8 + (cursor.position() as usize);
                    if raw.len() < dest_start + dest_len { continue; }

                    let dest_bytes = &raw[dest_start..dest_start + dest_len];
                    let dest = String::from_utf8_lossy(dest_bytes).to_string();
                    let payload = raw[dest_start + dest_len..].to_vec();

                    if let Some((dst, full_packet)) =
                        dg_defrag.push_fragment(session_id, packet_id, frag_id, frag_total, dest, payload)
                    {
                        let mut sessions_lock = dg_sessions.lock();
                        if let Some(tx) = sessions_lock.get(&session_id) {
                            let _ = tx.try_send((dst, full_packet));
                        } else {
                            if sessions_lock.len() >= 2048 {
                                sessions_lock.retain(|_, tx| !tx.is_closed());
                                if sessions_lock.len() >= 2048 {
                                    continue;
                                }
                            }

                            let (tx, rx) = mpsc::channel::<(String, Vec<u8>)>(256);
                            let _ = tx.try_send((dst.clone(), full_packet));
                            sessions_lock.insert(session_id, tx);
                            drop(sessions_lock);

                            let s_ctx = dg_ctx.clone();
                            let s_conn = dg_conn.clone();
                            let s_sessions = dg_sessions.clone();
                            let s_cancel = dg_cancel.clone();

                            tokio::spawn(async move {
                                handle_hy2_udp_session(
                                    session_id,
                                    rx,
                                    s_conn,
                                    s_ctx,
                                    user,
                                    dg_remote,
                                    s_cancel,
                                ).await;
                                s_sessions.lock().remove(&session_id);
                            });
                        }
                    }
                }
            }
        }
    });

    // Accept Bidi Streams (HTTP/3 Request Streams OR Hysteria2 0x401 TCP Proxy Streams)
    loop {
        tokio::select! {
            _ = conn_cancel.cancelled() => break Ok(()),
            _ = global_cancel.cancelled() => break Ok(()),
            bi_res = conn.accept_bi() => {
                let Ok((mut send, mut recv)) = bi_res else { break Ok(()); };

                // Read first varint to determine stream type
                let first_varint = match read_quic_varint_async(&mut recv).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if first_varint == HYSTERIA2_TCP_FRAME_TYPE {
                    // TCP Proxy Stream
                    let a_ok = auth_ok.clone();
                    let a_done = auth_done.clone();
                    let a_user = authenticated_user.clone();
                    let c_ctx = ctx.clone();
                    let c_remote = remote_addr;

                    tokio::spawn(async move {
                        // Wait for authentication if not yet complete (timeout 10s)
                        if !a_ok.load(Ordering::Acquire) {
                            let wait_res = tokio::time::timeout(Duration::from_secs(10), a_done.notified()).await;
                            if wait_res.is_err() || !a_ok.load(Ordering::Acquire) {
                                let _ = send.finish();
                                return;
                            }
                        }

                        let user = match a_user.lock().clone() {
                            Some(u) => u,
                            None => {
                                let _ = send.finish();
                                return;
                            }
                        };

                        // Address Length: QUIC Varint
                        let addr_len = match read_quic_varint_async(&mut recv).await {
                            Ok(al) => al as usize,
                            Err(_) => return,
                        };
                        if addr_len > 2048 {
                            let _ = send.finish();
                            return;
                        }

                        let mut addr_bytes = vec![0u8; addr_len];
                        if recv.read_exact(&mut addr_bytes).await.is_err() {
                            let _ = send.finish();
                            return;
                        }
                        let target_addr = String::from_utf8_lossy(&addr_bytes).to_string();

                        // Padding Length: QUIC Varint
                        let pad_len = match read_quic_varint_async(&mut recv).await {
                            Ok(pl) => pl as usize,
                            Err(_) => return,
                        };
                        if pad_len > 4096 {
                            let _ = send.finish();
                            return;
                        }
                        if pad_len > 0 {
                            let mut pad = vec![0u8; pad_len];
                            let _ = recv.read_exact(&mut pad).await;
                        }

                        let (host, port) = parse_host_port(&target_addr);
                        let _ = handle_hy2_tcp_stream(
                            recv,
                            send,
                            c_ctx,
                            user,
                            c_remote,
                            host,
                            port,
                        ).await;
                    });
                } else {
                    // HTTP/3 Frame
                    let frame_type = first_varint;
                    let frame_len = match read_quic_varint_async(&mut recv).await {
                        Ok(fl) => fl as usize,
                        Err(_) => continue,
                    };

                    if frame_len > 65536 {
                        continue;
                    }

                    let mut payload = vec![0u8; frame_len];
                    if recv.read_exact(&mut payload).await.is_err() {
                        continue;
                    }

                    if frame_type == H3_FRAME_SETTINGS {
                        continue;
                    } else if frame_type == H3_FRAME_HEADERS {
                        let parsed_req = parse_qpack_headers(&payload);
                        let req = match parsed_req {
                            Ok(r) => r,
                            Err(_) => {
                                send_masquerade_404(&mut send, &conn).await;
                                continue;
                            }
                        };

                        // 2. Strict Verification of :method, :path (align with official Hysteria 2 server)
                        let method = req.method.to_uppercase();
                        let path = &req.path;

                        if method != "POST" || path != "/auth" {
                            debug!("Hysteria v2 invalid HTTP/3 request: method={}, path={}, host={}", method, path, req.host());
                            send_masquerade_404(&mut send, &conn).await;
                            continue;
                        }

                        // Check authentication
                        let auth_str = req.get_header(HYSTERIA_AUTH_HEADER).unwrap_or("");
                        let matched_user = users.read().get(auth_str).cloned();

                        let user = match matched_user {
                            Some(u) => {
                                ctx.defense.record_success(client_ip);
                                u
                            }
                            None => {
                                ctx.defense.record_failure(client_ip);
                                send_masquerade_404(&mut send, &conn).await;
                                continue;
                            }
                        };

                        if !ctx.device_limiter.check_and_record_async(user.id, client_ip).await {
                            conn.close(1u32.into(), b"device limit exceeded");
                            continue;
                        }

                        let guard = match ctx.conn_limiter.try_acquire(user.id) {
                            Some(g) => g,
                            None => {
                                conn.close(1u32.into(), b"connection limit reached");
                                continue;
                            }
                        };

                        *conn_guard.lock() = Some(guard);
                        *authenticated_user.lock() = Some(user);
                        auth_ok.store(true, Ordering::Release);
                        auth_done.notify_waiters();

                        // Parse Hysteria-CC-RX and generate correct response
                        let rx_resp = if server_recv_bps > 0 {
                            server_recv_bps.to_string()
                        } else {
                            "auto".to_string()
                        };

                        let padding = "A".repeat(32);
                        let resp_headers = [
                            (HYSTERIA_UDP_HEADER, "true"),
                            (HYSTERIA_CC_RX_HEADER, rx_resp.as_str()),
                            (HYSTERIA_PADDING_HEADER, padding.as_str()),
                        ];
                        let resp_frame = encode_h3_response(233, &resp_headers);
                        let _ = send.write_all(&resp_frame).await;
                        let _ = send.finish();
                    }
                }
            }
        }
    }
}

async fn send_masquerade_404(send: &mut quinn::SendStream, _conn: &quinn::Connection) {
    let headers = [
        ("content-type", "text/html; charset=utf-8"),
        ("server", "nginx"),
    ];
    let resp_frame = encode_h3_response(404, &headers);
    let _ = send.write_all(&resp_frame).await;

    let html_body = b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p><hr><p>nginx</p></body></html>";
    let mut data_frame = Vec::new();
    let _ = write_quic_varint(&mut data_frame, H3_FRAME_DATA);
    let _ = write_quic_varint(&mut data_frame, html_body.len() as u64);
    data_frame.extend_from_slice(html_body);
    let _ = send.write_all(&data_frame).await;
    let _ = send.finish();
}

// ============================================================================
// Hysteria v2 TCP Stream Relay
// ============================================================================

async fn handle_hy2_tcp_stream(
    recv: quinn::RecvStream,
    send: quinn::SendStream,
    ctx: InboundContext,
    user: User,
    remote_addr: SocketAddr,
    target_host: String,
    target_port: u16,
) -> io::Result<()> {
    let client_ip = remote_addr.ip();
    let target_ip: Option<IpAddr> = target_host.parse().ok();

    // Domain sniffing if configured
    let stream = QuicStream::new(recv, send);
    let (sniffed, stream) =
        crate::conn::sniff_async_stream(stream, target_ip, ctx.global_config.domain_sniff).await;
    let match_host = sniffed.as_deref().unwrap_or(&target_host);
    let dial_host = if ctx.global_config.sniff_redirect {
        match_host
    } else {
        &target_host
    };

    // Audit check
    let mut stream = stream;
    if ctx.audit.should_block(match_host, target_ip, target_port) {
        let mut resp = Vec::new();
        resp.push(0x01); // Error
        let msg = b"blocked by audit rule";
        let _ = write_quic_varint(&mut resp, msg.len() as u64);
        resp.extend_from_slice(msg);
        let _ = write_quic_varint(&mut resp, 0); // Padding = 0
        let _ = stream.write_all(&resp).await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    // Match routing outbound
    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: match_host,
        target_ip,
        target_port,
        inbound_local_ip: None,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    // Connect outbound
    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, target_port, None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            debug!(
                "Hysteria v2 outbound TCP dial failed for {}:{}: {:?}",
                dial_host, target_port, e
            );
            let mut resp = Vec::new();
            resp.push(0x01); // Error
            let msg = b"connection failed";
            let _ = write_quic_varint(&mut resp, msg.len() as u64);
            resp.extend_from_slice(msg);
            let _ = write_quic_varint(&mut resp, 0); // Padding = 0
            let _ = stream.write_all(&resp).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    // Send TCPResponse OK (0x00, msg_len=0, pad_len=0)
    let mut ok_resp = Vec::new();
    ok_resp.push(0x00); // OK
    let _ = write_quic_varint(&mut ok_resp, 0); // Msg len = 0
    let _ = write_quic_varint(&mut ok_resp, 0); // Pad len = 0
    stream.write_all(&ok_resp).await?;

    let mut client_conn = MonitoredStream::new(stream, user.id, remote_addr);
    let start_time = Instant::now();

    let _ = crate::conn::copy_bidirectional_throttled(
        &mut client_conn,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
    )
    .await;

    let duration = start_time.elapsed();
    let (up, down) = client_conn.stats();

    if up > 0 || down > 0 {
        (ctx.on_traffic)(user.id, up, down);
    }

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "hysteria2",
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

// ============================================================================
// Hysteria v2 UDP Session Relay
// ============================================================================

async fn handle_hy2_udp_session(
    session_id: u32,
    mut packet_rx: mpsc::Receiver<(String, Vec<u8>)>,
    conn: quinn::Connection,
    ctx: InboundContext,
    user: User,
    remote_addr: SocketAddr,
    session_cancel: CancellationToken,
) {
    let start_time = Instant::now();
    let client_ip = remote_addr.ip();
    let mut total_up = 0u64;
    let mut total_down = 0u64;

    // Allocate dedicated unconnected UDP socket for Full Cone NAT
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            debug!("Hysteria v2 failed to bind dedicated UDP socket: {:?}", e);
            return;
        }
    };

    let resp_socket = socket.clone();
    let resp_conn = conn.clone();
    let resp_cancel = session_cancel.clone();
    let (down_tx, mut down_rx) = mpsc::channel::<usize>(128);

    // Downlink task: recv_from -> package Hysteria 2 Datagram -> send to client
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut packet_id: u16 = 1;
        let max_dg_size = resp_conn.max_datagram_size().unwrap_or(1200);

        loop {
            tokio::select! {
                _ = resp_cancel.cancelled() => break,
                recv_res = resp_socket.recv_from(&mut buf) => {
                    let Ok((n, src_addr)) = recv_res else { break; };
                    if n == 0 { continue; }

                    let data = &buf[..n];
                    let pkt_id = packet_id;
                    packet_id = packet_id.wrapping_add(1);

                    // True source address!
                    let resp_dest = src_addr.to_string();
                    let dest_bytes = resp_dest.as_bytes();
                    let header_len = 8 + quic_varint_len(dest_bytes.len() as u64) + dest_bytes.len();

                    if n + header_len <= max_dg_size {
                        // Single datagram
                        let mut dg = Vec::with_capacity(header_len + n);
                        dg.extend_from_slice(&session_id.to_be_bytes());
                        dg.extend_from_slice(&pkt_id.to_be_bytes());
                        dg.push(0); // frag_id = 0
                        dg.push(1); // frag_total = 1
                        let _ = write_quic_varint(&mut dg, dest_bytes.len() as u64);
                        dg.extend_from_slice(dest_bytes);
                        dg.extend_from_slice(data);

                        let _ = resp_conn.send_datagram(dg.into());
                        let _ = down_tx.send(n).await;
                    } else {
                        // Fragmented datagrams
                        let max_chunk = max_dg_size.saturating_sub(header_len);
                        if max_chunk == 0 { continue; }
                        let chunks: Vec<&[u8]> = data.chunks(max_chunk).collect();
                        let total_frags = chunks.len() as u8;

                        for (i, chunk) in chunks.into_iter().enumerate() {
                            let mut dg = Vec::with_capacity(header_len + chunk.len());
                            dg.extend_from_slice(&session_id.to_be_bytes());
                            dg.extend_from_slice(&pkt_id.to_be_bytes());
                            dg.push(i as u8);
                            dg.push(total_frags);
                            let _ = write_quic_varint(&mut dg, dest_bytes.len() as u64);
                            dg.extend_from_slice(dest_bytes);
                            dg.extend_from_slice(chunk);

                            if resp_conn.send_datagram(dg.into()).is_err() {
                                break;
                            }
                        }
                        let _ = down_tx.send(n).await;
                    }
                }
            }
        }
    });

    // Uplink loop: receive from client datagram channel -> dynamic route -> sendto
    let idle_timeout = Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = session_cancel.cancelled() => break,
            _ = tokio::time::sleep(idle_timeout) => break,
            Some(down_n) = down_rx.recv() => {
                total_down += down_n as u64;
            }
            packet = packet_rx.recv() => {
                let Some((dest, data)) = packet else { break; };
                let (host, port) = parse_host_port(&dest);
                let target_ip = host.parse().ok();

                if ctx.audit.should_block(&host, target_ip, port) {
                    continue;
                }

                ctx.rate_limiter.throttle(user.id, data.len()).await;

                if let Ok(mut resolved) = tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                    if let Some(target_sock) = resolved.next() {
                        if socket.send_to(&data, target_sock).await.is_ok() {
                            total_up += data.len() as u64;
                        }
                    }
                }
            }
        }
    }

    session_cancel.cancel();
    let duration = start_time.elapsed();

    if total_up > 0 || total_down > 0 {
        (ctx.on_traffic)(user.id, total_up, total_down);
    }

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "hysteria2",
        "udp",
        &client_ip.to_string(),
        "dynamic",
        0,
        total_up,
        total_down,
        duration.as_millis() as i64,
        "direct",
        "connected",
    ));
}

// ============================================================================
// Helpers
// ============================================================================

pub fn parse_host_port(addr: &str) -> (String, u16) {
    if let Some(idx) = addr.rfind(':') {
        let host = addr[..idx]
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = addr[idx + 1..].parse::<u16>().unwrap_or(0);
        (host, port)
    } else {
        (addr.to_string(), 0)
    }
}

pub fn read_quic_varint_sync<R: io::Read>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    let b = first[0];
    let prefix = b >> 6;
    let len = 1usize << prefix;
    let mut val = (b & 0x3f) as u64;

    for _ in 1..len {
        let mut next = [0u8; 1];
        reader.read_exact(&mut next)?;
        val = (val << 8) | (next[0] as u64);
    }
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hy2_parse_host_port() {
        assert_eq!(parse_host_port("1.1.1.1:53"), ("1.1.1.1".to_string(), 53));
        assert_eq!(
            parse_host_port("[2606:4700::1111]:443"),
            ("2606:4700::1111".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("example.com:8080"),
            ("example.com".to_string(), 8080)
        );
    }

    #[test]
    fn test_hy2_defragmenter_roundtrip() {
        let defrag = Hy2Defragmenter::new();
        let frag0 = b"Hysteria 2 ".to_vec();
        let frag1 = b"Datagram ".to_vec();
        let frag2 = b"Reassembly!".to_vec();

        assert!(defrag
            .push_fragment(100, 5, 0, 3, "8.8.8.8:53".to_string(), frag0)
            .is_none());
        assert!(defrag
            .push_fragment(100, 5, 2, 3, "8.8.8.8:53".to_string(), frag2)
            .is_none());
        let res = defrag.push_fragment(100, 5, 1, 3, "8.8.8.8:53".to_string(), frag1);
        assert!(res.is_some());

        let (dest, payload) = res.unwrap();
        assert_eq!(dest, "8.8.8.8:53");
        assert_eq!(payload, b"Hysteria 2 Datagram Reassembly!");
    }

    #[test]
    fn test_hy2_defragmenter_rejections() {
        let defrag = Hy2Defragmenter::new();

        // 1. frag_total = 0 rejected
        assert!(defrag
            .push_fragment(1, 1, 0, 0, "8.8.8.8:53".to_string(), vec![1])
            .is_none());

        // 2. frag_id >= frag_total rejected
        assert!(defrag
            .push_fragment(1, 1, 2, 2, "8.8.8.8:53".to_string(), vec![1])
            .is_none());

        // 3. Poisoned entry with destination mismatch rejected and cleared
        defrag.push_fragment(2, 10, 0, 2, "8.8.8.8:53".to_string(), vec![1, 2, 3]);
        // Same key, different dest -> rejected
        assert!(defrag
            .push_fragment(2, 10, 1, 2, "1.1.1.1:53".to_string(), vec![4, 5, 6])
            .is_none());
    }
}
