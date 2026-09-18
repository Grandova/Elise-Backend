use crate::protocol::mieru::crypto::{
    increment_nonce, MieruUserIndex, METADATA_LENGTH, NONCE_SIZE, OVERHEAD,
};
use crate::protocol::mieru::pattern::{decode_low_entropy, TrafficPatternExecutor};
use crate::protocol::mieru::relay::handle_socks5_session;
use crate::protocol::mieru::session::{
    MieruSessionState, PROTOCOL_CLOSE_SESSION_REQ, PROTOCOL_DATA_C2S,
    PROTOCOL_DATA_C2S_LOW_ENTROPY, PROTOCOL_DATA_S2C, PROTOCOL_OPEN_SESSION_REQ,
    PROTOCOL_OPEN_SESSION_RESP,
};
use crate::protocol::InboundContext;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag as XTag, XChaCha20Poly1305, XNonce};
use parking_lot::RwLock;
use rand::RngCore;
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{debug, info, warn};

const _UDP_MAX_PACKET_SIZE: usize = 65536;
const UDP_MAX_PAYLOAD_SIZE: usize = 32768; // Aligned with MAX_PDU

struct ActiveUdpSession {
    session_id: u32,
    client_addr: SocketAddr,
    key: [u8; 32],
    _state: Arc<Mutex<MieruSessionState>>,
    packet_tx: mpsc::Sender<Vec<u8>>,
    last_activity: Arc<parking_lot::Mutex<Instant>>,
}

pub async fn start_udp_server(
    ctx: InboundContext,
    user_index: Arc<RwLock<MieruUserIndex>>,
    pattern: Arc<TrafficPatternExecutor>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()> {
    let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    info!("Mieru UDP inbound listening on {}", bind_addr);

    let active_sessions: Arc<RwLock<HashMap<(SocketAddr, u32), Arc<ActiveUdpSession>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let mut tasks = tokio::task::JoinSet::new();
    let idle_timeout = ctx.global_config.udp_timeout;
    let cleaner_sessions = active_sessions.clone();
    let mut cleaner_shutdown = shutdown_rx.resubscribe();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = cleaner_shutdown.recv() => break,
                _ = interval.tick() => {
                    cleaner_sessions.write().retain(|_, s| {
                        idle_timeout == 0 || s.last_activity.lock().elapsed() < Duration::from_secs(idle_timeout)
                    });
                }
            }
        }
    });

    let mut recv_buf = vec![0u8; 65536];

    ctx.mark_ready();
    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result { warn!(error = %e, "Mieru UDP task failed"); }
            }
            _ = shutdown_rx.recv() => {
                info!("Mieru UDP inbound on port {} stopping", ctx.port);
                break;
            }
            recv_res = socket.recv_from(&mut recv_buf) => {
                let (n, remote_addr) = match recv_res {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("Mieru UDP recv_from error: {:?}", e);
                        continue;
                    }
                };

                if n < NONCE_SIZE + METADATA_LENGTH + OVERHEAD {
                    continue;
                }

                let packet = recv_buf[..n].to_vec();
                let socket_clone = socket.clone();
                let ctx_clone = ctx.clone();
                let user_index_clone = user_index.clone();
                let pattern_clone = pattern.clone();
                let sessions_clone = active_sessions.clone();

                tasks.spawn(async move {
                    let _ = handle_udp_packet(
                        packet,
                        remote_addr,
                        socket_clone,
                        ctx_clone,
                        user_index_clone,
                        pattern_clone,
                        sessions_clone,
                    ).await;
                });
            }
        }
    }

    active_sessions.write().clear();
    crate::protocol::common::inbound::drain_connections(&mut tasks).await;
    Ok(())
}

async fn handle_udp_packet(
    packet: Vec<u8>,
    remote_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    ctx: InboundContext,
    user_index: Arc<RwLock<MieruUserIndex>>,
    pattern: Arc<TrafficPatternExecutor>,
    sessions: Arc<RwLock<HashMap<(SocketAddr, u32), Arc<ActiveUdpSession>>>>,
) -> io::Result<()> {
    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(());
    }

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&packet[..24]);

    // 1. Try existing sessions for this client address
    let existing_match = {
        let lock = sessions.read();
        let candidates: Vec<Arc<ActiveUdpSession>> = lock
            .values()
            .filter(|s| s.client_addr == remote_addr)
            .cloned()
            .collect();
        candidates
    };

    for session in existing_match {
        if let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&session.key) {
            let mut meta_buf = packet[24..56].to_vec();
            let tag = XTag::from_slice(&packet[56..72]);
            if cipher
                .decrypt_in_place_detached(XNonce::from_slice(&nonce), b"", &mut meta_buf, tag)
                .is_ok()
            {
                let session_id = u32::from_be_bytes(meta_buf[6..10].try_into().unwrap());
                if session_id == session.session_id {
                    *session.last_activity.lock() = Instant::now();
                    let _ = session.packet_tx.send(packet).await;
                    return Ok(());
                }
            }
        }
    }

    // 2. Not an existing session: attempt to decrypt as a new session request
    let decrypt_opt = {
        let guard = user_index.read();
        guard.try_decrypt_metadata(&packet[24..72], &nonce, now_sec)
    };

    let (user, key, meta) = match decrypt_opt {
        Some(res) => {
            ctx.defense.record_success(client_ip);
            res
        }
        None => {
            ctx.defense.record_failure(client_ip);
            return Ok(());
        }
    };

    let proto = meta[0];
    if proto != PROTOCOL_OPEN_SESSION_REQ {
        return Ok(());
    }

    let session_id = u32::from_be_bytes(meta[6..10].try_into().unwrap());
    if session_id == 0 {
        return Ok(());
    }
    let open_req_seq = u32::from_be_bytes(meta[10..14].try_into().unwrap());
    let payload_len = u16::from_be_bytes(meta[15..17].try_into().unwrap()) as usize;
    let _suffix_len = meta[17] as usize;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;

    // Decrypt piggybacked initial payload if present
    let mut initial_payload = None;
    if payload_len > 0 && packet.len() >= 72 + payload_len + OVERHEAD {
        let mut p_buf = packet[72..72 + payload_len].to_vec();
        let p_tag = XTag::from_slice(&packet[72 + payload_len..72 + payload_len + OVERHEAD]);
        let mut p_nonce = nonce;
        increment_nonce(&mut p_nonce);
        if cipher
            .decrypt_in_place_detached(XNonce::from_slice(&p_nonce), b"", &mut p_buf, p_tag)
            .is_ok()
        {
            initial_payload = Some(p_buf);
        }
    }

    // Check device and conn limits
    if !ctx
        .device_limiter
        .check_and_record_async(user.panel_user.id, client_ip)
        .await
    {
        return Ok(());
    }
    let conn_guard = match ctx.conn_limiter.try_acquire(user.panel_user.id) {
        Some(g) => g,
        None => return Ok(()),
    };

    // 3. Send openSessionResponse
    let mut session_state = MieruSessionState::new(session_id);
    session_state.advance_recv_seq(open_req_seq);
    let resp_seq = session_state.alloc_send_seq();

    let cur_min = (now_sec / 60) as u32;
    let mut resp_meta = [0u8; 32];
    resp_meta[0] = PROTOCOL_OPEN_SESSION_RESP;
    resp_meta[2..6].copy_from_slice(&cur_min.to_be_bytes());
    resp_meta[6..10].copy_from_slice(&session_id.to_be_bytes());
    resp_meta[10..14].copy_from_slice(&resp_seq.to_be_bytes());
    resp_meta[14] = 0; // status: OK

    let mut send_nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut send_nonce);
    pattern.apply_nonce_pattern(&mut send_nonce, true, true);

    let mut resp_buf = resp_meta.to_vec();
    let resp_tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&send_nonce), b"", &mut resp_buf)
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Meta encrypt failed: {:?}", e),
            )
        })?;

    let mut resp_pkt = Vec::with_capacity(24 + 32 + 16);
    resp_pkt.extend_from_slice(&send_nonce);
    resp_pkt.extend_from_slice(&resp_buf);
    resp_pkt.extend_from_slice(resp_tag.as_slice());

    socket.send_to(&resp_pkt, remote_addr).await?;

    // 4. Create channels and register into active sessions
    let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(256);
    let shared_state = Arc::new(Mutex::new(session_state));

    let active_session = Arc::new(ActiveUdpSession {
        session_id,
        client_addr: remote_addr,
        key,
        _state: shared_state.clone(),
        packet_tx,
        last_activity: Arc::new(parking_lot::Mutex::new(Instant::now())),
    });

    sessions
        .write()
        .insert((remote_addr, session_id), active_session.clone());

    // 5. Connect session to relay using duplex virtual stream
    let (duplex_client, duplex_server) = tokio::io::duplex(65536);
    let (client_rx, mut client_tx) = tokio::io::split(duplex_client);
    let (server_rx, server_tx) = tokio::io::split(duplex_server);

    if let Some(p) = initial_payload {
        client_tx.write_all(&p).await?;
        client_tx.flush().await?;
    }

    let activity = active_session.last_activity.clone();
    let identity = Arc::downgrade(&active_session);
    drop(active_session);
    let relay = handle_socks5_session(
        server_rx,
        server_tx,
        user.panel_user.clone(),
        client_ip,
        ctx,
        conn_guard,
    );
    let bridge = run_udp_session_bridge(
        packet_rx,
        client_rx,
        client_tx,
        socket,
        remote_addr,
        session_id,
        key,
        shared_state,
        (*pattern).clone(),
        activity,
    );
    let _ = tokio::join!(relay, bridge);
    let session_key = (remote_addr, session_id);
    let mut sessions = sessions.write();
    if sessions
        .get(&session_key)
        .is_some_and(|s| identity.ptr_eq(&Arc::downgrade(s)))
    {
        sessions.remove(&session_key);
    }
    debug!("Mieru UDP session {} closed", session_id);

    Ok(())
}

async fn run_udp_session_bridge(
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    mut client_rx: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut client_tx: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    session_id: u32,
    key: [u8; 32],
    state: Arc<Mutex<MieruSessionState>>,
    pattern: TrafficPatternExecutor,
    activity: Arc<parking_lot::Mutex<Instant>>,
) -> io::Result<()> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // Downstream -> Upstream: incoming UDP packets from client -> write to duplex pipe
    let down_cancel = cancel_token.clone();
    let state_down = state.clone();
    let cipher_down = cipher.clone();
    let down_task = async move {
        loop {
            let packet = tokio::select! {
                _ = down_cancel.cancelled() => break,
                packet = packet_rx.recv() => match packet { Some(packet) => packet, None => break },
            };
            if packet.len() < 72 {
                continue;
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&packet[..24]);

            let mut meta_buf = packet[24..56].to_vec();
            let meta_tag = XTag::from_slice(&packet[56..72]);
            if cipher_down
                .decrypt_in_place_detached(XNonce::from_slice(&nonce), b"", &mut meta_buf, meta_tag)
                .is_err()
            {
                continue;
            }

            let proto = meta_buf[0];
            let seq = u32::from_be_bytes(meta_buf[10..14].try_into().unwrap());
            {
                let mut s = state_down.lock().await;
                s.advance_recv_seq(seq);
            }

            match proto {
                PROTOCOL_DATA_C2S => {
                    let prefix_len = meta_buf[21] as usize;
                    let payload_len =
                        u16::from_be_bytes(meta_buf[22..24].try_into().unwrap()) as usize;
                    let payload_offset = 72 + prefix_len;

                    if payload_len > 0 && packet.len() >= payload_offset + payload_len + OVERHEAD {
                        let mut p_buf =
                            packet[payload_offset..payload_offset + payload_len].to_vec();
                        let p_tag = XTag::from_slice(
                            &packet[payload_offset + payload_len
                                ..payload_offset + payload_len + OVERHEAD],
                        );
                        let mut p_nonce = nonce;
                        increment_nonce(&mut p_nonce);

                        if cipher_down
                            .decrypt_in_place_detached(
                                XNonce::from_slice(&p_nonce),
                                b"",
                                &mut p_buf,
                                p_tag,
                            )
                            .is_ok()
                        {
                            if client_tx.write_all(&p_buf).await.is_err() {
                                break;
                            }
                            let _ = client_tx.flush().await;
                        }
                    }
                }
                PROTOCOL_DATA_C2S_LOW_ENTROPY => {
                    let mode = meta_buf[1] as i32;
                    let prefix_len = meta_buf[21] as usize;
                    let payload_len =
                        u16::from_be_bytes(meta_buf[22..24].try_into().unwrap()) as usize;
                    let half_mask = u32::from_be_bytes(meta_buf[25..29].try_into().unwrap());
                    let extracted_len =
                        u16::from_be_bytes(meta_buf[29..31].try_into().unwrap()) as usize;
                    let rotation = meta_buf[31] as i32;
                    let payload_offset = 72 + prefix_len;

                    if payload_len > 0 && packet.len() >= payload_offset + payload_len + OVERHEAD {
                        let mut p_buf =
                            packet[payload_offset..payload_offset + payload_len].to_vec();
                        let p_tag = XTag::from_slice(
                            &packet[payload_offset + payload_len
                                ..payload_offset + payload_len + OVERHEAD],
                        );
                        let mut p_nonce = nonce;
                        increment_nonce(&mut p_nonce);

                        if cipher_down
                            .decrypt_in_place_detached(
                                XNonce::from_slice(&p_nonce),
                                b"",
                                &mut p_buf,
                                p_tag,
                            )
                            .is_ok()
                        {
                            if let Ok(raw) =
                                decode_low_entropy(&p_buf, extracted_len, mode, half_mask, rotation)
                            {
                                if client_tx.write_all(&raw).await.is_err() {
                                    break;
                                }
                                let _ = client_tx.flush().await;
                            }
                        }
                    }
                }
                PROTOCOL_CLOSE_SESSION_REQ => {
                    break;
                }
                _ => {}
            }
        }
        let _ = client_tx.shutdown().await;
        down_cancel.cancel();
    };

    // Upstream -> Downstream: read from duplex pipe -> package into Mieru UDP data packets -> send_to
    let up_cancel = cancel_token.clone();
    let state_up = state.clone();
    let cipher_up = cipher;
    let up_task = async move {
        let mut buf = vec![0u8; UDP_MAX_PAYLOAD_SIZE];
        loop {
            tokio::select! {
                _ = up_cancel.cancelled() => break,
                res = client_rx.read(&mut buf) => {
                    let n = match res {
                        Ok(0) => break,
                        Ok(len) => len,
                        Err(_) => break,
                    };

                    let (seq, unack_seq, window_size) = {
                        let mut s = state_up.lock().await;
                        (s.alloc_send_seq(), s.unack_seq, s.window_size)
                    };

                    let now_sec = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let cur_min = (now_sec / 60) as u32;

                    let mut send_nonce = [0u8; 24];
                    rand::thread_rng().fill_bytes(&mut send_nonce);
                    pattern.apply_nonce_pattern(&mut send_nonce, true, false);

                    let middle_pad = pattern.generate_middle_padding();
                    let end_pad = pattern.generate_end_padding();

                    let mut meta = [0u8; 32];
                    meta[0] = PROTOCOL_DATA_S2C;
                    meta[2..6].copy_from_slice(&cur_min.to_be_bytes());
                    meta[6..10].copy_from_slice(&session_id.to_be_bytes());
                    meta[10..14].copy_from_slice(&seq.to_be_bytes());
                    meta[14..18].copy_from_slice(&unack_seq.to_be_bytes());
                    meta[18..20].copy_from_slice(&window_size.to_be_bytes());
                    meta[20] = 0; // fragment number
                    meta[21] = middle_pad.len() as u8;
                    meta[22..24].copy_from_slice(&(n as u16).to_be_bytes());
                    meta[24] = end_pad.len() as u8;

                    // Encrypt metadata
                    let mut enc_meta = meta.to_vec();
                    let meta_tag = match cipher_up.encrypt_in_place_detached(XNonce::from_slice(&send_nonce), b"", &mut enc_meta) {
                        Ok(t) => t,
                        Err(_) => break,
                    };

                    // Encrypt payload
                    let mut payload_nonce = send_nonce;
                    increment_nonce(&mut payload_nonce);
                    let mut enc_payload = buf[..n].to_vec();
                    let payload_tag = match cipher_up.encrypt_in_place_detached(XNonce::from_slice(&payload_nonce), b"", &mut enc_payload) {
                        Ok(t) => t,
                        Err(_) => break,
                    };

                    // Build packet: Nonce(24) + Meta(32) + MetaTag(16) + MiddlePad + Payload + PayloadTag(16) + EndPad
                    let mut pkt = Vec::with_capacity(72 + middle_pad.len() + enc_payload.len() + 16 + end_pad.len());
                    pkt.extend_from_slice(&send_nonce);
                    pkt.extend_from_slice(&enc_meta);
                    pkt.extend_from_slice(meta_tag.as_slice());
                    if !middle_pad.is_empty() {
                        pkt.extend_from_slice(&middle_pad);
                    }
                    pkt.extend_from_slice(&enc_payload);
                    pkt.extend_from_slice(payload_tag.as_slice());
                    if !end_pad.is_empty() {
                        pkt.extend_from_slice(&end_pad);
                    }

                    if socket.send_to(&pkt, remote_addr).await.is_err() {
                        break;
                    }
                    *activity.lock() = Instant::now();
                    tokio::time::sleep(Duration::from_micros(150)).await;
                }
            }
        }
        up_cancel.cancel();
    };

    tokio::join!(down_task, up_task);
    Ok(())
}
