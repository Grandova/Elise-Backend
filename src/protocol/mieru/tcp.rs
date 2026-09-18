use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream};
use crate::protocol::mieru::crypto::{increment_nonce, MieruUserIndex, OVERHEAD};
use crate::protocol::mieru::pattern::TrafficPatternExecutor;
use crate::protocol::mieru::relay::handle_socks5_session;
use crate::protocol::mieru::session::{
    MieruSessionReader, MieruSessionState, MieruSessionWriter, MieruStreamCipher,
    PROTOCOL_OPEN_SESSION_REQ, PROTOCOL_OPEN_SESSION_RESP,
};
use crate::protocol::InboundContext;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use parking_lot::RwLock;
use rand::RngCore;
use std::io::{self, Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

pub async fn start_tcp_server(
    ctx: InboundContext,
    user_index: Arc<RwLock<MieruUserIndex>>,
    pattern: Arc<TrafficPatternExecutor>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()> {
    let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
    let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
    info!("Mieru TCP inbound listening on {}", bind_addr);

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Mieru TCP inbound on port {} stopping", ctx.port);
                break;
            }
            accept_res = listener.accept() => {
                let (stream, remote_addr) = match accept_res {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!("Mieru TCP accept error: {:?}", e);
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);

                let ctx = ctx.clone();
                let user_index = user_index.clone();
                let pattern = pattern.clone();

                tokio::spawn(async move {
                    let _ = handle_tcp_connection(stream, remote_addr, ctx, user_index, pattern).await;
                });
            }
        }
    }
    Ok(())
}

async fn handle_tcp_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    user_index: Arc<RwLock<MieruUserIndex>>,
    pattern: Arc<TrafficPatternExecutor>,
) -> io::Result<()> {
    // Timeout of 15 seconds for handshake to protect against slowloris attacks
    let handshake_res = tokio::time::timeout(
        Duration::from_secs(15),
        perform_tcp_handshake(stream, remote_addr, &ctx, &user_index, &pattern),
    )
    .await;

    let (client_rx, client_tx, user, client_ip, conn_guard) = match handshake_res {
        Ok(Ok(Some(tuple))) => tuple,
        _ => return Ok(()),
    };

    handle_socks5_session(client_rx, client_tx, user, client_ip, ctx, conn_guard).await
}

type HandshakeTuple = (
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    tokio::io::WriteHalf<tokio::io::DuplexStream>,
    crate::panel::types::User,
    std::net::IpAddr,
    crate::limiter::ConnGuard,
);

async fn perform_tcp_handshake(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: &InboundContext,
    user_index: &Arc<RwLock<MieruUserIndex>>,
    pattern: &Arc<TrafficPatternExecutor>,
) -> io::Result<Option<HandshakeTuple>> {
    let (src_opt, mut stream) =
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(None);
    }

    // 1. Read first segment: 24B Nonce + 32B Meta ciphertext + 16B Tag = 72B
    let mut initial_hdr = [0u8; 72];
    stream.read_exact(&mut initial_hdr).await?;

    let mut recv_nonce = [0u8; 24];
    recv_nonce.copy_from_slice(&initial_hdr[..24]);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let decrypt_opt = {
        let guard = user_index.read();
        guard.try_decrypt_metadata(&initial_hdr[24..72], &recv_nonce, now_sec)
    };

    let (user, key, meta) = match decrypt_opt {
        Some(res) => {
            ctx.defense.record_success(client_ip);
            res
        }
        None => {
            ctx.defense.record_failure(client_ip);
            return Ok(None);
        }
    };

    let proto = meta[0];
    if proto != PROTOCOL_OPEN_SESSION_REQ {
        return Ok(None);
    }

    let session_id = u32::from_be_bytes(meta[6..10].try_into().unwrap());
    if session_id == 0 {
        return Ok(None);
    }
    let open_req_seq = u32::from_be_bytes(meta[10..14].try_into().unwrap());
    let payload_len = u16::from_be_bytes(meta[15..17].try_into().unwrap()) as usize;
    let suffix_len = meta[17] as usize;

    let recv_cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;
    let send_cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;

    increment_nonce(&mut recv_nonce);
    let mut decoder = MieruStreamCipher::new(recv_cipher, recv_nonce);

    let mut initial_payload = None;
    if payload_len > 0 {
        let mut wire_payload = vec![0u8; payload_len + OVERHEAD];
        stream.read_exact(&mut wire_payload).await?;
        let p_data = decoder.decrypt_payload(&wire_payload, payload_len)?;
        initial_payload = Some(p_data);
    }
    if suffix_len > 0 {
        let mut discard_suffix = vec![0u8; suffix_len];
        stream.read_exact(&mut discard_suffix).await?;
    }

    // Check device and conn limits
    if !ctx.device_limiter.check_and_record_async(user.panel_user.id, client_ip).await {
        return Ok(None);
    }
    let conn_guard = match ctx.conn_limiter.try_acquire(user.panel_user.id) {
        Some(g) => g,
        None => return Ok(None),
    };

    let mut session_state = MieruSessionState::new(session_id);
    session_state.advance_recv_seq(open_req_seq);
    let resp_seq = session_state.alloc_send_seq();

    let mut send_nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut send_nonce);
    pattern.apply_nonce_pattern(&mut send_nonce, false, true);

    let mut encoder = MieruStreamCipher::new(send_cipher, send_nonce);

    let cur_min = (now_sec / 60) as u32;
    let mut resp_meta = [0u8; 32];
    resp_meta[0] = PROTOCOL_OPEN_SESSION_RESP;
    resp_meta[2..6].copy_from_slice(&cur_min.to_be_bytes());
    resp_meta[6..10].copy_from_slice(&session_id.to_be_bytes());
    resp_meta[10..14].copy_from_slice(&resp_seq.to_be_bytes());
    resp_meta[14] = 0; // status: OK

    let first_resp_frame = encoder.encrypt_initial_metadata(&resp_meta)?;
    stream.write_all(&first_resp_frame).await?;
    stream.flush().await?;

    let shared_session = Arc::new(Mutex::new(session_state));
    let boxed_stream: BoxedStream = Box::new(stream);
    let (read_half, write_half) = tokio::io::split(boxed_stream);

    let mut reader = MieruSessionReader::new(read_half, decoder, shared_session.clone());
    let mut writer = MieruSessionWriter::new(write_half, encoder, shared_session, (**pattern).clone());

    if let Some(ref p) = initial_payload {
        if !p.is_empty() {
            reader.seed_pending(p);
        }
    }

    let (duplex_client, duplex_mieru) = tokio::io::duplex(65536);
    let (client_rx, client_tx) = tokio::io::split(duplex_client);
    let (mut mieru_rx, mut mieru_tx) = tokio::io::split(duplex_mieru);

    // Downstream pump: read decoded Mieru packets -> write to duplex stream
    tokio::spawn(async move {
        loop {
            match reader.read_next_segment().await {
                Ok(Some(data)) => {
                    if mieru_tx.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!("Mieru TCP reader error: {:?}", e);
                    break;
                }
            }
        }
        let _ = mieru_tx.shutdown().await;
    });

    // Upstream pump: read plain bytes from duplex stream -> encode into Mieru packets
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match mieru_rx.read(&mut buf).await {
                Ok(0) => {
                    let _ = writer.close_session().await;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = writer.write_data(&buf[..n]).await {
                        debug!("Mieru TCP writer error: {:?}", e);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    Ok(Some((client_rx, client_tx, user.panel_user, client_ip, conn_guard)))
}
