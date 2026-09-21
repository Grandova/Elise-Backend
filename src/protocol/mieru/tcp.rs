use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream};
use crate::protocol::mieru::crypto::{increment_nonce, MieruUser, MieruUserIndex};
use crate::protocol::mieru::pattern::TrafficPatternExecutor;
use crate::protocol::mieru::relay::handle_socks5_session;
use crate::protocol::mieru::session::{
    MieruFrame, MieruSessionReader, MieruSessionState, MieruSessionWriter, MieruStreamCipher,
    PROTOCOL_ACK_C2S, PROTOCOL_CLOSE_SESSION_REQ, PROTOCOL_CLOSE_SESSION_RESP,
    PROTOCOL_OPEN_SESSION_REQ, PROTOCOL_OPEN_SESSION_RESP,
};
use crate::protocol::InboundContext;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use parking_lot::RwLock;
use rand::RngCore;
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
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

    let mut connections = tokio::task::JoinSet::new();
    ctx.mark_ready();
    loop {
        tokio::select! {
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Connection task failed"); }
                }
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

                let shutdown = shutdown_rx.resubscribe();
                connections.spawn(async move {
                    if let Err(e) = handle_tcp_connection(stream, remote_addr, ctx, user_index, pattern, shutdown).await {
                        if e.kind() == ErrorKind::UnexpectedEof || e.kind() == ErrorKind::ConnectionReset {
                            tracing::trace!(error = %e, "Mieru TCP scanner probe or early disconnect");
                        } else {
                            debug!(error = %e, "Mieru TCP connection closed");
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    crate::protocol::common::inbound::drain_connections(&mut connections).await;
    Ok(())
}

struct TcpSession {
    input: mpsc::Sender<Vec<u8>>,
    state: Arc<Mutex<MieruSessionState>>,
    cancel: CancellationToken,
}

type HandshakeTuple = (
    MieruSessionReader<tokio::io::ReadHalf<BoxedStream>>,
    MieruSessionWriter<tokio::io::WriteHalf<BoxedStream>>,
    MieruUser,
    IpAddr,
    MieruFrame,
);

async fn handle_tcp_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    user_index: Arc<RwLock<MieruUserIndex>>,
    pattern: Arc<TrafficPatternExecutor>,
    mut shutdown: broadcast::Receiver<()>,
) -> io::Result<()> {
    let handshake = tokio::select! {
        _ = shutdown.recv() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(15),
            perform_tcp_handshake(stream, remote_addr, &ctx, &user_index, &pattern)) => result,
    };
    let (mut reader, writer, authenticated, client_ip, first) = match handshake {
        Ok(Ok(Some(value))) => value,
        Ok(Err(error)) => return Err(error),
        _ => return Ok(()),
    };
    let writer = Arc::new(Mutex::new(writer));
    let cancel = CancellationToken::new();
    let (frames_tx, mut frames_rx) = mpsc::channel(16);
    let mut readers = tokio::task::JoinSet::new();
    readers.spawn(async move {
        if frames_tx.send(Ok(Some(first))).await.is_err() {
            return;
        }
        loop {
            let frame = reader.read_next_segment().await;
            let done = !matches!(&frame, Ok(Some(_)));
            if frames_tx.send(frame).await.is_err() || done {
                break;
            }
        }
    });
    let mut sessions = HashMap::<u32, TcpSession>::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut idle = tokio::time::interval(Duration::from_secs(1));
    let mut last_activity = tokio::time::Instant::now();
    let result = async {
        loop {
            let frame = tokio::select! {
                _ = shutdown.recv() => break,
                _ = cancel.cancelled() => break,
                _ = idle.tick() => {
                    if sessions.is_empty() && ctx.global_config.tcp_timeout > 0
                        && last_activity.elapsed().as_secs() >= ctx.global_config.tcp_timeout {
                        break;
                    }
                    continue;
                }
                done = tasks.join_next(), if !tasks.is_empty() => {
                    match done {
                        Some(Ok(id)) => { sessions.remove(&id); }
                        Some(Err(error)) => return Err(Error::other(error)),
                        None => {}
                    }
                    last_activity = tokio::time::Instant::now();
                    continue;
                }
                frame = frames_rx.recv() => match frame {
                    Some(Ok(Some(frame))) => frame,
                    Some(Err(error)) => return Err(error),
                    _ => break,
                },
            };
            last_activity = tokio::time::Instant::now();
            let id = u32::from_be_bytes(frame.meta[6..10].try_into().unwrap());
            let seq = u32::from_be_bytes(frame.meta[10..14].try_into().unwrap());
            match frame.meta[0] {
                PROTOCOL_OPEN_SESSION_REQ => {
                    if sessions.contains_key(&id) { continue; }
                    let state = Arc::new(Mutex::new(MieruSessionState::new(id)));
                    state.lock().await.advance_recv_seq(seq);

                    let user = user_index.read().users().iter()
                        .find(|u| u.panel_user.id == authenticated.panel_user.id
                            && u.hashed_password == authenticated.hashed_password)
                        .map(|u| u.panel_user.clone());
                    let Some(user) = user else {
                        writer.lock().await.write_control(&state, PROTOCOL_CLOSE_SESSION_REQ).await?;
                        continue;
                    };
                    let guard = if ctx.device_limiter.check_and_record_async(user.id, client_ip).await {
                        ctx.conn_limiter.try_acquire(user.id)
                    } else { None };
                    let Some(guard) = guard else {
                        writer.lock().await.write_control(&state, PROTOCOL_CLOSE_SESSION_REQ).await?;
                        continue;
                    };
                    writer.lock().await.write_control(&state, PROTOCOL_OPEN_SESSION_RESP).await?;
                    let (input, mut packets) = mpsc::channel::<Vec<u8>>(8);
                    if !frame.payload.is_empty() {
                        input.try_send(frame.payload).map_err(|_| Error::other("Mieru initial payload queue failed"))?;
                    }
                    let session_cancel = cancel.child_token();
                    sessions.insert(id, TcpSession { input, state: state.clone(), cancel: session_cancel.clone() });
                    let writer = writer.clone();
                    let ctx = ctx.clone();
                    let connection_cancel = cancel.clone();
                    tasks.spawn(async move {
                        let (client, transport) = tokio::io::duplex(65536);
                        let (client_read, client_write) = tokio::io::split(client);
                        let (mut output, mut input) = tokio::io::split(transport);
                        let mut pumps = tokio::task::JoinSet::new();
                        let incoming = pumps.spawn(async move {
                            while let Some(packet) = packets.recv().await {
                                if input.write_all(&packet).await.is_err() { break; }
                            }
                            let _ = input.shutdown().await;
                        });
                        let output_writer = writer.clone();
                        let output_state = state.clone();
                        let failed = connection_cancel.clone();
                        pumps.spawn(async move {
                            let mut buffer = vec![0u8; 16384];
                            loop {
                                match output.read(&mut buffer).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if let Err(e) = output_writer.lock().await.write_data(&output_state, &buffer[..n]).await {
                                            debug!(error = %e, "Mieru TCP writer failed");
                                            failed.cancel();
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                        tokio::select! {
                            _ = session_cancel.cancelled() => {},
                            result = handle_socks5_session(client_read, client_write, user, client_ip, ctx, guard) => {
                                if let Err(error) = result { debug!(session_id = id, %error, "Mieru session closed"); }
                            },
                        }
                        incoming.abort();

                        while let Some(result) = pumps.join_next().await {
                            if result.is_err_and(|e| e.is_panic()) { connection_cancel.cancel(); }
                        }
                        let mut writer = writer.lock().await;
                        if !state.lock().await.is_closed {
                            if writer.write_control(&state, PROTOCOL_CLOSE_SESSION_REQ).await.is_err() {
                                connection_cancel.cancel();
                            }
                        }
                        id
                    });
                }
                PROTOCOL_CLOSE_SESSION_REQ | PROTOCOL_CLOSE_SESSION_RESP => {
                    if let Some(session) = sessions.get(&id) {
                        session.state.lock().await.advance_recv_seq(seq);
                        if frame.meta[0] == PROTOCOL_CLOSE_SESSION_REQ {
                            writer.lock().await.write_control(&session.state, PROTOCOL_CLOSE_SESSION_RESP).await?;
                        } else {
                            session.state.lock().await.is_closed = true;
                        }
                        session.cancel.cancel();
                    }
                }
                _ => {
                    if let Some(session) = sessions.get(&id) {
                        session.state.lock().await.advance_recv_seq(seq);
                        if frame.meta[0] != PROTOCOL_ACK_C2S && !frame.payload.is_empty() {
                            let sent = tokio::select! {
                                _ = shutdown.recv() => break,
                                _ = cancel.cancelled() => break,
                                _ = session.cancel.cancelled() => continue,
                                sent = session.input.send(frame.payload) => sent,
                            };
                            if sent.is_err() {
                                writer.lock().await.write_control(&session.state, PROTOCOL_CLOSE_SESSION_REQ).await?;
                                session.cancel.cancel();
                            }
                        }
                    } else {
                        let state = Arc::new(Mutex::new(MieruSessionState::new(id)));
                        state.lock().await.next_send_seq = u32::from_be_bytes(frame.meta[14..18].try_into().unwrap());
                        writer.lock().await.write_control(&state, PROTOCOL_CLOSE_SESSION_REQ).await?;
                    }
                }
            }
        }
        Ok(())
    }.await;
    cancel.cancel();
    readers.abort_all();
    tasks.abort_all();
    while readers.join_next().await.is_some() {}
    while tasks.join_next().await.is_some() {}
    result
}

async fn perform_tcp_handshake(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: &InboundContext,
    user_index: &Arc<RwLock<MieruUserIndex>>,
    pattern: &Arc<TrafficPatternExecutor>,
) -> io::Result<Option<HandshakeTuple>> {
    let (source, mut stream) =
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
    if let Some(source) = source {
        remote_addr = source;
    }
    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(None);
    }
    let mut header = [0u8; 72];
    if let Err(e) = stream.read_exact(&mut header).await {
        if e.kind() == ErrorKind::UnexpectedEof || e.kind() == ErrorKind::ConnectionReset {
            return Ok(None);
        }
        return Err(e);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&header[..24]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let decrypted = user_index
        .read()
        .try_decrypt_metadata(&header[24..], &nonce, now);
    let Some((user, key, meta)) = decrypted else {
        ctx.defense.record_failure(client_ip);
        return Ok(None);
    };
    if meta[0] != PROTOCOL_OPEN_SESSION_REQ {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Mieru first frame must open a session",
        ));
    }
    increment_nonce(&mut nonce);
    let decoder = MieruStreamCipher::new(XChaCha20Poly1305::new_from_slice(&key).unwrap(), nonce);
    let mut send_nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut send_nonce);
    pattern.apply_nonce_pattern(&mut send_nonce, false, true);
    let encoder =
        MieruStreamCipher::new(XChaCha20Poly1305::new_from_slice(&key).unwrap(), send_nonce);
    let stream: BoxedStream = Box::new(stream);
    let (input, output) = tokio::io::split(stream);
    let mut reader = MieruSessionReader::new(input, decoder);
    let first = reader.read_payload(meta).await?;
    let writer = MieruSessionWriter::new(output, encoder, (**pattern).clone());
    ctx.defense.record_success(client_ip);
    Ok(Some((reader, writer, user, client_ip, first)))
}
