use super::ss2022::{self, Method, UserIndex};
use crate::protocol::InboundContext;
use crate::conn::proxy_protocol::{parse_proxy_protocol_datagram, ProxyProtocolMode};
use crate::conn::udp::UdpSession;
use parking_lot::RwLock;
use shadowsocks::relay::socks5::Address;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Hash, Eq, PartialEq)]
struct SessionKey {
    remote: SocketAddr,
    user: u32,
    key: [u8; 32],
    session: u64,
    address: Address,
}

struct Session {
    sender: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
}

struct ReplayWindow {
    packets: BTreeSet<u64>,
    highest: u64,
    seen: Instant,
    response: Arc<ResponseSession>,
}

struct ResponseSession {
    id: u64,
    counter: AtomicU64,
}

impl ReplayWindow {
    fn accept(&mut self, packet: u64) -> bool {
        if packet < self.highest.saturating_sub(1023) || !self.packets.insert(packet) {
            return false;
        }
        self.highest = self.highest.max(packet);
        self.packets = self.packets.split_off(&self.highest.saturating_sub(1023));
        self.seen = Instant::now();
        true
    }
}

pub async fn run_udp(
    socket: Arc<UdpSocket>,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<UserIndex>>>,
    method: Method,
    server_key: Arc<Option<Vec<u8>>>,
    cancel: CancellationToken,
    quic: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
) -> io::Result<()> {
    let mut buffer = vec![0; 65536];
    let mut sessions: HashMap<SessionKey, Session> = HashMap::new();
    let mut replay: HashMap<(u32, [u8; 32], u64), ReplayWindow> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    let local_ip = socket.local_addr()?.ip();
    let ss_defense = if ctx.global_config.ss_invalid_access_enable {
        Arc::new(crate::security::AttackDefenseManager::new(
            ctx.global_config.ss_invalid_access_count,
            ctx.global_config.ss_invalid_access_duration,
            ctx.global_config.ss_invalid_access_forbidden_time,
        ))
    } else {
        ctx.defense.clone()
    };
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sweep.tick() => {
                let current = users.read().clone();
                // O(1) set lookup per session instead of O(S * U) nested loop with BLAKE3 hashes!
                sessions.retain(|key, session| {
                    let valid = current.valid_keys.contains(&(key.user, key.key));
                    if !valid { session.cancel.cancel(); }
                    valid && !session.sender.is_closed()
                });
                replay.retain(|_, window| Arc::strong_count(&window.response) > 1 || window.seen.elapsed() < Duration::from_secs(60));
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Err(e)) => tracing::warn!(error = %e, "Shadowsocks UDP task failed"),
                    Some(Ok(Err(e))) => tracing::debug!(error = %e, "Shadowsocks UDP session ended"),
                    _ => {}
                }
            }
            result = socket.recv_from(&mut buffer) => {
                let (length, remote) = result?;
                let (client_remote, payload_slice) = if ctx.global_config.udp_proxy_protocol {
                    match parse_proxy_protocol_datagram(&buffer[..length], ProxyProtocolMode::Auto) {
                        Ok((Some(src), rest)) => (src, rest),
                        _ => (remote, &buffer[..length]),
                    }
                } else {
                    (remote, &buffer[..length])
                };

                if ss_defense.is_banned(client_remote.ip()) { continue; }
                let current = users.read().clone();
                let cached_user_id = ctx.ip_user_cache.get(&client_remote.ip());
                let packet = match ss2022::decrypt_udp_with_cache(method, server_key.as_deref(), &current, payload_slice, cached_user_id) {
                    Ok(packet) => {
                        ctx.ip_user_cache.insert(client_remote.ip(), packet.credential.user.id);
                        ss_defense.record_success(client_remote.ip());
                        packet
                    }
                    Err(_) => {
                        if let Some(quic) = &quic { let _ = quic.try_send((payload_slice.to_vec(), remote)); }
                        else { ss_defense.record_failure(client_remote.ip()); }
                        continue;
                    }
                };
                let hash = *blake3::hash(&packet.credential.key).as_bytes();
                let mut response_session = None;
                if method.is_aead_2022() {
                    let replay_key = (packet.credential.user.id, hash, packet.session_id);
                    if !replay.contains_key(&replay_key) && replay.len() >= 4096 { continue; }
                    let window = replay.entry(replay_key).or_insert_with(|| ReplayWindow { packets: BTreeSet::new(), highest: 0, seen: Instant::now(), response: Arc::new(ResponseSession { id: rand::random(), counter: AtomicU64::new(0) }) });
                    if !window.accept(packet.packet_id) { continue; }
                    response_session = Some(window.response.clone());
                }
                let host = packet.address.host();
                if host.is_empty() || packet.address.port() == 0 || ctx.audit.should_block(&host, host.parse().ok(), packet.address.port()) { continue; }
                let key = SessionKey { remote, user: packet.credential.user.id, key: hash, session: packet.session_id, address: packet.address.clone() };
                if sessions.get(&key).is_some_and(|s| s.sender.is_closed()) { sessions.remove(&key); }
                if let Some(session) = sessions.get(&key) {
                    let _ = session.sender.try_send(packet.payload);
                    continue;
                }
                if sessions.len() >= 4096 { continue; }
                let (sender, requests) = mpsc::channel(256);
                let child_cancel = cancel.child_token();
                let _ = sender.try_send(packet.payload);
                sessions.insert(key, Session { sender, cancel: child_cancel.clone() });
                let ctx = ctx.clone();
                let socket = socket.clone();
                tasks.spawn(async move {
                    let session = tokio::select! {
                        _ = child_cancel.cancelled() => return Ok(()),
                        result = UdpSession::connect(ctx, packet.credential.user.id, client_remote, host, packet.address.port(), Some(local_ip), "shadowsocks") => result?,
                    };
                    let (responses, mut received) = mpsc::channel(256);
                    let relay = session.relay(requests, responses, child_cancel.clone());
                    tokio::pin!(relay);
                    loop {
                        tokio::select! {
                            _ = child_cancel.cancelled() => return Ok(()),
                            result = &mut relay => return result,
                            response = received.recv() => {
                                let Some((response, response_address, ack)) = response else { return Ok(()); };
                                let (server_session, counter) = match &response_session {
                                    Some(session) => (session.id, session.counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)).map_err(|_| io::Error::other("SS2022 packet counter exhausted"))?),
                                    None => (0, 0),
                                };
                                let encoded = match ss2022::encrypt_udp(method, &packet.credential, &response_address, packet.session_id, server_session, counter, &response) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        tracing::debug!(error = %e, "SS UDP encode response failed");
                                        continue;
                                    }
                                };
                                tokio::select! {
                                    _ = child_cancel.cancelled() => return Ok(()),
                                    result = socket.send_to(&encoded, remote) => {
                                        match result {
                                            Ok(_) => { let _ = ack.send(()); }
                                            Err(e) => { tracing::debug!(error = %e, "SS UDP send_to remote failed"); }
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
    }
    for session in sessions.values() {
        session.cancel.cancel();
    }
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                tracing::warn!(error = %e, "Shadowsocks UDP shutdown task failed");
            }
        }
    };
    let close_quic = async {
        if let Some(quic) = quic {
            // Keep ACK/close packets flowing while Quinn drains its connections.
            let _ = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    tokio::select! {
                        _ = quic.closed() => break,
                        packet = socket.recv_from(&mut buffer) => {
                            let Ok((n, remote)) = packet else { break; };
                            let _ = quic.try_send((buffer[..n].to_vec(), remote));
                        }
                    }
                }
            })
            .await;
        }
    };
    tokio::join!(drain, close_quic);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_window_handles_reordering_and_counter_edges() {
        let mut window = ReplayWindow {
            packets: BTreeSet::new(),
            highest: 0,
            seen: Instant::now(),
            response: Arc::new(ResponseSession {
                id: 1,
                counter: AtomicU64::new(0),
            }),
        };
        assert!(window.accept(0));
        assert!(window.accept(1024));
        assert!(!window.accept(0));
        assert!(window.accept(1));
        assert!(!window.accept(1));
        assert!(window.accept(u64::MAX));
        assert!(window.accept(u64::MAX - 1));
        assert!(!window.accept(u64::MAX));
        assert!(!window.accept(1024));
    }
}
