use super::session::{make_frame, CMD_FIN, CMD_PSH, CMD_SYNACK};
use super::stream::parse_socks5_addr;
use crate::observability::AuditRecord;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub const UOT_V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub const UOT_V1_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

#[allow(clippy::too_many_arguments)]
pub async fn run_anytls_uot_worker(
    stream_id: u32,
    client_version: u32,
    mut initial_payload: Vec<u8>,
    mut stream_rx: mpsc::Receiver<Vec<u8>>,
    session_tx: mpsc::Sender<Vec<u8>>,
    user: Arc<User>,
    ctx: InboundContext,
    client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    uot_cancel: CancellationToken,
) -> std::io::Result<()> {
    // Read UoT request header: [isConnect 1B][SOCKS5 Destination...]
    while initial_payload.len() < 2 {
        tokio::select! {
            _ = uot_cancel.cancelled() => return Ok(()),
            chunk_opt = stream_rx.recv() => {
                match chunk_opt {
                    Some(c) => initial_payload.extend_from_slice(&c),
                    None => return Ok(()),
                }
            }
        }
    }

    let is_connect = initial_payload[0] == 1;
    let mut leftover = &initial_payload[1..];
    let (dest_host, dest_ip, dest_port, rem_after_addr) = loop {
        if let Some(parsed) = parse_socks5_addr(leftover) {
            break parsed;
        }
        tokio::select! {
            _ = uot_cancel.cancelled() => return Ok(()),
            chunk_opt = stream_rx.recv() => {
                match chunk_opt {
                    Some(c) => {
                        let off = leftover.as_ptr() as usize - initial_payload.as_ptr() as usize;
                        initial_payload.extend_from_slice(&c);
                        leftover = &initial_payload[off..];
                    }
                    None => return Ok(()),
                }
            }
        }
    };

    let pending_data = rem_after_addr.to_vec();

    // Audit check
    if ctx.audit.should_block(&dest_host, dest_ip, dest_port) {
        if client_version >= 2 {
            let _ = session_tx
                .send(make_frame(CMD_SYNACK, stream_id, b"blocked by audit rule"))
                .await;
        }
        let _ = session_tx.send(make_frame(CMD_FIN, stream_id, &[])).await;
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "udp",
        target_host: &dest_host,
        target_ip: dest_ip,
        target_port: dest_port,
        inbound_local_ip: local_ip,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    // [Requirement ⑥]: Route UDP through Elise UdpDialer
    let udp_socket = match ctx
        .router
        .dialer()
        .dial_udp_outbound(&outbound, &dest_host, dest_port, local_ip)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            if client_version >= 2 {
                let err_msg = format!("UDP dial error: {e}");
                let _ = session_tx
                    .send(make_frame(CMD_SYNACK, stream_id, err_msg.as_bytes()))
                    .await;
            }
            let _ = session_tx.send(make_frame(CMD_FIN, stream_id, &[])).await;
            return Ok(());
        }
    };

    // [Requirement ④]: Send empty SYNACK on success
    if client_version >= 2 {
        let _ = session_tx
            .send(make_frame(CMD_SYNACK, stream_id, &[]))
            .await;
    }

    let start_time = Instant::now();
    let mut total_up = 0u64;
    let mut total_down = 0u64;
    let rate_limiter_up = ctx.rate_limiter.clone();
    let rate_limiter_down = ctx.rate_limiter.clone();
    let user_id = user.id;

    let cancel_up_for_up = uot_cancel.clone();
    let cancel_down_for_up = uot_cancel.clone();
    let cancel_up_for_down = uot_cancel.clone();
    let cancel_down_for_down = uot_cancel.clone();
    let udp_socket = Arc::new(udp_socket);
    let udp_socket_send = udp_socket.clone();

    // Upstream: Client UoT stream -> Parse UDP packets -> Send via UdpOutbound
    let up_task = async move {
        let mut up = 0u64;
        let mut buffer = pending_data;

        loop {
            // Process any fully framed packets in buffer:
            // In connected mode: [length u16be][payload]
            while buffer.len() >= 2 {
                let pkt_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
                if buffer.len() < 2 + pkt_len {
                    break;
                }
                let pkt_data = &buffer[2..2 + pkt_len];
                rate_limiter_up.throttle(user_id, pkt_len).await;
                if udp_socket_send.send(pkt_data).await.is_err() {
                    cancel_down_for_up.cancel();
                    return up;
                }
                up += pkt_len as u64;
                buffer.drain(..2 + pkt_len);
            }

            tokio::select! {
                _ = cancel_up_for_up.cancelled() => break,
                chunk_opt = stream_rx.recv() => {
                    match chunk_opt {
                        Some(chunk) => buffer.extend_from_slice(&chunk),
                        None => break,
                    }
                }
            }
        }
        up
    };

    // Downstream: UdpOutbound recv -> Wrap in UoT frames -> Send via session_tx
    let down_task = async move {
        let mut down = 0u64;
        let mut recv_buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                _ = cancel_down_for_down.cancelled() => break,
                recv_res = udp_socket.recv(&mut recv_buf) => {
                    let (n, _addr) = match recv_res {
                        Ok(res) if res.0 > 0 => res,
                        _ => break,
                    };

                    rate_limiter_down.throttle(user_id, n).await;
                    let mut uot_frame = Vec::with_capacity(2 + n);
                    uot_frame.extend_from_slice(&(n as u16).to_be_bytes());
                    uot_frame.extend_from_slice(&recv_buf[..n]);

                    let frame = make_frame(CMD_PSH, stream_id, &uot_frame);
                    if session_tx.send(frame).await.is_err() {
                        cancel_up_for_down.cancel();
                        break;
                    }
                    down += n as u64;
                }
            }
        }
        let _ = session_tx.send(make_frame(CMD_FIN, stream_id, &[])).await;
        down
    };

    let (u, d) = tokio::join!(up_task, down_task);
    total_up += u;
    total_down += d;

    let duration = start_time.elapsed();

    if total_up > 0 || total_down > 0 {
        (ctx.on_traffic)(user.id, total_up, total_down);
    }

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "anytls",
        if is_connect {
            "udp-uot2-conn"
        } else {
            "udp-uot2"
        },
        &client_ip.to_string(),
        &dest_host,
        dest_port,
        total_up,
        total_down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}
