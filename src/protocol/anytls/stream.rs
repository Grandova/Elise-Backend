use super::session::{make_frame, CMD_FIN, CMD_PSH, CMD_SYNACK};
use crate::observability::AuditRecord;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub fn parse_socks5_addr(data: &[u8]) -> Option<(String, Option<IpAddr>, u16, &[u8])> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return None;
            }
            let ip = IpAddr::V4(Ipv4Addr::new(data[1], data[2], data[3], data[4]));
            let port = u16::from_be_bytes([data[5], data[6]]);
            Some((ip.to_string(), Some(ip), port, &data[7..]))
        }
        0x03 => {
            if data.len() < 2 {
                return None;
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return None;
            }
            let domain = String::from_utf8_lossy(&data[2..2 + len]).to_string();
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Some((domain, None, port, &data[4 + len..]))
        }
        0x04 => {
            if data.len() < 19 {
                return None;
            }
            let mut ipv6 = [0u8; 16];
            ipv6.copy_from_slice(&data[1..17]);
            let ip = IpAddr::V6(Ipv6Addr::from(ipv6));
            let port = u16::from_be_bytes([data[17], data[18]]);
            Some((ip.to_string(), Some(ip), port, &data[19..]))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_anytls_stream_worker(
    stream_id: u32,
    client_version: u32,
    target_host: String,
    target_ip: Option<IpAddr>,
    target_port: u16,
    initial_payload: Vec<u8>,
    mut stream_rx: mpsc::Receiver<Vec<u8>>,
    session_tx: mpsc::Sender<Vec<u8>>,
    user: Arc<User>,
    ctx: InboundContext,
    client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    stream_cancel: CancellationToken,
) -> std::io::Result<()> {
    let sniffed = if ctx.global_config.domain_sniff && !initial_payload.is_empty() {
        crate::conn::sniff_domain(&initial_payload).map(|(d, _)| d)
    } else {
        None
    };

    let match_host = sniffed.as_deref().unwrap_or(&target_host);
    let dial_host = if ctx.global_config.sniff_redirect {
        match_host
    } else {
        &target_host
    };

    if ctx.audit.should_block(match_host, target_ip, target_port) {
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
        network: "tcp",
        target_host: match_host,
        target_ip,
        target_port,
        inbound_local_ip: local_ip,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, target_port, local_ip)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            if client_version >= 2 {
                let err_msg = format!("dial error: {e}");
                let _ = session_tx
                    .send(make_frame(CMD_SYNACK, stream_id, err_msg.as_bytes()))
                    .await;
            }
            let _ = session_tx.send(make_frame(CMD_FIN, stream_id, &[])).await;
            return Ok(());
        }
    };

    if client_version >= 2 {
        let _ = session_tx
            .send(make_frame(CMD_SYNACK, stream_id, &[]))
            .await;
    }

    let start_time = Instant::now();
    let mut total_up = 0u64;
    let mut total_down = 0u64;

    if !initial_payload.is_empty() {
        let n = initial_payload.len();
        ctx.rate_limiter.throttle(user.id, n).await;
        if out_stream.write_all(&initial_payload).await.is_err() {
            let _ = session_tx.send(make_frame(CMD_FIN, stream_id, &[])).await;
            return Ok(());
        }
        total_up += n as u64;
    }

    let (mut out_read, mut out_write) = tokio::io::split(out_stream);
    let rate_limiter = ctx.rate_limiter.clone();
    let user_id = user.id;

    let cancel_up = stream_cancel.clone();
    let cancel_down = stream_cancel.clone();

    let up_task = async {
        let mut up = 0u64;
        loop {
            tokio::select! {
                _ = cancel_up.cancelled() => break,
                chunk_opt = stream_rx.recv() => {
                    match chunk_opt {
                        Some(chunk) => {
                            let n = chunk.len();
                            rate_limiter.throttle(user_id, n).await;
                            if out_write.write_all(&chunk).await.is_err() {
                                cancel_down.cancel();
                                break;
                            }
                            up += n as u64;
                        }
                        None => {

                            let _ = out_write.shutdown().await;
                            break;
                        }
                    }
                }
            }
        }
        let _ = out_write.shutdown().await;
        up
    };

    let down_task = async {
        let mut buf = vec![0u8; 16384];
        let mut down = 0u64;
        loop {
            tokio::select! {
                _ = cancel_down.cancelled() => break,
                read_res = out_read.read(&mut buf) => {
                    let n = match read_res {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };

                    rate_limiter.throttle(user_id, n).await;
                    let frame = make_frame(CMD_PSH, stream_id, &buf[..n]);
                    if session_tx.send(frame).await.is_err() {
                        cancel_up.cancel();
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
        "tcp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        total_up,
        total_down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks5_ipv4() {
        let mut data = vec![0x01, 1, 2, 3, 4, 0x01, 0xbb];
        data.extend_from_slice(b"extra payload");

        let (host, ip, port, leftover) = parse_socks5_addr(&data).unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(port, 443);
        assert_eq!(leftover, b"extra payload");
    }

    #[test]
    fn test_parse_socks5_domain() {
        let mut data = vec![0x03, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x00, 80]);

        let (host, ip, port, leftover) = parse_socks5_addr(&data).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(ip, None);
        assert_eq!(port, 80);
        assert!(leftover.is_empty());
    }
}
