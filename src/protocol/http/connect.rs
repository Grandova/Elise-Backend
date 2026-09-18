use crate::conn::{BoxedStream, MonitoredStream, PrefixedStream};
use crate::observability::AuditRecord;
use crate::panel::types::User;
use crate::protocol::http::auth::{RESP_200_CONNECTION_ESTABLISHED, RESP_502_BAD_GATEWAY};
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::AsyncWriteExt;

pub async fn handle_connect(
    client_stream: BoxedStream,
    target: &str,
    leftover: &[u8],
    user: &User,
    remote_addr: SocketAddr,
    ctx: &InboundContext,
) -> io::Result<(u64, u64)> {
    let authority = target
        .parse::<http::uri::Authority>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid CONNECT authority"))?;
    let port = authority.port_u16().filter(|p| *p > 0).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "CONNECT requires a valid port")
    })?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    relay(
        client_stream,
        host,
        port,
        leftover.to_vec(),
        user,
        remote_addr,
        ctx,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn relay(
    mut client_stream: BoxedStream,
    host: &str,
    port: u16,
    prefix: Vec<u8>,
    user: &User,
    remote_addr: SocketAddr,
    ctx: &InboundContext,
    connect: bool,
) -> io::Result<(u64, u64)> {
    let ip = host.parse().ok();
    // CONNECT clients normally wait for 200 before sending TLS; only early data
    // can affect routing before the tunnel is established.
    let sniffed = if ctx.global_config.domain_sniff && ip.is_some() {
        crate::conn::sniff_domain(&prefix).map(|(host, _)| host)
    } else {
        None
    };
    let match_host = sniffed.as_deref().unwrap_or(host);
    if ctx.audit.should_block(host, ip, port) || ctx.audit.should_block(match_host, ip, port) {
        client_stream.write_all(RESP_502_BAD_GATEWAY).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Blocked by audit",
        ));
    }
    let outbound = ctx.router.match_outbound(&MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: match_host,
        target_ip: ip,
        target_port: port,
        inbound_local_ip: None,
    });
    let dial_host = if ctx.global_config.sniff_redirect {
        match_host
    } else {
        host
    };
    let mut target = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, port, None)
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            let _ = client_stream.write_all(RESP_502_BAD_GATEWAY).await;
            return Err(e);
        }
    };
    if connect {
        client_stream
            .write_all(RESP_200_CONNECTION_ESTABLISHED)
            .await?;
        client_stream.flush().await?;
    }
    let stream = PrefixedStream::new(client_stream, Some(prefix));
    let mut client = MonitoredStream::new(stream, user.id, remote_addr);
    let _traffic = client.traffic_guard(ctx.on_traffic.clone());
    let started = Instant::now();
    let result = crate::conn::copy_bidirectional_throttled(
        &mut client,
        &mut target,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;
    let (up, down) = client.stats();
    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "http",
        "tcp",
        &remote_addr.ip().to_string(),
        host,
        port,
        up,
        down,
        started.elapsed().as_millis() as i64,
        &outbound.tag,
        if result.is_ok() { "completed" } else { "error" },
    ));
    result.map(|_| (up, down))
}
