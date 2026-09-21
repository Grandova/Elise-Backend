use crate::conn::{copy_bidirectional_throttled, ConnectionMeta, MonitoredStream};
use crate::observability::AuditRecord;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use std::io;
use std::net::IpAddr;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

pub async fn handle_socks5_connect<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    mut stream: S,
    meta: ConnectionMeta,
    user: User,
    target_host: String,
    target_ip: Option<IpAddr>,
    target_port: u16,
    ctx: InboundContext,
) -> io::Result<()> {
    info!(
        "SOCKS5 CONNECT: user={} client_ip={} target={}:{}",
        user.id,
        meta.client_addr.ip(),
        target_host,
        target_port
    );

    if ctx.audit.should_block(&target_host, target_ip, target_port) {
        let _ = stream
            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
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

    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, &target_host, target_port, None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            debug!(
                "SOCKS5 outbound dial failed to {}:{} -> {:?}",
                target_host, target_port, e
            );

            let _ = stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Ok(());
        }
    };

    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let mut client_monitored = MonitoredStream::new(stream, user.id, meta.client_addr);
    let _traffic = client_monitored.traffic_guard(ctx.on_traffic.clone());
    let start_time = Instant::now();

    let _ = copy_bidirectional_throttled(
        &mut client_monitored,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;

    let duration = start_time.elapsed();
    let (up, down) = client_monitored.stats();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "socks5",
        "tcp",
        &meta.client_addr.ip().to_string(),
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
