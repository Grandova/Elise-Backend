use crate::conn::BoxedStream;
use crate::panel::types::User;
use crate::protocol::http::auth::{RESP_200_CONNECTION_ESTABLISHED, RESP_502_BAD_GATEWAY};
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Handles an HTTP CONNECT tunnel request.
/// Once established, client and target stream are linked via transparent bidirectional copy (no MITM).
pub async fn handle_connect(
    mut client_stream: BoxedStream,
    target: &str,
    leftover: &[u8],
    user: &User,
    conn_id: u64,
) -> io::Result<(u64, u64)> {
    let mut target_stream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "[HTTP CONNECT] conn={} user_id={} failed to connect target {}: {}",
                conn_id, user.id, target, e
            );
            let _ = client_stream.write_all(RESP_502_BAD_GATEWAY).await;
            let _ = client_stream.flush().await;
            return Err(e);
        }
    };
    let _ = target_stream.set_nodelay(true);

    // Reply 200 Connection Established to client
    if let Err(e) = client_stream.write_all(RESP_200_CONNECTION_ESTABLISHED).await {
        warn!(
            "[HTTP CONNECT] conn={} user_id={} failed to send 200 Established: {}",
            conn_id, user.id, e
        );
        return Err(e);
    }
    let _ = client_stream.flush().await;

    // Send leftover bytes if client sent early data after CONNECT headers
    let mut initial_up = 0u64;
    if !leftover.is_empty() {
        if let Err(e) = target_stream.write_all(leftover).await {
            warn!(
                "[HTTP CONNECT] conn={} user_id={} failed to write leftover data to target: {}",
                conn_id, user.id, e
            );
            return Err(e);
        }
        let _ = target_stream.flush().await;
        initial_up = leftover.len() as u64;
    }

    info!(
        "[HTTP CONNECT] conn={} user_id={} target={} tunnel established",
        conn_id, user.id, target
    );

    // Bidirectional transparent relay
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut target_read, mut target_write) = target_stream.into_split();

    let client_to_target = async {
        tokio::io::copy(&mut client_read, &mut target_write).await
    };
    let target_to_client = async {
        tokio::io::copy(&mut target_read, &mut client_write).await
    };

    let (up_res, down_res) = tokio::join!(client_to_target, target_to_client);
    let up = up_res.unwrap_or(0) + initial_up;
    let down = down_res.unwrap_or(0);

    info!(
        "[HTTP CONNECT] conn={} user_id={} target={} tunnel closed (up={} bytes, down={} bytes)",
        conn_id, user.id, target, up, down
    );

    Ok((up, down))
}
