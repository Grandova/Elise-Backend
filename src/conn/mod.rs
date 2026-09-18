pub mod listener;
pub mod proxy_protocol;
pub mod sniffer;
pub mod udp;

pub use listener::bind_tcp_listener;
pub use proxy_protocol::{
    encode_proxy_protocol_v1, encode_proxy_protocol_v2, parse_proxy_protocol_datagram,
    read_proxy_protocol, read_proxy_protocol_with_meta, ConnectionMeta, PrefixedStream,
    ProxyProtocolMode,
};
pub use sniffer::{sniff_and_detect_stream, sniff_async_stream, sniff_domain};

use crate::limiter::RateLimiter;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

/// MonitoredStream wraps the client inbound connection to track upload and download bandwidth.
/// Reading from the stream = client uploading to server.
/// Writing to the stream = server downloading/replying to client.
pub struct MonitoredStream<S> {
    inner: S,
    pub user_id: u32,
    pub client_addr: SocketAddr,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl<S> MonitoredStream<S> {
    pub fn new(inner: S, user_id: u32, client_addr: SocketAddr) -> Self {
        Self {
            inner,
            user_id,
            client_addr,
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
        )
    }

    pub fn upload_handle(&self) -> Arc<AtomicU64> {
        self.upload.clone()
    }

    pub fn download_handle(&self) -> Arc<AtomicU64> {
        self.download.clone()
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MonitoredStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let read_bytes = (buf.filled().len() - before) as u64;
            // Data read from client is client upload
            self.upload.fetch_add(read_bytes, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MonitoredStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            // Data written to client is client download
            self.download.fetch_add(*n as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Native ultra-optimized bidirectional stream copy with 32KB buffer and integrated rate limiting.
/// When user has no speed limit active, utilizes Tokio's zero-lock poll-driven bidirectional engine
/// directly, avoiding split locks and reducing memory usage by 50%.
pub async fn copy_bidirectional_throttled<A, B>(
    a: &mut A,
    b: &mut B,
    user_id: u32,
    rate_limiter: Option<&RateLimiter>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    const BUFFER_SIZE: usize = 32768; // 32KB optimal socket buffer size

    // Fast-path: if no speed limit is configured for this user, execute zero-lock poll copy directly
    if !rate_limiter.is_some_and(|r| r.is_limited(user_id)) {
        return tokio::io::copy_bidirectional_with_sizes(a, b, BUFFER_SIZE, BUFFER_SIZE).await;
    }

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let a_to_b = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            let n = a_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(limiter) = rate_limiter {
                limiter.throttle(user_id, n).await;
            }
            b_write.write_all(&buf[..n]).await?;
            b_write.flush().await?;
            total += n as u64;
        }
        b_write.shutdown().await?;
        Ok::<u64, io::Error>(total)
    };

    let b_to_a = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            let n = b_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(limiter) = rate_limiter {
                limiter.throttle(user_id, n).await;
            }
            a_write.write_all(&buf[..n]).await?;
            a_write.flush().await?;
            total += n as u64;
        }
        a_write.shutdown().await?;
        Ok::<u64, io::Error>(total)
    };

    let (res_a, res_b) = tokio::try_join!(a_to_b, b_to_a)?;
    if res_b > 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok((res_a, res_b))
}
