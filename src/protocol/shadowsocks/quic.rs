use crate::conn::BoxedStream;
use parking_lot::Mutex;
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

type Packet = (Vec<u8>, SocketAddr);

#[derive(Debug)]
struct Socket {
    sender: Arc<dyn AsyncUdpSocket>,
    received: Mutex<mpsc::Receiver<Packet>>,
}

impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.sender.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.sender.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut received = self.received.lock();
        for _ in 0..32 {
            match received.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()))
                }
                Poll::Ready(Some((data, remote))) => {
                    if data.is_empty() || data.len() > bufs[0].len() {
                        continue;
                    }
                    bufs[0][..data.len()].copy_from_slice(&data);
                    meta[0] = quinn::udp::RecvMeta {
                        addr: remote,
                        len: data.len(),
                        stride: data.len(),
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sender.local_addr()
    }
}

pub fn endpoint(
    socket: std::net::UdpSocket,
    tls: &rustls::ServerConfig,
) -> io::Result<(quinn::Endpoint, mpsc::Sender<Packet>)> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls.max_early_data_size = 0;
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(32u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()))
        .stream_receive_window((1024 * 1024u32).into())
        .receive_window((4 * 1024 * 1024u32).into())
        .send_window(4 * 1024 * 1024)
        .datagram_receive_buffer_size(None);
    server.transport_config(Arc::new(transport));
    let runtime = Arc::new(quinn::TokioRuntime);
    let sender = runtime.wrap_udp_socket(socket)?;
    let (send, received) = mpsc::channel(256);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        Default::default(),
        Some(server),
        Arc::new(Socket {
            sender,
            received: Mutex::new(received),
        }),
        runtime,
    )?;
    Ok((endpoint, send))
}

struct Stream {
    read: quinn::RecvStream,
    write: quinn::SendStream,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.write), cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.write), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.write), cx)
    }
}

pub async fn serve<F, Fut>(
    endpoint: quinn::Endpoint,
    cancel: CancellationToken,
    handler: F,
) -> io::Result<()>
where
    F: Fn(BoxedStream, SocketAddr, CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let handler = Arc::new(handler);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result { tracing::warn!(%error, "SS QUIC task failed"); }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                if connections.len() >= 256 { incoming.refuse(); continue; }
                if !incoming.remote_address_validated() && incoming.may_retry() { let _ = incoming.retry(); continue; }
                let handler = handler.clone();
                let cancel = cancel.clone();
                connections.spawn(async move {
                    let connection = tokio::select! {
                        _ = cancel.cancelled() => return,
                        result = tokio::time::timeout(Duration::from_secs(15), incoming) => match result { Ok(Ok(c)) => c, _ => return },
                    };
                    let stream_cancel = cancel.child_token();
                    let mut streams = JoinSet::new();
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = connection.closed() => break,
                            result = streams.join_next(), if !streams.is_empty() => {
                                match result {
                                    Some(Err(error)) => tracing::warn!(%error, "SS QUIC stream task failed"),
                                    Some(Ok(Err(error))) => tracing::debug!(%error, "SS QUIC stream ended"),
                                    _ => {}
                                }
                            }
                            result = connection.accept_bi(), if streams.len() < 32 => {
                                let Ok((write, read)) = result else { break; };
                                let future = handler(Box::new(Stream { read, write }), connection.remote_address(), stream_cancel.clone());
                                streams.spawn(future);
                            }
                        }
                    }
                    connection.close(0u32.into(), b"shutdown");
                    stream_cancel.cancel();
                    while streams.join_next().await.is_some() {}
                });
            }
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    while connections.join_next().await.is_some() {}
    endpoint.wait_idle().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn quic_stream_fin_and_connection_cancellation() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let addr = socket.local_addr().unwrap();
        let (server, packets) = endpoint(socket.try_clone().unwrap(), &tls).unwrap();
        let socket = tokio::net::UdpSocket::from_std(socket).unwrap();
        let cancel = CancellationToken::new();
        let reader_cancel = CancellationToken::new();
        let stop_receiver = reader_cancel.clone();
        let receive = tokio::spawn(async move {
            let mut bytes = vec![0; 65536];
            loop {
                tokio::select! {
                    _ = reader_cancel.cancelled() => break,
                    packet = socket.recv_from(&mut bytes) => {
                        let (n, addr) = packet.unwrap(); let _ = packets.try_send((bytes[..n].to_vec(), addr));
                    }
                }
            }
        });
        let serve = tokio::spawn(super::serve(
            server,
            cancel.clone(),
            |mut stream, _, cancel| async move {
                tokio::select! {
                    _ = cancel.cancelled() => Ok(()),
                    result = async {
                        let mut bytes = Vec::new(); stream.read_to_end(&mut bytes).await?;
                        assert_eq!(bytes, b"request");
                        stream.write_all(&vec![42; 65536]).await?; stream.shutdown().await
                    } => result,
                }
            },
        ));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        tokio::time::timeout(Duration::from_secs(5), async {
            let conn = tokio::time::timeout(
                Duration::from_secs(2),
                client.connect(addr, "localhost").unwrap(),
            )
            .await
            .expect("QUIC handshake timed out")
            .unwrap();
            for _ in 0..2 {
                let (mut write, mut read) = conn.open_bi().await.unwrap();
                write.write_all(b"request").await.unwrap();
                write.finish().unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), read.read_to_end(65537))
                        .await
                        .expect("QUIC FIN response timed out")
                        .unwrap(),
                    vec![42; 65536]
                );
            }
            let (mut write, _read) = conn.open_bi().await.unwrap();
            write.write_all(b"request").await.unwrap();
            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(2), serve)
                .await
                .expect("QUIC shutdown timed out")
                .unwrap()
                .unwrap();
            stop_receiver.cancel();
            receive.await.unwrap();
            assert!(conn.closed().await.to_string().contains("closed"));
        })
        .await
        .unwrap();
        client.close(0u32.into(), b"done");
    }
}
