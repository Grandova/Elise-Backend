use super::aead::VlessAead;
use super::xor::{decode_header, encode_header, XorFilter};
use crate::conn::{BoxedStream, TlsDirectControl};
use bytes::{Buf, BytesMut};
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_PAYLOAD_CHUNK: usize = 8192;

pub struct VlessEncryptionStream {
    inner: BoxedStream,
    use_aes: bool,
    united_key: Vec<u8>,
    aead: VlessAead,
    peer_aead: VlessAead,
    xor_filter: Option<XorFilter>,
    pub direct_control: TlsDirectControl,

    pre_write: Option<Vec<u8>>,
    write_buf: Vec<u8>,
    write_pos: usize,

    read_raw_buf: BytesMut,
    read_decrypted_buf: BytesMut,
}

impl VlessEncryptionStream {
    pub fn new(
        inner: BoxedStream,
        use_aes: bool,
        united_key: Vec<u8>,
        aead: VlessAead,
        peer_aead: VlessAead,
        pre_write: Option<Vec<u8>>,
        xor_filter: Option<XorFilter>,
    ) -> Self {
        Self {
            inner,
            use_aes,
            united_key,
            aead,
            peer_aead,
            xor_filter,
            direct_control: TlsDirectControl::default(),
            pre_write,
            write_buf: Vec::new(),
            write_pos: 0,
            read_raw_buf: BytesMut::with_capacity(16645),
            read_decrypted_buf: BytesMut::with_capacity(16384),
        }
    }

    pub fn direct_control(&self) -> Option<TlsDirectControl> {
        if self.xor_filter.is_some() {
            None
        } else {
            Some(self.direct_control.clone())
        }
    }
}

impl AsyncRead for VlessEncryptionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if !this.read_decrypted_buf.is_empty() {
            let to_copy = this.read_decrypted_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_decrypted_buf[..to_copy]);
            this.read_decrypted_buf.advance(to_copy);
            if this.read_decrypted_buf.is_empty() {
                this.read_decrypted_buf.clear();
            }
            return Poll::Ready(Ok(()));
        }

        if this.direct_control.direct_read.load(Ordering::Acquire) {
            if !this.read_raw_buf.is_empty() {
                let to_copy = this.read_raw_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_raw_buf[..to_copy]);
                this.read_raw_buf.advance(to_copy);
                if this.read_raw_buf.is_empty() {
                    this.read_raw_buf.clear();
                }
                return Poll::Ready(Ok(()));
            }

            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        loop {
            if this.read_raw_buf.len() < 5 {
                let mut temp = [0u8; 1024];
                let mut temp_buf = ReadBuf::new(&mut temp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            if !this.read_raw_buf.is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF during VLESS encryption header read",
                                )));
                            }
                            return Poll::Ready(Ok(()));
                        }
                        let filled = temp_buf.filled_mut();
                        if let Some(ref mut xor) = this.xor_filter {
                            xor.filter_in(filled);
                        }
                        this.read_raw_buf.extend_from_slice(filled);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if this.read_raw_buf.len() < 5 {
                continue;
            }

            let header = [
                this.read_raw_buf[0],
                this.read_raw_buf[1],
                this.read_raw_buf[2],
                this.read_raw_buf[3],
                this.read_raw_buf[4],
            ];
            let payload_len = match decode_header(&header) {
                Ok(l) => l,
                Err(e) => return Poll::Ready(Err(e)),
            };

            let total_frame_len = 5 + payload_len;
            if this.read_raw_buf.len() < total_frame_len {
                let mut temp = [0u8; 4096];
                let mut temp_buf = ReadBuf::new(&mut temp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF during VLESS encryption frame read",
                            )));
                        }
                        let filled = temp_buf.filled_mut();
                        if let Some(ref mut xor) = this.xor_filter {
                            xor.filter_in(filled);
                        }
                        this.read_raw_buf.extend_from_slice(filled);
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let frame = this.read_raw_buf.split_to(total_frame_len);
            let frame_header = &frame[..5];
            let frame_ciphertext = &frame[5..];

            let is_max = this.peer_aead.is_max_nonce();
            let decrypted = this.peer_aead.open(None, frame_ciphertext, frame_header)?;
            if is_max {
                this.peer_aead = VlessAead::new(&frame, &this.united_key, this.use_aes);
            }
            this.read_decrypted_buf.extend_from_slice(&decrypted);

            let to_copy = this.read_decrypted_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_decrypted_buf[..to_copy]);
            this.read_decrypted_buf.advance(to_copy);

            if this.read_decrypted_buf.is_empty() {
                this.read_decrypted_buf.clear();
            }
            if this.read_raw_buf.is_empty() {
                this.read_raw_buf.clear();
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for VlessEncryptionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        while this.write_pos < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf.clear();
        this.write_pos = 0;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.direct_control.direct_write.load(Ordering::Acquire) {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let chunk_len = buf.len().min(MAX_PAYLOAD_CHUNK);
        let chunk = &buf[..chunk_len];

        let record_payload_len = chunk_len + 16;
        let mut header = [0u8; 5];
        encode_header(&mut header, record_payload_len);

        let is_max = this.aead.is_max_nonce();
        let ciphertext = this.aead.seal(None, chunk, &header)?;

        let needed_cap = (if this.pre_write.is_some() { 16 } else { 0 }) + 5 + ciphertext.len();
        this.write_buf.reserve(needed_cap);

        if let Some(pre) = this.pre_write.take() {
            this.write_buf.extend_from_slice(&pre);
        }

        this.write_buf.extend_from_slice(&header);
        this.write_buf.extend_from_slice(&ciphertext);

        if is_max {
            let mut rekey_ctx = Vec::with_capacity(5 + ciphertext.len());
            rekey_ctx.extend_from_slice(&header);
            rekey_ctx.extend_from_slice(&ciphertext);
            this.aead = VlessAead::new(&rekey_ctx, &this.united_key, this.use_aes);
        }

        if let Some(ref mut xor) = this.xor_filter {
            xor.filter_out(&mut this.write_buf);
        }

        this.write_pos = 0;

        while this.write_pos < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return Poll::Ready(Ok(chunk_len));
                }
            }
        }

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.write_pos < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn encrypted(
        inner: impl AsyncRead + AsyncWrite + Send + Unpin + 'static,
    ) -> VlessEncryptionStream {
        let key = vec![0x33; 96];
        VlessEncryptionStream::new(
            Box::new(inner),
            true,
            key.clone(),
            VlessAead::new(b"io-test", &key, true),
            VlessAead::new(b"io-test", &key, true),
            None,
            None,
        )
    }

    struct ZeroWriter(usize);

    impl AsyncRead for ZeroWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ZeroWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0 += 1;
            assert_eq!(
                self.0, 1,
                "zero-progress write must not be polled in a loop"
            );
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_zero_fails_without_spinning() {
        for pending in [false, true] {
            let mut stream = encrypted(ZeroWriter(0));
            if pending {
                stream.write_buf.push(1);
            }
            assert_eq!(
                stream.write(b"payload").await.unwrap_err().kind(),
                io::ErrorKind::WriteZero
            );
        }
    }

    #[tokio::test]
    async fn flush_zero_fails_without_spinning() {
        let mut stream = encrypted(ZeroWriter(0));
        stream.write_buf.push(1);
        assert_eq!(
            stream.flush().await.unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }

    #[tokio::test]
    async fn shutdown_drains_pending_frame_and_preserves_half_close() {
        let (a, b) = tokio::io::duplex(64);
        let mut sender = encrypted(a);
        let mut receiver = encrypted(b);
        let payload = vec![0x42; 4096];
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let send = async {
                sender.write_all(&payload).await.unwrap();
                assert!(sender.write_pos < sender.write_buf.len());
                sender.shutdown().await.unwrap();
                let mut response = Vec::new();
                sender.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"ack");
            };
            let receive = async {
                let mut received = Vec::new();
                receiver.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, payload);
                receiver.write_all(b"ack").await.unwrap();
                receiver.shutdown().await.unwrap();
            };
            tokio::join!(send, receive);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn truncated_header_is_not_clean_eof() {
        for len in 1..5 {
            let (mut a, b) = tokio::io::duplex(64);
            a.write_all(&[23, 3, 3, 0][..len]).await.unwrap();
            a.shutdown().await.unwrap();
            let mut receiver = encrypted(b);
            assert_eq!(
                receiver.read(&mut [0; 1]).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn empty_read_does_not_poll_pending_transport() {
        let (_a, b) = tokio::io::duplex(64);
        let mut stream = encrypted(b);
        let mut empty = [];
        let mut buf = ReadBuf::new(&mut empty);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
    }

    #[tokio::test]
    async fn final_nonce_frame_is_opened_before_rekeying() {
        let (a, b) = tokio::io::duplex(65536);
        let mut sender = encrypted(a);
        let mut receiver = encrypted(b);
        sender.aead.nonce = super::super::aead::MAX_NONCE;
        receiver.peer_aead.nonce = super::super::aead::MAX_NONCE;
        sender.write_all(b"old key").await.unwrap();
        sender.write_all(b"new key").await.unwrap();
        sender.shutdown().await.unwrap();
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"old keynew key");
    }

    #[tokio::test]
    async fn test_vless_encryption_stream_duplex() {
        let (s1, s2) = tokio::io::duplex(65536);
        let united_key = vec![0x33u8; 96];

        let aead1 = VlessAead::new(b"ctx-1", &united_key, true);
        let peer_aead1 = VlessAead::new(b"ctx-2", &united_key, true);

        let aead2 = VlessAead::new(b"ctx-2", &united_key, true);
        let peer_aead2 = VlessAead::new(b"ctx-1", &united_key, true);

        let mut stream1 = VlessEncryptionStream::new(
            Box::new(s1),
            true,
            united_key.clone(),
            aead1,
            peer_aead1,
            None,
            None,
        );

        let mut stream2 = VlessEncryptionStream::new(
            Box::new(s2),
            true,
            united_key,
            aead2,
            peer_aead2,
            None,
            None,
        );

        let write_task = tokio::spawn(async move {
            stream1
                .write_all(b"hello VLESS encryption world!")
                .await
                .unwrap();
            stream1.flush().await.unwrap();
        });

        let mut buf = vec![0u8; 64];
        let n = stream2.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello VLESS encryption world!");

        write_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_vless_encryption_stream_direct_read_passthrough() {
        let (mut s1, s2) = tokio::io::duplex(65536);
        let united_key = vec![0x44u8; 96];

        let aead1 = VlessAead::new(b"ctx-1", &united_key, true);
        let peer_aead1 = VlessAead::new(b"ctx-2", &united_key, true);

        let mut stream2 = VlessEncryptionStream::new(
            Box::new(s2),
            true,
            united_key,
            aead1,
            peer_aead1,
            None,
            None,
        );

        stream2
            .direct_control
            .direct_read
            .store(true, Ordering::Release);

        s1.write_all(b"direct-raw-tls-bytes").await.unwrap();
        s1.flush().await.unwrap();

        let mut buf2 = vec![0u8; 64];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        assert_eq!(&buf2[..n2], b"direct-raw-tls-bytes");
    }

    #[tokio::test]
    async fn test_vless_encryption_stream_direct_write_passthrough() {
        let (s1, mut s2) = tokio::io::duplex(65536);
        let united_key = vec![0x44u8; 96];

        let aead1 = VlessAead::new(b"ctx-1", &united_key, true);
        let peer_aead1 = VlessAead::new(b"ctx-2", &united_key, true);

        let mut stream1 = VlessEncryptionStream::new(
            Box::new(s1),
            true,
            united_key,
            aead1,
            peer_aead1,
            None,
            None,
        );

        stream1
            .direct_control
            .direct_write
            .store(true, Ordering::Release);

        stream1
            .write_all(b"direct-write-raw-tls-bytes")
            .await
            .unwrap();
        stream1.flush().await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = s2.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"direct-write-raw-tls-bytes");
    }

    #[tokio::test]
    async fn test_vless_encryption_stream_vision_e2e() {
        let (s1, s2) = tokio::io::duplex(65536);
        let united_key = vec![0x44u8; 96];

        let aead1 = VlessAead::new(b"ctx-1", &united_key, true);
        let peer_aead1 = VlessAead::new(b"ctx-2", &united_key, true);

        let aead2 = VlessAead::new(b"ctx-2", &united_key, true);
        let peer_aead2 = VlessAead::new(b"ctx-1", &united_key, true);

        let stream1 = VlessEncryptionStream::new(
            Box::new(s1),
            true,
            united_key.clone(),
            aead1,
            peer_aead1,
            None,
            None,
        );

        let stream2 = VlessEncryptionStream::new(
            Box::new(s2),
            true,
            united_key,
            aead2,
            peer_aead2,
            None,
            None,
        );

        let ctrl1 = stream1.direct_control().unwrap();
        let ctrl2 = stream2.direct_control().unwrap();

        let (r1, w1) = tokio::io::split(stream1);
        let (r2, w2) = tokio::io::split(stream2);

        let user_uuid = [0x42u8; 16];

        let mut client_writer = crate::protocol::vless::vision::VisionWriter::new(w1, user_uuid);
        client_writer.set_direct_control(Some(ctrl1.clone()));

        let mut client_reader = crate::protocol::vless::vision::VisionReader::new(r1, user_uuid);
        client_reader.set_direct_control(Some(ctrl1));

        let mut server_writer = crate::protocol::vless::vision::VisionWriter::new(w2, user_uuid);
        server_writer.set_direct_control(Some(ctrl2.clone()));

        let mut server_reader = crate::protocol::vless::vision::VisionReader::new(r2, user_uuid);
        server_reader.set_direct_control(Some(ctrl2));

        let mut server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x50, 0x02];
        server_hello.resize(44, 0);
        server_hello.push(0);
        server_hello.extend_from_slice(&0x1301u16.to_be_bytes());
        server_hello.push(0);
        server_hello.extend_from_slice(&crate::protocol::vless::vision::TLS13_SUPPORTED_VERSIONS);
        server_hello.resize(85, 0);

        server_writer.write_payload(&server_hello).await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = client_reader.read_payload(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &server_hello[..]);

        client_writer.state_mut().enable_xtls = true;
        assert!(server_writer.state_mut().enable_xtls);

        let client_app_data = [0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        client_writer.write_payload(&client_app_data).await.unwrap();

        let n = server_reader.read_payload(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &client_app_data[..]);

        let server_app_data = [0x17, 0x03, 0x03, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08];
        server_writer.write_payload(&server_app_data).await.unwrap();

        let n = client_reader.read_payload(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &server_app_data[..]);

        for i in 0..5 {
            let server_msg = format!("server-direct-message-{}", i).into_bytes();
            server_writer.write_payload(&server_msg).await.unwrap();
            let n = client_reader.read_payload(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &server_msg[..]);

            let client_msg = format!("client-direct-message-{}", i).into_bytes();
            client_writer.write_payload(&client_msg).await.unwrap();
            let n = server_reader.read_payload(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &client_msg[..]);
        }
    }
}
