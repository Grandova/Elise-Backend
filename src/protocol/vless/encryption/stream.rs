use super::aead::VlessAead;
use super::xor::{decode_header, encode_header, XorFilter};
use crate::conn::BoxedStream;
use bytes::{Buf, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_PAYLOAD_CHUNK: usize = 8192;

/// Wrapped bidirectional stream handling VLESS Encryption TLS-record framing,
/// AEAD sealing/opening, MaxNonce rekeying, and optional XorConn CTR obfuscation.
pub struct VlessEncryptionStream {
    inner: BoxedStream,
    use_aes: bool,
    united_key: Vec<u8>,
    aead: VlessAead,
    peer_aead: VlessAead,
    xor_filter: Option<XorFilter>,

    // Write state
    pre_write: Option<Vec<u8>>,
    write_buf: Vec<u8>,
    write_pos: usize,

    // Read state
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
            pre_write,
            write_buf: Vec::new(),
            write_pos: 0,
            read_raw_buf: BytesMut::with_capacity(16645),
            read_decrypted_buf: BytesMut::with_capacity(16384),
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

        // If decrypted buffer has data, copy directly to destination
        if !this.read_decrypted_buf.is_empty() {
            let to_copy = this.read_decrypted_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_decrypted_buf[..to_copy]);
            this.read_decrypted_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        // Need to read and decrypt next TLS frame
        loop {
            // Need at least 5-byte header
            if this.read_raw_buf.len() < 5 {
                let mut temp = [0u8; 1024];
                let mut temp_buf = ReadBuf::new(&mut temp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        let mut filled = temp_buf.filled().to_vec();
                        if let Some(ref mut xor) = this.xor_filter {
                            xor.filter_in(&mut filled);
                        }
                        this.read_raw_buf.extend_from_slice(&filled);
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
                // Need more data for full record
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

            // Extract frame
            let frame = this.read_raw_buf.split_to(total_frame_len);
            let frame_header = &frame[..5];
            let frame_ciphertext = &frame[5..];

            // Check MaxNonce rekeying
            if this.peer_aead.is_max_nonce() {
                this.peer_aead = VlessAead::new(&frame, &this.united_key, this.use_aes);
            }

            let decrypted = this.peer_aead.open(None, frame_ciphertext, frame_header)?;
            this.read_decrypted_buf.extend_from_slice(&decrypted);

            let to_copy = this.read_decrypted_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_decrypted_buf[..to_copy]);
            this.read_decrypted_buf.advance(to_copy);

            // Reset internal cursors when buffers are empty to avoid fragmentation
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

        // Flush any pending write bytes first
        while this.write_pos < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
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

        let chunk_len = buf.len().min(MAX_PAYLOAD_CHUNK);
        let chunk = &buf[..chunk_len];

        // Format TLS Record header: [0x17, 0x03, 0x03, len(2B)]
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

        // Start writing immediately
        while this.write_pos < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Packet buffered in write_buf, chunk was consumed
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}
