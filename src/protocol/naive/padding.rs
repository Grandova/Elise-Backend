use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const K_FIRST_PADDINGS: usize = 8;

/// NaiveProxy Padded Stream Wrapper.
/// For the first `kFirstPaddings = 8` frames in both read and write directions,
/// encapsulates data in `[orig_size_high, orig_size_low, pad_len, data..., pad_zeros...]`
/// and strips padding upon reception. After 8 frames, transitions seamlessly to raw transparent byte streaming.
pub struct NaivePaddedStream<S> {
    inner: S,
    reads_padded_left: usize,
    writes_padded_left: usize,
    read_buf: BytesMut,
    write_buf: BytesMut,
    pending_data: BytesMut,
}

impl<S> NaivePaddedStream<S> {
    pub fn new(inner: S, padding_enabled: bool) -> Self {
        let count = if padding_enabled { K_FIRST_PADDINGS } else { 0 };
        Self {
            inner,
            reads_padded_left: count,
            writes_padded_left: count,
            read_buf: BytesMut::with_capacity(8192),
            write_buf: BytesMut::with_capacity(8192),
            pending_data: BytesMut::new(),
        }
    }

    pub fn reads_padded_left(&self) -> usize {
        self.reads_padded_left
    }

    pub fn writes_padded_left(&self) -> usize {
        self.writes_padded_left
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for NaivePaddedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            // 1. Deliver any pending extracted payload first
            if !self.pending_data.is_empty() {
                let to_copy = self.pending_data.len().min(output.remaining());
                output.put_slice(&self.pending_data[..to_copy]);
                self.pending_data.advance(to_copy);
                return Poll::Ready(Ok(()));
            }

            // 2. If unpadded mode (either disabled or finished 8 frames)
            if self.reads_padded_left == 0 {
                // If there are leftover bytes in read_buf, deliver them first
                if !self.read_buf.is_empty() {
                    let to_copy = self.read_buf.len().min(output.remaining());
                    output.put_slice(&self.read_buf[..to_copy]);
                    self.read_buf.advance(to_copy);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut self.inner).poll_read(cx, output);
            }

            // 3. Padded mode: Check if read_buf has a full frame
            if self.read_buf.len() >= 3 {
                let orig_size = ((self.read_buf[0] as usize) << 8) | (self.read_buf[1] as usize);
                let pad_size = self.read_buf[2] as usize;
                let total_frame_len = 3 + orig_size + pad_size;

                if self.read_buf.len() >= total_frame_len {
                    self.read_buf.advance(3);
                    let payload = self.read_buf.split_to(orig_size);
                    self.read_buf.advance(pad_size);
                    self.reads_padded_left -= 1;

                    if !payload.is_empty() {
                        let to_copy = payload.len().min(output.remaining());
                        output.put_slice(&payload[..to_copy]);
                        if to_copy < payload.len() {
                            self.pending_data.extend_from_slice(&payload[to_copy..]);
                        }
                        return Poll::Ready(Ok(()));
                    } else {
                        // Empty payload frame, continue to next frame
                        continue;
                    }
                }
            }

            // 4. Need more bytes to complete frame
            let mut temp = [0u8; 8192];
            let mut r_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut r_buf) {
                Poll::Ready(Ok(())) => {
                    let n = r_buf.filled().len();
                    if n == 0 {
                        if !self.read_buf.is_empty() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "incomplete naive padded frame at EOF",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    self.read_buf.extend_from_slice(r_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NaivePaddedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        // Flush existing write buffer first
        while !this.write_buf.is_empty() {
            let buf_slice: &[u8] = &this.write_buf;
            match Pin::new(&mut this.inner).poll_write(cx, buf_slice) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero bytes written to inner stream",
                        )));
                    }
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if this.writes_padded_left == 0 {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }

        // Encapsulate into PaddedData frame
        let chunk_len = data.len().min(65535);
        let pad_len = rand::thread_rng().gen_range(0..=255) as usize;
        let total_frame_len = 3 + chunk_len + pad_len;

        this.write_buf.reserve(total_frame_len);
        this.write_buf.put_u8((chunk_len >> 8) as u8);
        this.write_buf.put_u8((chunk_len & 0xff) as u8);
        this.write_buf.put_u8(pad_len as u8);
        this.write_buf.put_slice(&data[..chunk_len]);
        this.write_buf.put_bytes(0, pad_len);
        this.writes_padded_left -= 1;

        // Try sending buffered frame
        while !this.write_buf.is_empty() {
            let buf_slice: &[u8] = &this.write_buf;
            match Pin::new(&mut this.inner).poll_write(cx, buf_slice) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero bytes written to inner stream",
                        )));
                    }
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break, // frame queued in buffer
            }
        }

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            let buf_slice: &[u8] = &this.write_buf;
            match Pin::new(&mut this.inner).poll_write(cx, buf_slice) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero bytes written to inner stream",
                        )));
                    }
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            let buf_slice: &[u8] = &this.write_buf;
            match Pin::new(&mut this.inner).poll_write(cx, buf_slice) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero bytes written to inner stream",
                        )));
                    }
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
