use crate::protocol::mieru::crypto::{increment_nonce, METADATA_LENGTH, NONCE_SIZE, OVERHEAD};
use crate::protocol::mieru::pattern::{decode_low_entropy, TrafficPatternExecutor};
use bytes::BytesMut;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{Tag as XTag, XChaCha20Poly1305, XNonce};
use std::io::{self, Error, ErrorKind};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub const PROTOCOL_OPEN_SESSION_REQ: u8 = 2;
pub const PROTOCOL_OPEN_SESSION_RESP: u8 = 3;
pub const PROTOCOL_CLOSE_SESSION_REQ: u8 = 4;
pub const PROTOCOL_CLOSE_SESSION_RESP: u8 = 5;
pub const PROTOCOL_DATA_C2S: u8 = 6;
pub const PROTOCOL_DATA_S2C: u8 = 7;
pub const PROTOCOL_ACK_C2S: u8 = 8;
pub const PROTOCOL_ACK_S2C: u8 = 9;
pub const PROTOCOL_DATA_C2S_LOW_ENTROPY: u8 = 10;
pub const PROTOCOL_DATA_S2C_LOW_ENTROPY: u8 = 11;

pub const MAX_PDU: usize = 32768;
pub const DEFAULT_WINDOW_SIZE: u16 = 256;

/// Shared session state machine for seq / ack / window tracking
#[derive(Debug)]
pub struct MieruSessionState {
    pub session_id: u32,
    pub next_send_seq: u32,
    pub next_recv_seq: u32,
    pub unack_seq: u32,
    pub window_size: u16,
    pub is_closed: bool,
}

impl MieruSessionState {
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            next_send_seq: 0,
            next_recv_seq: 0,
            unack_seq: 0,
            window_size: DEFAULT_WINDOW_SIZE,
            is_closed: false,
        }
    }

    pub fn alloc_send_seq(&mut self) -> u32 {
        let seq = self.next_send_seq;
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        seq
    }

    pub fn advance_recv_seq(&mut self, seq: u32) {
        if seq >= self.next_recv_seq || (self.next_recv_seq > 0xF000_0000 && seq < 0x1000_0000) {
            self.next_recv_seq = seq.wrapping_add(1);
            self.unack_seq = self.next_recv_seq;
        }
    }

    pub fn next_recv_seq(&self) -> u32 {
        self.next_recv_seq
    }
}

/// Mieru Stream Cipher wrapping XChaCha20Poly1305 and maintaining 24-byte Nonce
pub struct MieruStreamCipher {
    cipher: XChaCha20Poly1305,
    nonce: [u8; NONCE_SIZE],
}

impl MieruStreamCipher {
    pub fn new(cipher: XChaCha20Poly1305, nonce: [u8; NONCE_SIZE]) -> Self {
        Self { cipher, nonce }
    }

    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    pub fn set_nonce(&mut self, nonce: [u8; NONCE_SIZE]) {
        self.nonce = nonce;
    }

    /// Encrypt initial metadata (includes 24-byte nonce prefix)
    pub fn encrypt_initial_metadata(&mut self, meta: &[u8; METADATA_LENGTH]) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(NONCE_SIZE + METADATA_LENGTH + OVERHEAD);
        out.extend_from_slice(&self.nonce);

        let mut buf = meta.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Metadata encrypt failed: {:?}", e)))?;

        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());

        increment_nonce(&mut self.nonce);
        Ok(out)
    }

    /// Encrypt subsequent metadata (48 bytes: 32 meta + 16 tag)
    pub fn encrypt_subsequent_metadata(&mut self, meta: &[u8; METADATA_LENGTH]) -> io::Result<Vec<u8>> {
        let mut buf = meta.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Subsequent metadata encrypt failed: {:?}", e)))?;

        let mut out = Vec::with_capacity(METADATA_LENGTH + OVERHEAD);
        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());

        increment_nonce(&mut self.nonce);
        Ok(out)
    }

    /// Encrypt payload slice
    pub fn encrypt_payload(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut buf = payload.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Payload encrypt failed: {:?}", e)))?;

        buf.extend_from_slice(tag.as_slice());
        increment_nonce(&mut self.nonce);
        Ok(buf)
    }

    /// Decrypt subsequent metadata (expects 48 bytes: 32 meta + 16 tag)
    pub fn decrypt_metadata(&mut self, data: &[u8]) -> io::Result<[u8; METADATA_LENGTH]> {
        if data.len() < METADATA_LENGTH + OVERHEAD {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Metadata too short"));
        }

        let mut buf = data[..METADATA_LENGTH].to_vec();
        let tag = XTag::from_slice(&data[METADATA_LENGTH..METADATA_LENGTH + OVERHEAD]);

        self.cipher
            .decrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf, tag)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Metadata decrypt failed: {:?}", e)))?;

        increment_nonce(&mut self.nonce);

        let mut meta = [0u8; METADATA_LENGTH];
        meta.copy_from_slice(&buf);
        Ok(meta)
    }

    /// Decrypt payload body
    pub fn decrypt_payload(&mut self, data: &[u8], payload_len: usize) -> io::Result<Vec<u8>> {
        if data.len() < payload_len + OVERHEAD {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Payload wire buffer too short"));
        }

        let mut buf = data[..payload_len].to_vec();
        let tag = XTag::from_slice(&data[payload_len..payload_len + OVERHEAD]);

        self.cipher
            .decrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf, tag)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Payload decrypt failed: {:?}", e)))?;

        increment_nonce(&mut self.nonce);
        Ok(buf)
    }
}

/// Reader that parses incoming Mieru segments and exposes an AsyncRead stream
pub struct MieruSessionReader<S> {
    stream: S,
    decoder: MieruStreamCipher,
    session: Arc<Mutex<MieruSessionState>>,
    pending: BytesMut,
    eof_reached: bool,
}

impl<S: AsyncReadExt + Unpin> MieruSessionReader<S> {
    pub fn new(stream: S, decoder: MieruStreamCipher, session: Arc<Mutex<MieruSessionState>>) -> Self {
        Self {
            stream,
            decoder,
            session,
            pending: BytesMut::new(),
            eof_reached: false,
        }
    }

    pub fn seed_pending(&mut self, initial: &[u8]) {
        self.pending.extend_from_slice(initial);
    }

    /// Read next Mieru segment from the stream and decrypt payload.
    /// Returns Ok(Some(payload)) when data arrives.
    /// Returns Ok(None) when the stream closes or receives CLOSE_SESSION_REQ.
    pub async fn read_next_segment(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.pending.is_empty() {
            let data = self.pending.to_vec();
            self.pending.clear();
            return Ok(Some(data));
        }

        if self.eof_reached {
            return Ok(None);
        }

        loop {
            let mut meta_hdr = [0u8; METADATA_LENGTH + OVERHEAD];
            match self.stream.read_exact(&mut meta_hdr).await {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::UnexpectedEof || e.kind() == ErrorKind::ConnectionReset => {
                    self.eof_reached = true;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }

            let meta = self.decoder.decrypt_metadata(&meta_hdr)?;
            let proto = meta[0];

            match proto {
                PROTOCOL_DATA_C2S => {
                    let seq = u32::from_be_bytes(meta[10..14].try_into().unwrap());
                    let prefix_len = meta[21] as usize;
                    let payload_len = u16::from_be_bytes(meta[22..24].try_into().unwrap()) as usize;
                    let suffix_len = meta[24] as usize;

                    if prefix_len > 0 {
                        let mut p_buf = vec![0u8; prefix_len];
                        self.stream.read_exact(&mut p_buf).await?;
                    }

                    let payload = if payload_len > 0 {
                        let mut wire_payload = vec![0u8; payload_len + OVERHEAD];
                        self.stream.read_exact(&mut wire_payload).await?;
                        self.decoder.decrypt_payload(&wire_payload, payload_len)?
                    } else {
                        Vec::new()
                    };

                    if suffix_len > 0 {
                        let mut s_buf = vec![0u8; suffix_len];
                        self.stream.read_exact(&mut s_buf).await?;
                    }

                    let mut s = self.session.lock().await;
                    s.advance_recv_seq(seq);

                    if !payload.is_empty() {
                        return Ok(Some(payload));
                    }
                }
                PROTOCOL_DATA_C2S_LOW_ENTROPY => {
                    let mode = meta[1] as i32;
                    let seq = u32::from_be_bytes(meta[10..14].try_into().unwrap());
                    let prefix_len = meta[21] as usize;
                    let payload_len = u16::from_be_bytes(meta[22..24].try_into().unwrap()) as usize;
                    let suffix_len = meta[24] as usize;
                    let half_mask = u32::from_be_bytes(meta[25..29].try_into().unwrap());
                    let extracted_len = u16::from_be_bytes(meta[29..31].try_into().unwrap()) as usize;
                    let rotation = meta[31] as i32;

                    if prefix_len > 0 {
                        let mut p_buf = vec![0u8; prefix_len];
                        self.stream.read_exact(&mut p_buf).await?;
                    }

                    let raw_payload = if payload_len > 0 {
                        let mut wire_payload = vec![0u8; payload_len + OVERHEAD];
                        self.stream.read_exact(&mut wire_payload).await?;
                        let enc_payload = self.decoder.decrypt_payload(&wire_payload, payload_len)?;
                        decode_low_entropy(&enc_payload, extracted_len, mode, half_mask, rotation)?
                    } else {
                        Vec::new()
                    };

                    if suffix_len > 0 {
                        let mut s_buf = vec![0u8; suffix_len];
                        self.stream.read_exact(&mut s_buf).await?;
                    }

                    let mut s = self.session.lock().await;
                    s.advance_recv_seq(seq);

                    if !raw_payload.is_empty() {
                        return Ok(Some(raw_payload));
                    }
                }
                PROTOCOL_ACK_C2S => {
                    // Client sent ACK segment, advance session unack seq
                    let seq = u32::from_be_bytes(meta[10..14].try_into().unwrap());
                    let mut s = self.session.lock().await;
                    s.advance_recv_seq(seq);
                }
                PROTOCOL_CLOSE_SESSION_REQ => {
                    self.eof_reached = true;
                    let mut s = self.session.lock().await;
                    s.is_closed = true;
                    return Ok(None);
                }
                other => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Unexpected protocol byte in session reader: {}", other),
                    ));
                }
            }
        }
    }
}

/// Writer that formats outbound payloads into Mieru Data segments
pub struct MieruSessionWriter<S> {
    stream: S,
    encoder: MieruStreamCipher,
    session: Arc<Mutex<MieruSessionState>>,
    pattern: TrafficPatternExecutor,
}

impl<S: AsyncWriteExt + Unpin> MieruSessionWriter<S> {
    pub fn new(
        stream: S,
        encoder: MieruStreamCipher,
        session: Arc<Mutex<MieruSessionState>>,
        pattern: TrafficPatternExecutor,
    ) -> Self {
        Self {
            stream,
            encoder,
            session,
            pattern,
        }
    }

    /// Write raw application data framed as Mieru Data segments
    pub async fn write_data(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cur_min = (now_sec / 60) as u32;

        while offset < payload.len() {
            let chunk_len = std::cmp::min(payload.len() - offset, MAX_PDU);
            let chunk = &payload[offset..offset + chunk_len];

            let (session_id, seq, unack_seq, window_size) = {
                let mut s = self.session.lock().await;
                (s.session_id, s.alloc_send_seq(), s.unack_seq, s.window_size)
            };

            let middle_pad = self.pattern.generate_middle_padding();
            let end_pad = self.pattern.generate_end_padding();

            let mut meta = [0u8; METADATA_LENGTH];
            meta[0] = PROTOCOL_DATA_S2C;
            meta[2..6].copy_from_slice(&cur_min.to_be_bytes());
            meta[6..10].copy_from_slice(&session_id.to_be_bytes());
            meta[10..14].copy_from_slice(&seq.to_be_bytes());
            meta[14..18].copy_from_slice(&unack_seq.to_be_bytes());
            meta[18..20].copy_from_slice(&window_size.to_be_bytes());
            meta[20] = 0; // fragment number
            meta[21] = middle_pad.len() as u8;
            meta[22..24].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            meta[24] = end_pad.len() as u8;

            let enc_meta = self.encoder.encrypt_subsequent_metadata(&meta)?;
            let enc_payload = self.encoder.encrypt_payload(chunk)?;

            // Construct frame: metadata (48B) + middle padding + payload + end padding
            let mut frame = Vec::with_capacity(enc_meta.len() + middle_pad.len() + enc_payload.len() + end_pad.len());
            frame.extend_from_slice(&enc_meta);
            if !middle_pad.is_empty() {
                frame.extend_from_slice(&middle_pad);
            }
            frame.extend_from_slice(&enc_payload);
            if !end_pad.is_empty() {
                frame.extend_from_slice(&end_pad);
            }

            // Apply TCP fragmentation if enabled
            if self.pattern.is_tcp_fragment_enabled() {
                let fragments = self.pattern.fragment_tcp_buffer(&frame);
                for frag in fragments {
                    self.stream.write_all(frag).await?;
                    if let Some(sleep) = self.pattern.next_tcp_fragment_sleep() {
                        tokio::time::sleep(sleep).await;
                    }
                }
            } else {
                self.stream.write_all(&frame).await?;
            }

            offset += chunk_len;
        }

        self.stream.flush().await?;
        Ok(())
    }

    /// Send close session notification
    pub async fn close_session(&mut self) -> io::Result<()> {
        let (session_id, seq) = {
            let mut s = self.session.lock().await;
            s.is_closed = true;
            (s.session_id, s.alloc_send_seq())
        };

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cur_min = (now_sec / 60) as u32;

        let mut meta = [0u8; METADATA_LENGTH];
        meta[0] = PROTOCOL_CLOSE_SESSION_REQ;
        meta[2..6].copy_from_slice(&cur_min.to_be_bytes());
        meta[6..10].copy_from_slice(&session_id.to_be_bytes());
        meta[10..14].copy_from_slice(&seq.to_be_bytes());

        let enc_meta = self.encoder.encrypt_subsequent_metadata(&meta)?;
        self.stream.write_all(&enc_meta).await?;
        self.stream.flush().await?;
        Ok(())
    }
}
