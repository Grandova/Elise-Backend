use crate::protocol::mieru::crypto::{increment_nonce, METADATA_LENGTH, NONCE_SIZE, OVERHEAD};
use crate::protocol::mieru::pattern::{decode_low_entropy, TrafficPatternExecutor};
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
    pub fn encrypt_initial_metadata(
        &mut self,
        meta: &[u8; METADATA_LENGTH],
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(NONCE_SIZE + METADATA_LENGTH + OVERHEAD);
        out.extend_from_slice(&self.nonce);

        let mut buf = meta.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Metadata encrypt failed: {:?}", e),
                )
            })?;

        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());

        increment_nonce(&mut self.nonce);
        Ok(out)
    }

    /// Encrypt subsequent metadata (48 bytes: 32 meta + 16 tag)
    pub fn encrypt_subsequent_metadata(
        &mut self,
        meta: &[u8; METADATA_LENGTH],
    ) -> io::Result<Vec<u8>> {
        let mut buf = meta.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Subsequent metadata encrypt failed: {:?}", e),
                )
            })?;

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
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Payload encrypt failed: {:?}", e),
                )
            })?;

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
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Metadata decrypt failed: {:?}", e),
                )
            })?;

        increment_nonce(&mut self.nonce);

        let mut meta = [0u8; METADATA_LENGTH];
        meta.copy_from_slice(&buf);
        Ok(meta)
    }

    /// Decrypt payload body
    pub fn decrypt_payload(&mut self, data: &[u8], payload_len: usize) -> io::Result<Vec<u8>> {
        if data.len() < payload_len + OVERHEAD {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Payload wire buffer too short",
            ));
        }

        let mut buf = data[..payload_len].to_vec();
        let tag = XTag::from_slice(&data[payload_len..payload_len + OVERHEAD]);

        self.cipher
            .decrypt_in_place_detached(XNonce::from_slice(&self.nonce), b"", &mut buf, tag)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Payload decrypt failed: {:?}", e),
                )
            })?;

        increment_nonce(&mut self.nonce);
        Ok(buf)
    }
}

pub struct MieruFrame {
    pub meta: [u8; METADATA_LENGTH],
    pub payload: Vec<u8>,
}

/// Nonce state belongs to the TCP connection, not to an individual multiplexed session.
pub struct MieruSessionReader<S> {
    stream: S,
    decoder: MieruStreamCipher,
}

impl<S: AsyncReadExt + Unpin> MieruSessionReader<S> {
    pub fn new(stream: S, decoder: MieruStreamCipher) -> Self {
        Self { stream, decoder }
    }

    pub async fn read_next_segment(&mut self) -> io::Result<Option<MieruFrame>> {
        let mut header = [0u8; METADATA_LENGTH + OVERHEAD];
        if self.stream.read(&mut header[..1]).await? == 0 {
            return Ok(None);
        }
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            self.stream.read_exact(&mut header[1..]).await?;
            let meta = self.decoder.decrypt_metadata(&header)?;
            self.read_payload(meta).await.map(Some)
        })
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "Mieru frame timed out"))?
    }

    pub async fn read_payload(&mut self, meta: [u8; METADATA_LENGTH]) -> io::Result<MieruFrame> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 60;
        let timestamp = u32::from_be_bytes(meta[2..6].try_into().unwrap()) as u64;
        if now.abs_diff(timestamp) > 1 || meta[6..10] == [0; 4] {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Mieru timestamp or session ID",
            ));
        }
        let (prefix, length, suffix) = match meta[0] {
            PROTOCOL_OPEN_SESSION_REQ
            | PROTOCOL_CLOSE_SESSION_REQ
            | PROTOCOL_CLOSE_SESSION_RESP => {
                let length = u16::from_be_bytes(meta[15..17].try_into().unwrap()) as usize;
                if length > 1024 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Mieru session payload exceeds 1024 bytes",
                    ));
                }
                (0, length, meta[17] as usize)
            }
            PROTOCOL_DATA_C2S | PROTOCOL_DATA_C2S_LOW_ENTROPY | PROTOCOL_ACK_C2S => (
                meta[21] as usize,
                u16::from_be_bytes(meta[22..24].try_into().unwrap()) as usize,
                meta[24] as usize,
            ),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid Mieru client frame",
                ))
            }
        };
        let mut padding = [0u8; 255];
        self.stream.read_exact(&mut padding[..prefix]).await?;
        let payload = if length > 0 {
            let mut wire = vec![0u8; length + OVERHEAD];
            self.stream.read_exact(&mut wire).await?;
            if meta[0] == PROTOCOL_DATA_C2S_LOW_ENTROPY {
                let extracted = u16::from_be_bytes(meta[29..31].try_into().unwrap()) as usize;
                // Upstream expands ciphertext including its tag, before putting it on the wire.
                wire = decode_low_entropy(
                    &wire,
                    extracted + OVERHEAD,
                    meta[1] as i32,
                    u32::from_be_bytes(meta[25..29].try_into().unwrap()),
                    meta[31] as i32,
                )?;
                self.decoder.decrypt_payload(&wire, extracted)?
            } else {
                self.decoder.decrypt_payload(&wire, length)?
            }
        } else {
            Vec::new()
        };
        self.stream.read_exact(&mut padding[..suffix]).await?;
        Ok(MieruFrame { meta, payload })
    }
}

/// Writer that formats outbound payloads into Mieru Data segments
pub struct MieruSessionWriter<S> {
    stream: S,
    encoder: MieruStreamCipher,
    initial: bool,
    pattern: TrafficPatternExecutor,
}

impl<S: AsyncWriteExt + Unpin> MieruSessionWriter<S> {
    pub fn new(stream: S, encoder: MieruStreamCipher, pattern: TrafficPatternExecutor) -> Self {
        Self {
            stream,
            encoder,
            initial: true,
            pattern,
        }
    }

    /// Write raw application data framed as Mieru Data segments
    pub async fn write_data(
        &mut self,
        session: &Arc<Mutex<MieruSessionState>>,
        payload: &[u8],
    ) -> io::Result<()> {
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
                let mut s = session.lock().await;
                if s.is_closed {
                    return Ok(());
                }
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
            let mut frame = Vec::with_capacity(
                enc_meta.len() + middle_pad.len() + enc_payload.len() + end_pad.len(),
            );
            frame.extend_from_slice(&enc_meta);
            if !middle_pad.is_empty() {
                frame.extend_from_slice(&middle_pad);
            }
            frame.extend_from_slice(&enc_payload);
            if !end_pad.is_empty() {
                frame.extend_from_slice(&end_pad);
            }

            tokio::time::timeout(std::time::Duration::from_secs(15), async {
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
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "Mieru frame write timed out"))??;

            offset += chunk_len;
        }

        self.stream.flush().await?;
        Ok(())
    }

    pub async fn write_control(
        &mut self,
        session: &Arc<Mutex<MieruSessionState>>,
        protocol: u8,
    ) -> io::Result<()> {
        let (session_id, seq) = {
            let mut s = session.lock().await;
            if protocol == PROTOCOL_CLOSE_SESSION_REQ || protocol == PROTOCOL_CLOSE_SESSION_RESP {
                s.is_closed = true;
            }
            (s.session_id, s.alloc_send_seq())
        };
        let cur_min = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 60) as u32;
        let mut meta = [0u8; METADATA_LENGTH];
        meta[0] = protocol;
        meta[2..6].copy_from_slice(&cur_min.to_be_bytes());
        meta[6..10].copy_from_slice(&session_id.to_be_bytes());
        meta[10..14].copy_from_slice(&seq.to_be_bytes());
        let frame = if self.initial {
            self.initial = false;
            self.encoder.encrypt_initial_metadata(&meta)?
        } else {
            self.encoder.encrypt_subsequent_metadata(&meta)?
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            self.stream.write_all(&frame).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "Mieru control write timed out"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::KeyInit;

    fn metadata(protocol: u8, id: u32) -> [u8; METADATA_LENGTH] {
        let mut meta = [0u8; METADATA_LENGTH];
        meta[0] = protocol;
        let now = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60) as u32;
        meta[2..6].copy_from_slice(&now.to_be_bytes());
        meta[6..10].copy_from_slice(&id.to_be_bytes());
        meta
    }

    fn cipher() -> MieruStreamCipher {
        MieruStreamCipher::new(
            XChaCha20Poly1305::new_from_slice(&[7; 32]).unwrap(),
            [9; 24],
        )
    }

    #[tokio::test]
    async fn interleaved_frames_share_nonce_and_preserve_session_ids() {
        let mut encoder = cipher();
        let mut wire = Vec::new();
        let cases = [
            (PROTOCOL_OPEN_SESSION_REQ, 1),
            (PROTOCOL_OPEN_SESSION_REQ, 2),
            (PROTOCOL_DATA_C2S, 2),
            (PROTOCOL_CLOSE_SESSION_REQ, 1),
            (PROTOCOL_ACK_C2S, 2),
            (PROTOCOL_DATA_C2S, 2),
        ];
        for (protocol, id) in cases {
            let mut meta = metadata(protocol, id);
            if protocol == PROTOCOL_OPEN_SESSION_REQ || protocol == PROTOCOL_CLOSE_SESSION_REQ {
                meta[15..17].copy_from_slice(&3u16.to_be_bytes());
                meta[17] = 2;
            } else {
                meta[21] = 1;
                meta[22..24].copy_from_slice(&3u16.to_be_bytes());
                meta[24] = 2;
            }
            wire.extend(encoder.encrypt_subsequent_metadata(&meta).unwrap());
            if protocol != PROTOCOL_OPEN_SESSION_REQ && protocol != PROTOCOL_CLOSE_SESSION_REQ {
                wire.push(0);
            }
            wire.extend(encoder.encrypt_payload(b"abc").unwrap());
            wire.extend([0; 2]);
        }
        let mut reader = MieruSessionReader::new(wire.as_slice(), cipher());
        for (protocol, id) in cases {
            let frame = reader.read_next_segment().await.unwrap().unwrap();
            assert_eq!(frame.meta[0], protocol);
            assert_eq!(
                u32::from_be_bytes(frame.meta[6..10].try_into().unwrap()),
                id
            );
            assert_eq!(frame.payload, b"abc");
        }
        assert!(reader.read_next_segment().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_truncated_frames_bad_tags_and_invalid_metadata() {
        let mut bad = metadata(PROTOCOL_OPEN_SESSION_REQ, 1);
        bad[15..17].copy_from_slice(&1025u16.to_be_bytes());
        for meta in [
            metadata(PROTOCOL_OPEN_SESSION_REQ, 0),
            metadata(255, 1),
            bad,
            [0; 32],
        ] {
            let wire = cipher().encrypt_subsequent_metadata(&meta).unwrap();
            assert!(MieruSessionReader::new(wire.as_slice(), cipher())
                .read_next_segment()
                .await
                .is_err());
        }
        let meta = metadata(PROTOCOL_OPEN_SESSION_REQ, 1);
        let mut wire = cipher().encrypt_subsequent_metadata(&meta).unwrap();
        for n in [1, 20, wire.len() - 1] {
            assert!(MieruSessionReader::new(&wire[..n], cipher())
                .read_next_segment()
                .await
                .is_err());
        }
        wire[40] ^= 1;
        assert!(MieruSessionReader::new(wire.as_slice(), cipher())
            .read_next_segment()
            .await
            .is_err());
    }
}
