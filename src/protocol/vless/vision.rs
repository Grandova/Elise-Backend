use super::header::process_uuid;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const FLOW_VISION: &str = "xtls-rprx-vision";

pub const VISION_CMD_CONTINUE: u8 = 0x00;
pub const VISION_CMD_END: u8 = 0x01;
pub const VISION_CMD_DIRECT: u8 = 0x02;

pub const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
pub const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
pub const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
pub const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

pub struct TrafficState {
    pub user_uuid: [u8; 16],
    pub packets_to_filter: usize,
    pub enable_xtls: bool,
    pub is_tls: bool,
    pub is_tls12_or_above: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
    pub is_padding: bool,
}

impl TrafficState {
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            packets_to_filter: 8,
            enable_xtls: false,
            is_tls: false,
            is_tls12_or_above: false,
            cipher: 0,
            remaining_server_hello: -1,
            is_padding: true,
        }
    }

    pub fn filter_tls(&mut self, data: &[u8], is_downlink: bool) {
        if self.packets_to_filter == 0 || data.is_empty() {
            return;
        }
        self.packets_to_filter = self.packets_to_filter.saturating_sub(1);

        if !is_downlink {
            if data.len() >= 6 && data.starts_with(&TLS_CLIENT_HANDSHAKE_START) && data[5] == 0x01 {
                self.is_tls = true;
            }
        } else {
            if data.len() >= 6 && data.starts_with(&TLS_SERVER_HANDSHAKE_START) && data[5] == 0x02 {
                self.remaining_server_hello = (((data[3] as i32) << 8) | (data[4] as i32)) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;

                if data.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = data[43] as usize;
                    let cipher_pos = 44 + session_id_len;
                    if cipher_pos + 2 <= data.len() {
                        self.cipher = u16::from_be_bytes([data[cipher_pos], data[cipher_pos + 1]]);
                    }
                }
            }

            if self.remaining_server_hello > 0 {
                let end = (self.remaining_server_hello as usize).min(data.len());
                self.remaining_server_hello -= data.len() as i32;

                if data[..end]
                    .windows(TLS13_SUPPORTED_VERSIONS.len())
                    .any(|w| w == TLS13_SUPPORTED_VERSIONS)
                {
                    if self.cipher != 0x1305 {
                        self.enable_xtls = true;
                    }
                    self.packets_to_filter = 0;
                    return;
                } else if self.remaining_server_hello <= 0 {
                    self.packets_to_filter = 0;
                    return;
                }
            }
        }
    }
}

use super::timing::{record_event, SharedTimingTracker, VisionTimingEvent};

pub struct VisionReader<R> {
    inner: R,
    user_uuid: [u8; 16],
    buf: Vec<u8>,
    buf_pos: usize,
    direct: bool,
    is_first: bool,
    timing_tracker: Option<SharedTimingTracker>,
    direct_control: Option<crate::conn::TlsDirectControl>,
}

impl<R: AsyncRead + Unpin> VisionReader<R> {
    pub fn new(inner: R, user_uuid: [u8; 16]) -> Self {
        Self {
            inner,
            user_uuid,
            buf: Vec::new(),
            buf_pos: 0,
            direct: false,
            is_first: true,
            timing_tracker: None,
            direct_control: None,
        }
    }

    pub fn set_timing_tracker(&mut self, tracker: Option<SharedTimingTracker>) {
        self.timing_tracker = tracker;
    }

    pub fn set_direct_control(&mut self, direct_control: Option<crate::conn::TlsDirectControl>) {
        self.direct_control = direct_control;
    }

    pub async fn read_payload(&mut self, dest: &mut [u8]) -> io::Result<usize> {
        if dest.is_empty() {
            return Ok(0);
        }

        loop {
            if self.buf_pos < self.buf.len() {
                let n = (self.buf.len() - self.buf_pos).min(dest.len());
                dest[..n].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + n]);
                self.buf_pos += n;
                return Ok(n);
            }

            if self.direct {
                return self.inner.read(dest).await;
            }

            if self.is_first {
                let mut uuid = [0u8; 16];
                self.inner.read_exact(&mut uuid).await?;
                if uuid != self.user_uuid && process_uuid(uuid) != process_uuid(self.user_uuid) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VLESS Vision UUID mismatch",
                    ));
                }
                self.is_first = false;
            }

            let mut hdr = [0u8; 5];
            if self.inner.read(&mut hdr[..1]).await? == 0 {
                return Ok(0);
            }
            self.inner.read_exact(&mut hdr[1..]).await?;
            let command = hdr[0];
            let content_len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
            let padding_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

            self.buf.resize(content_len, 0);
            self.buf_pos = 0;
            if content_len > 0 {
                self.inner.read_exact(&mut self.buf).await?;
            }

            if padding_len > 0 {
                let mut discard = [0u8; 1024];
                let mut rem = padding_len;
                while rem > 0 {
                    let to_read = rem.min(discard.len());
                    self.inner.read_exact(&mut discard[..to_read]).await?;
                    rem -= to_read;
                }
            }

            if command == VISION_CMD_END || command == VISION_CMD_DIRECT {
                if !self.direct {
                    self.direct = true;
                    if command == VISION_CMD_DIRECT && self.direct_control.is_some() {
                        if let Some(ctrl) = &self.direct_control {
                            ctrl.direct_read
                                .store(true, std::sync::atomic::Ordering::Release);
                        }
                        record_event(&self.timing_tracker, VisionTimingEvent::DirectCopyEnabled);
                    } else {
                        record_event(&self.timing_tracker, VisionTimingEvent::CommandPaddingEnd);
                    }
                }
            }

            if content_len > 0 {
                let n = (self.buf.len() - self.buf_pos).min(dest.len());
                dest[..n].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + n]);
                self.buf_pos += n;
                return Ok(n);
            }
        }
    }
}

pub struct VisionWriter<W> {
    inner: W,
    traffic_state: TrafficState,
    direct: bool,
    is_first: bool,
    packet_count: usize,
    timing_tracker: Option<SharedTimingTracker>,
    direct_control: Option<crate::conn::TlsDirectControl>,
}

impl<W: AsyncWrite + Unpin> VisionWriter<W> {
    pub fn new(inner: W, user_uuid: [u8; 16]) -> Self {
        Self {
            inner,
            traffic_state: TrafficState::new(user_uuid),
            direct: false,
            is_first: true,
            packet_count: 0,
            timing_tracker: None,
            direct_control: None,
        }
    }

    pub fn set_timing_tracker(&mut self, tracker: Option<SharedTimingTracker>) {
        self.timing_tracker = tracker;
    }

    pub fn set_direct_control(&mut self, direct_control: Option<crate::conn::TlsDirectControl>) {
        self.direct_control = direct_control;
    }

    pub fn state_mut(&mut self) -> &mut TrafficState {
        &mut self.traffic_state
    }

    pub async fn write_payload(&mut self, data: &[u8]) -> io::Result<()> {
        if self.direct {
            self.inner.write_all(data).await?;
            return self.inner.flush().await;
        }

        self.traffic_state.filter_tls(data, true);

        let is_tls_app_data = data.len() >= 3 && data.starts_with(&TLS_APPLICATION_DATA_START);
        let (command, switch_direct) = if is_tls_app_data {
            if self.traffic_state.enable_xtls && self.direct_control.is_some() {
                (VISION_CMD_DIRECT, true)
            } else {
                (VISION_CMD_END, true)
            }
        } else if !self.traffic_state.is_tls12_or_above
            && (self.packet_count >= 2 || self.traffic_state.packets_to_filter <= 1)
        {
            (VISION_CMD_END, true)
        } else {
            (VISION_CMD_CONTINUE, false)
        };

        if command == VISION_CMD_DIRECT {
            record_event(
                &self.timing_tracker,
                VisionTimingEvent::CommandPaddingDirect,
            );
        } else if command == VISION_CMD_END {
            record_event(&self.timing_tracker, VisionTimingEvent::CommandPaddingEnd);
        }

        let content_len = data.len();
        let pad_len = if content_len < 900 {
            let r = (rand::random::<u16>() % 500) as usize;
            r + 900 - content_len
        } else {
            (rand::random::<u16>() % 256) as usize
        };
        let pad_len = pad_len.min(2048);

        let mut frame =
            Vec::with_capacity((if self.is_first { 16 } else { 0 }) + 5 + content_len + pad_len);

        if self.is_first {
            frame.extend_from_slice(&self.traffic_state.user_uuid);
            self.is_first = false;
        }

        frame.push(command);
        frame.extend_from_slice(&(content_len as u16).to_be_bytes());
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        frame.extend_from_slice(data);
        frame.resize(frame.len() + pad_len, 0);

        self.inner.write_all(&frame).await?;
        self.inner.flush().await?;

        if self.packet_count == 0 {
            record_event(&self.timing_tracker, VisionTimingEvent::FirstVisionWrite);
        }

        if switch_direct {
            if !self.direct {
                self.direct = true;
                if command == VISION_CMD_DIRECT {
                    if let Some(ctrl) = &self.direct_control {
                        ctrl.direct_write
                            .store(true, std::sync::atomic::Ordering::Release);
                    }
                }
                record_event(&self.timing_tracker, VisionTimingEvent::DirectCopyEnabled);
            }
        } else {
            self.packet_count += 1;
        }

        Ok(())
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        let _ = self.inner.flush().await;
        self.inner.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn end_frame_drains_buffer_before_direct_and_rejects_truncation() {
        let mut wire = vec![0x55; 16];
        wire.extend_from_slice(&[VISION_CMD_END, 0, 6, 0, 0]);
        wire.extend_from_slice(b"abcdefraw");
        let mut reader = VisionReader::new(wire.as_slice(), [0x55; 16]);
        let mut data = Vec::new();
        let mut buf = [0; 2];
        loop {
            let n = reader.read_payload(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        assert_eq!(data, b"abcdefraw");
        for end in 17..27 {
            let mut reader = VisionReader::new(&wire[..end], [0x55; 16]);
            assert_eq!(
                reader.read_payload(&mut [0; 64]).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn test_vision_reader_and_writer_roundtrip() {
        let user_uuid = [0x55u8; 16];
        let (client_stream, mut server_stream) = tokio::io::duplex(65536);

        let client_task = tokio::spawn(async move {
            let mut writer = VisionWriter::new(client_stream, user_uuid);
            writer.write_payload(b"hello tls client").await.unwrap();
            let app_data = [0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
            writer.write_payload(&app_data).await.unwrap();
        });

        let mut reader = VisionReader::new(&mut server_stream, user_uuid);
        let mut buf1 = vec![0u8; 64];
        let n1 = reader.read_payload(&mut buf1).await.unwrap();
        assert_eq!(&buf1[..n1], b"hello tls client");

        let mut buf2 = vec![0u8; 64];
        let n2 = reader.read_payload(&mut buf2).await.unwrap();
        assert_eq!(
            &buf2[..n2],
            &[0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]
        );

        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_vision_reader_handles_empty_padding_frames() {
        let user_uuid = [0x55u8; 16];
        let mut wire = user_uuid.to_vec();

        wire.push(VISION_CMD_CONTINUE);
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&16u16.to_be_bytes());
        wire.extend_from_slice(&[0xaa; 16]);

        wire.push(VISION_CMD_END);
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(&10u16.to_be_bytes());
        wire.extend_from_slice(b"world");
        wire.extend_from_slice(&[0xbb; 10]);

        wire.extend_from_slice(b" direct payload");

        let mut reader = VisionReader::new(wire.as_slice(), user_uuid);
        let mut out = Vec::new();
        let mut buf = [0u8; 16];
        loop {
            let n = reader.read_payload(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, b"world direct payload");
    }

    #[tokio::test]
    async fn test_vision_direct_control_transition_tls13() {
        use std::sync::atomic::Ordering;

        let user_uuid = [0x42u8; 16];
        let direct_control_writer = crate::conn::TlsDirectControl::default();
        let direct_control_reader = crate::conn::TlsDirectControl::default();

        let (client_stream, mut server_stream) = tokio::io::duplex(65536);

        let mut writer = VisionWriter::new(client_stream, user_uuid);
        writer.set_direct_control(Some(direct_control_writer.clone()));

        let mut server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x50, 0x02];
        server_hello.resize(44, 0);
        server_hello.push(0);
        server_hello.extend_from_slice(&0x1301u16.to_be_bytes());
        server_hello.push(0);
        server_hello.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        server_hello.resize(85, 0);

        writer.write_payload(&server_hello).await.unwrap();
        assert!(writer.state_mut().enable_xtls);
        assert!(!direct_control_writer.direct_write.load(Ordering::Acquire));

        let app_data = [0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];
        writer.write_payload(&app_data).await.unwrap();

        assert!(direct_control_writer.direct_write.load(Ordering::Acquire));
        assert!(writer.direct);

        let mut reader = VisionReader::new(&mut server_stream, user_uuid);
        reader.set_direct_control(Some(direct_control_reader.clone()));

        let mut buf_sh = vec![0u8; 128];
        let n_sh = reader.read_payload(&mut buf_sh).await.unwrap();
        assert_eq!(&buf_sh[..n_sh], &server_hello[..]);
        assert!(!direct_control_reader.direct_read.load(Ordering::Acquire));

        let mut buf_ad = vec![0u8; 128];
        let n_ad = reader.read_payload(&mut buf_ad).await.unwrap();
        assert_eq!(&buf_ad[..n_ad], &app_data[..]);

        assert!(direct_control_reader.direct_read.load(Ordering::Acquire));
        assert!(reader.direct);
    }

    #[tokio::test]
    async fn test_vision_no_direct_control_falls_back_to_cmd_end() {
        use std::sync::atomic::Ordering;

        let user_uuid = [0x42u8; 16];
        let (client_stream, mut server_stream) = tokio::io::duplex(65536);

        let mut writer = VisionWriter::new(client_stream, user_uuid);

        let mut server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x50, 0x02];
        server_hello.resize(44, 0);
        server_hello.push(0);
        server_hello.extend_from_slice(&0x1301u16.to_be_bytes());
        server_hello.push(0);
        server_hello.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        server_hello.resize(85, 0);

        writer.write_payload(&server_hello).await.unwrap();
        assert!(writer.state_mut().enable_xtls);

        let app_data = [0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];
        writer.write_payload(&app_data).await.unwrap();

        assert!(writer.direct);

        let direct_control_reader = crate::conn::TlsDirectControl::default();
        let mut reader = VisionReader::new(&mut server_stream, user_uuid);
        reader.set_direct_control(Some(direct_control_reader.clone()));

        let mut buf_sh = vec![0u8; 128];
        let n_sh = reader.read_payload(&mut buf_sh).await.unwrap();
        assert_eq!(&buf_sh[..n_sh], &server_hello[..]);
        assert!(!direct_control_reader.direct_read.load(Ordering::Acquire));

        let mut buf_ad = vec![0u8; 128];
        let n_ad = reader.read_payload(&mut buf_ad).await.unwrap();
        assert_eq!(&buf_ad[..n_ad], &app_data[..]);

        assert!(!direct_control_reader.direct_read.load(Ordering::Acquire));
        assert!(reader.direct);
    }
}
