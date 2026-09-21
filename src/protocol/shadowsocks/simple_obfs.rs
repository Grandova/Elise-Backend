use crate::conn::{BoxedStream, PrefixedStream};
use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::AsyncReadExt;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tokio_util::io::{SinkWriter, StreamReader};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub async fn accept_http(
    mut stream: BoxedStream,
    expected_host: Option<&str>,
) -> io::Result<BoxedStream> {
    let mut data = Vec::new();
    let end = loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if data.len() >= 16384 {
            return Err(invalid("Obfs HTTP header too large"));
        }
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        data.extend_from_slice(&buffer[..n]);
    };
    let header =
        std::str::from_utf8(&data[..end]).map_err(|_| invalid("Invalid obfs HTTP header"))?;
    let mut lines = header.split("\r\n");
    if !lines.next().is_some_and(|l| l.ends_with(" HTTP/1.1")) {
        return Err(invalid("Invalid obfs HTTP request"));
    }
    let mut host = None;
    let mut upgrade = false;
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("Invalid obfs HTTP field"))?;
        if name.eq_ignore_ascii_case("host") && host.replace(value.trim()).is_some() {
            return Err(invalid("Duplicate obfs Host"));
        }
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade = value.trim().eq_ignore_ascii_case("websocket");
        }
    }
    if !upgrade
        || expected_host.is_some_and(|h| {
            !host.is_some_and(|actual| {
                let hostname = actual
                    .rsplit_once(':')
                    .filter(|(_, port)| port.parse::<u16>().is_ok())
                    .map_or(actual, |(host, _)| host);
                hostname.eq_ignore_ascii_case(h)
            })
        })
    {
        return Err(invalid("Obfs HTTP Host/Upgrade rejected"));
    }
    let key: [u8; 16] = rand::random();
    let response = format!("HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nDate: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT"), base64::engine::general_purpose::STANDARD.encode(key));
    let (reader, writer) = tokio::io::split(stream);
    let reader = PrefixedStream::new(reader, Some(data[end..].to_vec()));
    let writer = SinkWriter::new(FramedWrite::new(
        writer,
        HttpResponse(Some(response.into_bytes())),
    ));
    Ok(Box::new(tokio::io::join(reader, writer)))
}

struct HttpResponse(Option<Vec<u8>>);
impl Encoder<&[u8]> for HttpResponse {
    type Error = io::Error;
    fn encode(&mut self, data: &[u8], output: &mut BytesMut) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if let Some(header) = self.0.take() {
            output.extend_from_slice(&header);
        }
        output.extend_from_slice(data);
        Ok(())
    }
}

pub async fn accept_tls(
    mut stream: BoxedStream,
    expected_host: Option<&str>,
) -> io::Result<BoxedStream> {
    let mut record = [0; 5];
    stream.read_exact(&mut record).await?;
    if record[0] != 0x16 || record[1] != 3 || !matches!(record[2], 1 | 3) {
        return Err(invalid("Invalid obfs ClientHello record"));
    }
    let length = u16::from_be_bytes([record[3], record[4]]) as usize;
    let mut hello = vec![0; length];
    stream.read_exact(&mut hello).await?;
    if length < 76
        || hello[0] != 1
        || hello[1] != 0
        || u16::from_be_bytes([hello[2], hello[3]]) as usize + 4 != length
        || hello[38] != 32
    {
        return Err(invalid("Invalid obfs ClientHello length/session"));
    }
    let session: [u8; 32] = hello[39..71].try_into().unwrap();
    let cipher_len = u16::from_be_bytes([hello[71], hello[72]]) as usize;
    let mut offset = 73 + cipher_len;
    if cipher_len == 0 || !cipher_len.is_multiple_of(2) || offset >= length {
        return Err(invalid("Invalid obfs cipher list"));
    }
    offset += 1 + hello[offset] as usize;
    if offset + 2 > length {
        return Err(invalid("Truncated obfs extensions"));
    }
    let extensions = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2;
    if offset + extensions != length {
        return Err(invalid("Invalid obfs extension length"));
    }
    let mut ticket = None;
    let mut host = None;
    while offset < length {
        if offset + 4 > length {
            return Err(invalid("Truncated obfs extension"));
        }
        let kind = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        offset += 4;
        if offset + len > length {
            return Err(invalid("Truncated obfs extension body"));
        }
        let body = &hello[offset..offset + len];
        match kind {
            35 => {
                if ticket.replace(body.to_vec()).is_some() {
                    return Err(invalid("Duplicate obfs session ticket"));
                }
            }
            0 => {
                if len < 5
                    || body[2] != 0
                    || u16::from_be_bytes([body[0], body[1]]) as usize + 2 != len
                    || u16::from_be_bytes([body[3], body[4]]) as usize + 5 != len
                {
                    return Err(invalid("Invalid obfs SNI"));
                }
                host = Some(
                    std::str::from_utf8(&body[5..])
                        .map_err(|_| invalid("Invalid obfs SNI encoding"))?,
                );
            }
            _ => {}
        }
        offset += len;
    }
    if expected_host.is_some_and(|h| host != Some(h)) {
        return Err(invalid("Obfs SNI rejected"));
    }
    let ticket = ticket.ok_or_else(|| invalid("Missing obfs session ticket"))?;
    let (reader, writer) = tokio::io::split(stream);
    let reader = StreamReader::new(FramedRead::new(reader, TlsRecords));
    let writer = SinkWriter::new(FramedWrite::new(
        writer,
        TlsResponse {
            session: Some(session),
        },
    ));
    Ok(Box::new(PrefixedStream::new(
        tokio::io::join(reader, writer),
        Some(ticket),
    )))
}

struct TlsRecords;
impl Decoder for TlsRecords {
    type Item = Bytes;
    type Error = io::Error;
    fn decode(&mut self, data: &mut BytesMut) -> io::Result<Option<Bytes>> {
        loop {
            if data.len() < 5 {
                return Ok(None);
            }
            if data[..3] != [0x17, 3, 3] {
                return Err(invalid("Invalid obfs application record"));
            }
            let length = u16::from_be_bytes([data[3], data[4]]) as usize;
            if length > 16384 {
                return Err(invalid("Obfs application record too large"));
            }
            if data.len() < length + 5 {
                return Ok(None);
            }
            data.advance(5);
            if length > 0 {
                return Ok(Some(data.split_to(length).freeze()));
            }
        }
    }
    fn decode_eof(&mut self, data: &mut BytesMut) -> io::Result<Option<Bytes>> {
        let frame = self.decode(data)?;
        if frame.is_none() && !data.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(frame)
    }
}

struct TlsResponse {
    session: Option<[u8; 32]>,
}
impl Encoder<&[u8]> for TlsResponse {
    type Error = io::Error;
    fn encode(&mut self, data: &[u8], output: &mut BytesMut) -> io::Result<()> {
        for chunk in data.chunks(16384) {
            let first = self.session.take();
            if let Some(session) = first {
                output.extend_from_slice(&[0x16, 3, 1, 0, 91, 2, 0, 0, 87, 3, 3]);
                output.put_u32(chrono::Utc::now().timestamp() as u32);
                let random: [u8; 28] = rand::random();
                output.extend_from_slice(&random);
                output.put_u8(32);
                output.extend_from_slice(&session);
                output.extend_from_slice(&[
                    0xcc, 0xa8, 0, 0, 0, 0xff, 1, 0, 1, 0, 0, 0x17, 0, 0, 0, 0x0b, 0, 2, 1, 0,
                ]);
                output.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
            }
            output.extend_from_slice(&[if first.is_some() { 0x16 } else { 0x17 }, 3, 3]);
            output.put_u16(chunk.len() as u16);
            output.extend_from_slice(chunk);
        }
        Ok(())
    }
}
