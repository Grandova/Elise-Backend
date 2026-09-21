use std::io::{self, Cursor, Read, Write};

#[path = "huffman_table.rs"]
mod huffman_table;
use self::huffman_table::DECODE_TABLE;

pub fn read_quic_varint<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    let tag = first[0] >> 6;
    let len = 1 << tag;
    let mut val = (first[0] & 0x3f) as u64;

    for _ in 1..len {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        val = (val << 8) | (b[0] as u64);
    }
    Ok(val)
}

pub async fn read_quic_varint_async<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<u64> {
    use tokio::io::AsyncReadExt;
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let tag = first[0] >> 6;
    let len = 1 << tag;
    let mut val = (first[0] & 0x3f) as u64;

    for _ in 1..len {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b).await?;
        val = (val << 8) | (b[0] as u64);
    }
    Ok(val)
}

pub fn write_quic_varint<W: Write>(writer: &mut W, val: u64) -> io::Result<usize> {
    if val <= 63 {
        writer.write_all(&[val as u8])?;
        Ok(1)
    } else if val <= 16383 {
        let buf = [0x40 | ((val >> 8) as u8), val as u8];
        writer.write_all(&buf)?;
        Ok(2)
    } else if val <= 1073741823 {
        let mut buf = [0x80; 4];
        buf[0] |= ((val >> 24) as u8) & 0x3f;
        buf[1] = (val >> 16) as u8;
        buf[2] = (val >> 8) as u8;
        buf[3] = val as u8;
        writer.write_all(&buf)?;
        Ok(4)
    } else {
        let mut buf = [0xc0; 8];
        buf[0] |= ((val >> 56) as u8) & 0x3f;
        buf[1] = (val >> 48) as u8;
        buf[2] = (val >> 40) as u8;
        buf[3] = (val >> 32) as u8;
        buf[4] = (val >> 24) as u8;
        buf[5] = (val >> 16) as u8;
        buf[6] = (val >> 8) as u8;
        buf[7] = val as u8;
        writer.write_all(&buf)?;
        Ok(8)
    }
}

pub fn quic_varint_len(val: u64) -> usize {
    if val <= 63 {
        1
    } else if val <= 16383 {
        2
    } else if val <= 1073741823 {
        4
    } else {
        8
    }
}

const BRANCH: u16 = 0x8000;
const TABLE_INDEX_MASK: u16 = 0x7f00;
const TABLE_WIDTH: usize = 256;

pub fn decode_huffman(src: &[u8]) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(src.len() * 2);
    let mut table = 0;
    let mut acc = 0u32;
    let mut bits = 0;

    for &byte in src {
        acc = (acc << 8) | byte as u32;
        bits += 8;

        while bits >= 8 {
            let index = (acc >> (bits - 8)) as u8 as usize;
            let entry = DECODE_TABLE[table * TABLE_WIDTH + index];

            if entry & BRANCH == 0 {
                buf.push(entry as u8);
                table = 0;
                bits -= (entry >> 8) as usize;
            } else {
                table = ((entry & TABLE_INDEX_MASK) >> 8) as usize;
                if table == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid Huffman code",
                    ));
                }
                bits -= 8;
            }
        }
    }

    while bits > 0 {
        let padding = (1u32 << bits) - 1;
        if table == 0 && acc & padding == padding {
            break;
        }

        let index = (acc << (8 - bits)) as u8 as usize;
        let entry = DECODE_TABLE[table * TABLE_WIDTH + index];
        if entry & BRANCH != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Huffman code",
            ));
        }

        let used = (entry >> 8) as usize;
        if used > bits {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Huffman code",
            ));
        }

        buf.push(entry as u8);
        table = 0;
        bits -= used;
    }

    if table == 0 {
        Ok(buf)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid Huffman code",
        ))
    }
}

fn read_qpack_int<R: Read>(reader: &mut R, first_byte: u8, prefix_bits: u8) -> io::Result<usize> {
    let mask = (1 << prefix_bits) - 1;
    let mut val = (first_byte & mask) as usize;
    if val == mask as usize {
        let mut m = 0;
        loop {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b)?;
            val += ((b[0] & 0x7f) as usize) << m;
            m += 7;
            if (b[0] & 0x80) == 0 {
                break;
            }
        }
    }
    Ok(val)
}

fn read_qpack_string<R: Read>(
    reader: &mut R,
    first_byte: u8,
    prefix_bits: u8,
) -> io::Result<String> {
    let is_huffman = (first_byte & (1 << prefix_bits)) != 0;
    let len = read_qpack_int(reader, first_byte, prefix_bits)?;

    let mut raw = vec![0u8; len];
    reader.read_exact(&mut raw)?;

    let bytes = if is_huffman {
        decode_huffman(&raw)?
    } else {
        raw
    };

    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub const QPACK_STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-"),
    ("content-type", "application/"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html;"),
    ("content-type", "text/plain"),
    ("content-type", "text/"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000;"),
    ("strict-transport-security", "max-age=31536000;"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none';"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

pub const H3_FRAME_DATA: u64 = 0x00;
pub const H3_FRAME_HEADERS: u64 = 0x01;
pub const H3_FRAME_SETTINGS: u64 = 0x04;

pub const HYSTERIA_AUTH_HEADER: &str = "hysteria-auth";
pub const HYSTERIA_CC_RX_HEADER: &str = "hysteria-cc-rx";
pub const HYSTERIA_PADDING_HEADER: &str = "hysteria-padding";
pub const HYSTERIA_UDP_HEADER: &str = "hysteria-udp";

pub const H3_STREAM_CONTROL: u64 = 0x00;
pub const H3_STREAM_PUSH: u64 = 0x01;
pub const H3_STREAM_QPACK_ENCODER: u64 = 0x02;
pub const H3_STREAM_QPACK_DECODER: u64 = 0x03;

pub fn encode_h3_control_stream() -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = write_quic_varint(&mut buf, H3_STREAM_CONTROL);
    let _ = write_quic_varint(&mut buf, H3_FRAME_SETTINGS);
    let _ = write_quic_varint(&mut buf, 0);
    buf
}

#[derive(Debug, Clone, Default)]
pub struct Http3Request {
    pub method: String,
    pub path: String,
    pub authority: String,
    pub headers: Vec<(String, String)>,
}

impl Http3Request {
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let target = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == target)
            .map(|(_, v)| v.as_str())
    }

    pub fn host(&self) -> &str {
        if !self.authority.is_empty() {
            &self.authority
        } else if let Some(h) = self.get_header("host") {
            h
        } else {
            ""
        }
    }
}

pub fn parse_qpack_headers(payload: &[u8]) -> io::Result<Http3Request> {
    let mut cursor = Cursor::new(payload);
    if payload.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "QPACK payload too short",
        ));
    }

    let mut first = [0u8; 1];
    cursor.read_exact(&mut first)?;
    let mut _ric = (first[0] & 0xff) as usize;
    if _ric == 0xff {
        let mut m = 0;
        loop {
            let mut b = [0u8; 1];
            cursor.read_exact(&mut b)?;
            _ric += ((b[0] & 0x7f) as usize) << m;
            m += 7;
            if (b[0] & 0x80) == 0 {
                break;
            }
        }
    }

    let mut s_db = [0u8; 1];
    cursor.read_exact(&mut s_db)?;
    let mut _db = (s_db[0] & 0x7f) as usize;
    if _db == 0x7f {
        let mut m = 0;
        loop {
            let mut b = [0u8; 1];
            cursor.read_exact(&mut b)?;
            _db += ((b[0] & 0x7f) as usize) << m;
            m += 7;
            if (b[0] & 0x80) == 0 {
                break;
            }
        }
    }

    let mut req = Http3Request::default();

    while (cursor.position() as usize) < payload.len() {
        let mut b = [0u8; 1];
        if cursor.read_exact(&mut b).is_err() {
            break;
        }
        let byte = b[0];

        if (byte & 0x80) != 0 {
            let is_static = (byte & 0x40) != 0;
            let idx = read_qpack_int(&mut cursor, byte, 6)?;
            if is_static && idx < QPACK_STATIC_TABLE.len() {
                let (name, val) = QPACK_STATIC_TABLE[idx];
                if name == ":method" {
                    req.method = val.to_string();
                } else if name == ":path" {
                    req.path = val.to_string();
                } else if name == ":authority" || name == ":host" || name == "host" {
                    req.authority = val.to_string();
                } else {
                    req.headers.push((name.to_string(), val.to_string()));
                }
            }
        } else if (byte & 0x40) != 0 {
            let is_static = (byte & 0x10) != 0;
            let name_idx = read_qpack_int(&mut cursor, byte, 4)?;
            let name = if is_static && name_idx < QPACK_STATIC_TABLE.len() {
                QPACK_STATIC_TABLE[name_idx].0.to_string()
            } else {
                "unknown".to_string()
            };

            let mut len_b = [0u8; 1];
            cursor.read_exact(&mut len_b)?;
            let value = read_qpack_string(&mut cursor, len_b[0], 7)?;

            if name == ":method" {
                req.method = value;
            } else if name == ":path" {
                req.path = value;
            } else if name == ":authority" || name == ":host" || name == "host" {
                req.authority = value;
            } else {
                req.headers.push((name, value));
            }
        } else if (byte & 0x20) != 0 {
            let name = read_qpack_string(&mut cursor, byte, 3)?;
            let mut val_b = [0u8; 1];
            cursor.read_exact(&mut val_b)?;
            let value = read_qpack_string(&mut cursor, val_b[0], 7)?;

            if name == ":method" {
                req.method = value;
            } else if name == ":path" {
                req.path = value;
            } else if name == ":authority" || name == ":host" || name == "host" {
                req.authority = value;
            } else {
                req.headers.push((name, value));
            }
        } else {
            break;
        }
    }

    Ok(req)
}

pub fn encode_h3_response(status: u16, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut qpack_payload = Vec::new();

    qpack_payload.push(0x00);
    qpack_payload.push(0x00);

    write_qpack_literal(&mut qpack_payload, ":status", &status.to_string());

    for &(name, value) in headers {
        write_qpack_literal(&mut qpack_payload, name, value);
    }

    let mut frame = Vec::new();
    let _ = write_quic_varint(&mut frame, H3_FRAME_HEADERS);
    let _ = write_quic_varint(&mut frame, qpack_payload.len() as u64);
    frame.extend_from_slice(&qpack_payload);
    frame
}

fn write_qpack_int(out: &mut Vec<u8>, prefix: u8, prefix_bits: u8, mut val: usize) {
    let max_prefix = (1 << prefix_bits) - 1;
    if val < max_prefix {
        out.push(prefix | (val as u8));
    } else {
        out.push(prefix | (max_prefix as u8));
        val -= max_prefix;
        while val >= 128 {
            out.push(((val & 0x7f) as u8) | 0x80);
            val >>= 7;
        }
        out.push(val as u8);
    }
}

fn write_qpack_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    let name_bytes = name.as_bytes();

    write_qpack_int(out, 0x20, 3, name_bytes.len());
    out.extend_from_slice(name_bytes);

    let val_bytes = value.as_bytes();

    write_qpack_int(out, 0x00, 7, val_bytes.len());
    out.extend_from_slice(val_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_varint_roundtrip() {
        let test_vals = [
            0,
            1,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            4611686018427387903,
        ];
        for &val in &test_vals {
            let mut buf = Vec::new();
            let written = write_quic_varint(&mut buf, val).unwrap();
            assert_eq!(written, quic_varint_len(val));
            let mut cursor = Cursor::new(&buf);
            let read = read_quic_varint(&mut cursor).unwrap();
            assert_eq!(val, read);
        }
    }

    #[test]
    fn test_huffman_decode_golden() {
        let decoded = decode_huffman(&[0b00111111]).unwrap();
        assert_eq!(decoded, b"o");
    }

    #[test]
    fn test_qpack_encode_decode_roundtrip() {
        let headers = [
            ("hysteria-auth", "secret12345"),
            ("hysteria-cc-rx", "100000000"),
            ("hysteria-padding", "random_padding_test"),
        ];
        let frame = encode_h3_response(233, &headers);
        assert!(!frame.is_empty());

        let mut cursor = Cursor::new(&frame);
        let frame_type = read_quic_varint(&mut cursor).unwrap();
        assert_eq!(frame_type, H3_FRAME_HEADERS);
        let frame_len = read_quic_varint(&mut cursor).unwrap() as usize;
        let mut payload = vec![0u8; frame_len];
        cursor.read_exact(&mut payload).unwrap();

        let req = parse_qpack_headers(&payload).unwrap();
        assert_eq!(req.get_header("hysteria-auth"), Some("secret12345"));
        assert_eq!(req.get_header("hysteria-cc-rx"), Some("100000000"));
        assert_eq!(
            req.get_header("hysteria-padding"),
            Some("random_padding_test")
        );
    }
}
