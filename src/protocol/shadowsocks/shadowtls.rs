use crate::conn::{BoxedStream, PrefixedStream};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tokio_util::io::{SinkWriter, StreamReader};

type Hash = Hmac<Sha1>;

pub struct ShadowTls {
    pub host: String,
    pub port: u16,
    password: String,
    strict: bool,
}

use super::transport::Accepted;

impl ShadowTls {
    pub fn new(opts: &HashMap<String, String>) -> io::Result<Self> {
        let version_ok = matches!(opts.get("v3").map(String::as_str), Some("true" | "1" | ""))
            || matches!(opts.get("version").map(String::as_str), Some("3" | "v3"))
            || (!opts.contains_key("v3") && !opts.contains_key("version") && !opts.is_empty());
        if !version_ok {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ShadowTLS requires explicit v3",
            ));
        }
        let password = opts
            .get("passwd")
            .or(opts.get("password"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("ShadowTLS passwd is required"))?
            .clone();
        let address = opts
            .get("tls")
            .or(opts.get("host"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("ShadowTLS tls handshake address is required"))?;
        let (host, port) = match address.rsplit_once(':') {
            Some((host, port)) => (
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
                port.parse::<u16>()
                    .map_err(|_| invalid("Invalid ShadowTLS handshake port"))?,
            ),
            None => (address.clone(), 443),
        };
        if host.is_empty() || port == 0 || host.contains(';') {
            return Err(invalid("Invalid ShadowTLS handshake address"));
        }
        let strict = match opts.get("strict").map(String::as_str) {
            None | Some("false" | "0") => false,
            Some("true" | "1" | "") => true,
            _ => return Err(invalid("Invalid ShadowTLS strict flag")),
        };
        Ok(Self {
            host,
            port,
            password,
            strict,
        })
    }

    pub async fn accept(
        &self,
        mut client: BoxedStream,
        mut decoy: BoxedStream,
    ) -> io::Result<Accepted> {
        let hello = read_record(&mut client).await?;
        let authenticated = verify_hello(&hello, &self.password);
        decoy.write_all(&hello).await?;
        if !authenticated {
            return Ok(Accepted::Fallback(client, decoy));
        }
        let hello = read_record(&mut decoy).await?;
        client.write_all(&hello).await?;
        if hello.len() < 44 || hello[0] != 22 || hello[5] != 2 || (self.strict && !tls13(&hello)) {
            return Ok(Accepted::Fallback(client, decoy));
        }
        let random = &hello[11..43];
        let mut verify = Hash::new_from_slice(self.password.as_bytes()).unwrap();
        verify.update(random);
        verify.update(b"C");
        let mut send = Hash::new_from_slice(self.password.as_bytes()).unwrap();
        send.update(random);
        send.update(b"S");
        let mut handshake_hash = Hash::new_from_slice(self.password.as_bytes()).unwrap();
        handshake_hash.update(random);
        let mut key = Sha256::new();
        key.update(self.password.as_bytes());
        key.update(random);
        let key = key.finalize();
        let (client_read, mut client_write) = tokio::io::split(client);
        let (decoy_read, mut decoy_write) = tokio::io::split(decoy);
        let mut client_read = FramedRead::new(client_read, Records);
        let mut decoy_read = FramedRead::new(decoy_read, Records);
        let first = loop {
            tokio::select! {
                frame = client_read.next() => {
                    let frame = frame.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))??;
                    if frame[0] == 23 && frame.len() > 9 && frame[1..3] == [3, 3] {
                        let mut candidate = verify.clone();
                        candidate.update(&frame[9..]);
                        if candidate.clone().verify_truncated_left(&frame[5..9]).is_ok() {
                            candidate.update(&frame[5..9]);
                            verify = candidate;
                            break frame.slice(9..);
                        }
                    }
                    decoy_write.write_all(&frame).await?;
                }
                frame = decoy_read.next() => {
                    let mut frame = frame.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))??.to_vec();
                    if frame[0] == 23 {
                        for (i, byte) in frame[5..].iter_mut().enumerate() { *byte ^= key[i % key.len()]; }
                        handshake_hash.update(&frame[5..]);
                        let tag = handshake_hash.clone().finalize().into_bytes();
                        let length = (frame.len() - 5 + 4) as u16;
                        frame[3..5].copy_from_slice(&length.to_be_bytes());
                        client_write.write_all(&frame[..5]).await?;
                        client_write.write_all(&tag[..4]).await?;
                        client_write.write_all(&frame[5..]).await?;
                    } else { client_write.write_all(&frame).await?; }
                }
            }
        };
        // Preserve bytes read beyond the first authenticated record during the handshake switch.
        let parts = client_read.into_parts();
        let reader = PrefixedStream::new(parts.io, Some(parts.read_buf.to_vec()));
        let reader = StreamReader::new(FramedRead::new(reader, Verified(verify)));
        let writer = SinkWriter::new(FramedWrite::new(client_write, Verified(send)));
        Ok(Accepted::Stream(Box::new(PrefixedStream::new(
            tokio::io::join(reader, writer),
            Some(first.to_vec()),
        ))))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn verify_hello(frame: &[u8], password: &str) -> bool {
    if frame.len() < 76 || frame[0] != 22 || frame[5] != 1 || frame[43] != 32 {
        return false;
    }
    let declared = ((frame[6] as usize) << 16) | ((frame[7] as usize) << 8) | frame[8] as usize;
    if declared != frame.len() - 9 {
        return false;
    }
    let mut hash = Hash::new_from_slice(password.as_bytes()).unwrap();
    hash.update(&frame[5..72]);
    hash.update(&[0; 4]);
    hash.update(&frame[76..]);
    hash.verify_truncated_left(&frame[72..76]).is_ok()
}

fn tls13(frame: &[u8]) -> bool {
    if frame.len() < 44 {
        return false;
    }
    let start = 44 + frame[43] as usize + 3;
    if frame.len() < start + 2 {
        return false;
    }
    let size = u16::from_be_bytes([frame[start], frame[start + 1]]) as usize;
    if start + 2 + size != frame.len() {
        return false;
    }
    let mut extensions = &frame[start + 2..];
    let mut supported = false;
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return false;
        }
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        let size = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        if extensions.len() < 4 + size {
            return false;
        }
        if kind == 43 {
            if supported || extensions[4..4 + size] != [3, 4] {
                return false;
            }
            supported = true;
        }
        extensions = &extensions[4 + size..];
    }
    supported
}

async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut frame = vec![0; 5];
    stream.read_exact(&mut frame).await?;
    let length = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    if frame[1] != 3 || !matches!(frame[2], 1 | 3) || length > 18436 {
        return Err(invalid("Invalid TLS record"));
    }
    frame.resize(5 + length, 0);
    stream.read_exact(&mut frame[5..]).await?;
    Ok(frame)
}

struct Records;
impl Decoder for Records {
    type Item = Bytes;
    type Error = io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if src.len() < 5 {
            return Ok(None);
        }
        let size = u16::from_be_bytes([src[3], src[4]]) as usize;
        if src[1] != 3 || !matches!(src[2], 1 | 3) || size > 18436 {
            return Err(invalid("Invalid TLS record"));
        }
        if src.len() < 5 + size {
            return Ok(None);
        }
        Ok(Some(src.split_to(5 + size).freeze()))
    }
}

struct Verified(Hash);
impl Decoder for Verified {
    type Item = Bytes;
    type Error = io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        let Some(frame) = Records.decode(src)? else {
            return Ok(None);
        };
        if frame[0] == 21 {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        if frame[0] != 23 || frame[1..3] != [3, 3] || frame.len() < 9 {
            return Err(invalid("Invalid ShadowTLS data record"));
        }
        let mut hash = self.0.clone();
        hash.update(&frame[9..]);
        hash.clone()
            .verify_truncated_left(&frame[5..9])
            .map_err(|_| invalid("ShadowTLS record authentication failed"))?;
        hash.update(&frame[5..9]);
        self.0 = hash;
        Ok(Some(frame.slice(9..)))
    }
}

impl Encoder<&[u8]> for Verified {
    type Error = io::Error;
    fn encode(&mut self, data: &[u8], dst: &mut BytesMut) -> io::Result<()> {
        for part in data.chunks(16384) {
            self.0.update(part);
            let tag = self.0.clone().finalize().into_bytes();
            self.0.update(&tag[..4]);
            dst.extend_from_slice(&[23, 3, 3]);
            dst.put_u16((part.len() + 4) as u16);
            dst.extend_from_slice(&tag[..4]);
            dst.extend_from_slice(part);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_chain_matches_independent_python_vectors() {
        // Python stdlib hmac/sha1: key="fixture", seed=bytes(range(32))+b"C".
        let vectors = ["1703030007ab871db6616263", "170303000710541e1d646566"];
        let mut hash = Hash::new_from_slice(b"fixture").unwrap();
        hash.update(&(0u8..32).collect::<Vec<_>>());
        hash.update(b"C");
        let mut reader = Verified(hash.clone());
        let mut writer = Verified(hash);
        for (wire, plain) in vectors.iter().zip([&b"abc"[..], &b"def"[..]]) {
            let wire = hex::decode(wire).unwrap();
            let mut corrupted = wire.clone();
            corrupted[5] ^= 1;
            assert!(reader.decode(&mut BytesMut::from(&corrupted[..])).is_err());
            assert_eq!(
                reader
                    .decode(&mut BytesMut::from(&wire[..]))
                    .unwrap()
                    .unwrap(),
                plain
            );
            assert!(reader.decode(&mut BytesMut::from(&wire[..])).is_err());
            let mut encoded = BytesMut::new();
            writer.encode(plain, &mut encoded).unwrap();
            assert_eq!(&encoded[..], &wire);
        }
    }

    #[test]
    fn record_boundaries_and_client_hello_validation() {
        let wire = hex::decode("1703030007ab871db6616263").unwrap();
        for end in 1..wire.len() {
            let mut buffer = BytesMut::from(&wire[..end]);
            assert!(Records.decode(&mut buffer).unwrap().is_none());
            assert!(Records.decode_eof(&mut buffer).is_err());
        }
        let mut hello = vec![0; 76];
        hello[..9].copy_from_slice(&[22, 3, 1, 0, 71, 1, 0, 0, 67]);
        hello[43] = 32;
        let mut hash = Hash::new_from_slice(b"fixture").unwrap();
        hash.update(&hello[5..]);
        hello[72..76].copy_from_slice(&hash.finalize().into_bytes()[..4]);
        assert!(verify_hello(&hello, "fixture"));
        assert!(!verify_hello(&hello, "wrong"));
        for end in 0..hello.len() {
            assert!(!verify_hello(&hello[..end], "fixture"));
        }
        hello[43] = 31;
        assert!(!verify_hello(&hello, "fixture"));
        assert!(!tls13(&hello));
    }
}
