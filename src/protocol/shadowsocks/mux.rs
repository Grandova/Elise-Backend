use crate::conn::BoxedStream;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::codec::{Decoder, FramedRead};
use tokio_util::sync::CancellationToken;

struct Frame {
    id: u32,
    status: u8,
    options: u8,
    payload: Bytes,
}

#[derive(Clone, Copy)]
pub enum Mux {
    Vmess,
    Smux,
}

struct Codec(Mux);

impl Decoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Frame>> {
        if matches!(self.0, Mux::Smux) {
            if src.len() < 8 {
                return Ok(None);
            }
            if src[0] != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "GOST requires smux v1",
                ));
            }
            let length = u16::from_le_bytes([src[2], src[3]]) as usize;
            let id = u32::from_le_bytes(src[4..8].try_into().unwrap());
            let status = match src[1] {
                0 => 1,
                1 => 3,
                2 => 2,
                3 => 4,
                _ => return Err(invalid("Invalid smux command")),
            };
            if status != 2 && length != 0 {
                return Err(invalid("smux control frame has payload"));
            }
            if src.len() < 8 + length {
                return Ok(None);
            }
            src.advance(8);
            return Ok(Some(Frame {
                id,
                status,
                options: if status == 2 { 1 } else { 0 },
                payload: src.split_to(length).freeze(),
            }));
        }
        if src.len() < 2 {
            return Ok(None);
        }
        let length = u16::from_be_bytes([src[0], src[1]]) as usize;
        if !(4..=512).contains(&length) {
            return Err(invalid("Invalid mux header length"));
        }
        if src.len() < length + 2 {
            return Ok(None);
        }
        let id = u16::from_be_bytes([src[2], src[3]]) as u32;
        let status = src[4];
        let options = src[5];
        if !(1..=4).contains(&status) || options & !3 != 0 {
            return Err(invalid("Invalid mux status/options"));
        }
        if status == 1 && length == 4 {
            return Err(invalid("Mux New lacks destination"));
        }
        if length > 4 {
            let header = &src[6..length + 2];
            if header.len() < 4 {
                return Err(invalid("Truncated mux destination"));
            }
            if header[0] != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SS plugin mux requires TCP streams",
                ));
            }
            let address_len = match header[3] {
                1 => 8,
                3 => 20,
                2 if header.len() >= 5 && header[4] != 0 => 5 + header[4] as usize,
                _ => return Err(invalid("Invalid mux address")),
            };
            if header.len() < address_len {
                return Err(invalid("Truncated mux address"));
            }
            // The plugin's destination is overridden by its local SS endpoint upstream.
        }
        let mut offset = length + 2;
        let data_len = if options & 1 != 0 {
            if src.len() < offset + 2 {
                return Ok(None);
            }
            let n = u16::from_be_bytes([src[offset], src[offset + 1]]) as usize;
            offset += 2;
            n
        } else {
            0
        };
        if src.len() < offset + data_len {
            return Ok(None);
        }
        src.advance(offset);
        let payload = src.split_to(data_len).freeze();
        Ok(Some(Frame {
            id,
            status,
            options,
            payload,
        }))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Session {
    input: Option<mpsc::Sender<Bytes>>,
    cancel: CancellationToken,
}

pub async fn serve<F, Fut>(
    stream: BoxedStream,
    mux: Mux,
    cancel: CancellationToken,
    handle: F,
) -> io::Result<()>
where
    F: Fn(BoxedStream) -> Fut,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut frames = FramedRead::new(reader, Codec(mux));
    let (output, mut outgoing) = mpsc::channel::<Frame>(64);
    let write = async {
        while let Some(frame) = outgoing.recv().await {
            let mut header = if matches!(mux, Mux::Smux) {
                let command = match frame.status {
                    1 => 0,
                    2 => 2,
                    3 => 1,
                    _ => 3,
                };
                let mut header = vec![1, command];
                header.extend_from_slice(&(frame.payload.len() as u16).to_le_bytes());
                header.extend_from_slice(&frame.id.to_le_bytes());
                header
            } else {
                vec![
                    0,
                    4,
                    (frame.id >> 8) as u8,
                    frame.id as u8,
                    frame.status,
                    frame.options,
                ]
            };
            if matches!(mux, Mux::Vmess) && frame.options & 1 != 0 {
                header.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
            }
            writer.write_all(&header).await?;
            writer.write_all(&frame.payload).await?;
            writer.flush().await?;
        }
        Ok::<_, io::Error>(())
    };
    tokio::pin!(write);
    let mut sessions: HashMap<u32, Session> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    let idle = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(idle);
    let receive = async {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = &mut idle => return Err(io::Error::new(io::ErrorKind::TimedOut, "Mux connection idle")),
                _ = keepalive.tick() => {
                    output.send(Frame { id: 0, status: 4, options: 0, payload: Bytes::new() }).await.map_err(io::Error::other)?;
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    let id = result.unwrap().map_err(io::Error::other)?;
                    sessions.remove(&id);
                }
                frame = frames.next() => {
                    let Some(frame) = frame else { return Ok(()); };
                    let frame = frame?;
                    idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60));
                    let id = frame.id;
                    if frame.status == 1 {
                        if sessions.len() >= 64 || sessions.contains_key(&id) {
                            return Err(invalid("Mux stream limit or duplicate stream ID"));
                        }
                        let (input, mut incoming) = mpsc::channel::<Bytes>(16);
                        let child = cancel.child_token();
                        sessions.insert(id, Session { input: Some(input), cancel: child.clone() });
                        let (plain, bridge) = tokio::io::duplex(65536);
                        let handler = handle(Box::new(plain));
                        let output = output.clone();
                        tasks.spawn(async move {
                            let (mut read, mut write) = tokio::io::split(bridge);
                            let done = CancellationToken::new();
                            let incoming = async {
                                loop {
                                    tokio::select! {
                                        _ = done.cancelled() => break,
                                        packet = incoming.recv() => {
                                            let Some(packet) = packet else { break; };
                                            write.write_all(&packet).await?;
                                        }
                                    }
                                }
                                write.shutdown().await
                            };
                            let outgoing = async {
                                let mut buffer = [0; 16384];
                                loop {
                                    let n = read.read(&mut buffer).await?;
                                    if n == 0 { break; }
                                    output.send(Frame { id, status: 2, options: 1, payload: Bytes::copy_from_slice(&buffer[..n]) }).await.map_err(io::Error::other)?;
                                }
                                Ok::<_, io::Error>(())
                            };
                            let handler = async { let result = handler.await; done.cancel(); result };
                            let result = tokio::select! {
                                _ = child.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "Mux stream cancelled")),
                                result = async {
                                    let (a, b, c) = tokio::join!(handler, incoming, outgoing);
                                    a.and(b).and(c)
                                } => result,
                            };
                            let end = Frame { id, status: 3, options: if result.is_err() { 2 } else { 0 }, payload: Bytes::new() };
                            tokio::select! { _ = child.cancelled() => {}, _ = output.send(end) => {} }
                            id
                        });
                    }
                    match frame.status {
                        1 | 2 => {
                            if let Some(session) = sessions.get(&id) {
                                if let Some(input) = &session.input {
                                    if !frame.payload.is_empty() {
                                        // A slow stream cannot hold every stream's buffers without a bound.
                                        tokio::select! {
                                            _ = cancel.cancelled() => return Ok(()),
                                            result = tokio::time::timeout(Duration::from_secs(60), input.send(frame.payload)) => {
                                                if result.is_err() { return Err(io::Error::new(io::ErrorKind::TimedOut, "Mux stream stalled")); }
                                            }
                                        }
                                    }
                                }
                            } else {
                                output.send(Frame { id, status: 3, options: 2, payload: Bytes::new() }).await.map_err(io::Error::other)?;
                            }
                        }
                        3 => if let Some(session) = sessions.get_mut(&id) {
                            session.input.take();
                            if frame.options & 2 != 0 { session.cancel.cancel(); }
                        },
                        _ => {}
                    }
                }
            }
        }
    };
    let result = tokio::select! {
        result = receive => result,
        result = &mut write => result,
    };
    for session in sessions.values() {
        session.cancel.cancel();
    }
    while tasks.join_next().await.is_some() {}
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smux_v1_boundaries_and_version() {
        let frame = [1, 2, 3, 0, 0x78, 0x56, 0x34, 0x12, 9, 8, 7];
        for end in 1..frame.len() {
            let mut bytes = BytesMut::from(&frame[..end]);
            assert!(Codec(Mux::Smux).decode(&mut bytes).unwrap().is_none());
            assert!(Codec(Mux::Smux).decode_eof(&mut bytes).is_err());
        }
        let decoded = Codec(Mux::Smux)
            .decode(&mut BytesMut::from(&frame[..]))
            .unwrap()
            .unwrap();
        assert_eq!(decoded.id, 0x12345678);
        assert_eq!(&decoded.payload[..], &[9, 8, 7]);
        let mut bad = frame;
        bad[0] = 2;
        assert_eq!(
            Codec(Mux::Smux)
                .decode(&mut BytesMut::from(&bad[..]))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Unsupported
        );
        bad = frame;
        bad[1] = 0;
        assert!(Codec(Mux::Smux)
            .decode(&mut BytesMut::from(&bad[..]))
            .is_err());
    }

    #[test]
    fn malformed_frames_and_truncations() {
        // Port-first VMess address, as serialized by sing-vmess v0.2.8.
        let frame = [0, 12, 0, 7, 1, 1, 1, 0, 80, 1, 127, 0, 0, 1, 0, 3, 9, 8, 7];
        for end in 1..frame.len() {
            let mut bytes = BytesMut::from(&frame[..end]);
            assert!(Codec(Mux::Vmess).decode(&mut bytes).unwrap().is_none());
            assert!(Codec(Mux::Vmess).decode_eof(&mut bytes).is_err());
        }
        let mut bytes = BytesMut::from(&frame[..]);
        let decoded = Codec(Mux::Vmess).decode(&mut bytes).unwrap().unwrap();
        assert_eq!(decoded.id, 7);
        assert_eq!(&decoded.payload[..], &[9, 8, 7]);
        assert!(bytes.is_empty());
        for (offset, value) in [(1, 3), (4, 0), (5, 4), (6, 2), (9, 9)] {
            let mut bad = frame;
            bad[offset] = value;
            assert!(Codec(Mux::Vmess)
                .decode(&mut BytesMut::from(&bad[..]))
                .is_err());
        }
    }

    #[tokio::test]
    async fn two_streams_drain_after_peer_end_and_cancel() {
        let (mut client, server) = tokio::io::duplex(4096);
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let task = tokio::spawn(serve(
            Box::new(server),
            Mux::Vmess,
            token,
            |mut stream| async move {
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await?;
                stream.write_all(&request).await?;
                stream.shutdown().await
            },
        ));
        for id in [1, 2] {
            client
                .write_all(&[0, 12, 0, id, 1, 1, 1, 0, 80, 1, 127, 0, 0, 1, 0, 1, id])
                .await
                .unwrap();
            client.write_all(&[0, 4, 0, id, 3, 0]).await.unwrap();
        }
        let mut frames = FramedRead::new(client, Codec(Mux::Vmess));
        let mut replies = HashMap::new();
        let mut ends = 0;
        tokio::time::timeout(Duration::from_secs(2), async {
            while ends < 2 {
                let frame = frames.next().await.unwrap().unwrap();
                if frame.status == 3 {
                    ends += 1;
                    assert_eq!(frame.options, 0);
                } else {
                    replies.insert(frame.id, frame.payload);
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(&replies[&1][..], &[1]);
        assert_eq!(&replies[&2][..], &[2]);
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
