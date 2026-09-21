use anyhow::{anyhow, Result};
use bytes::Buf;

use rand::Rng;
use std::{cmp::min, io::Cursor};

use tokio_util::codec::{Decoder, Framed};

use super::common::{BUF_SIZE, RECORD_HANDSHAKE};

pub type TLSStream = Framed<crate::conn::BoxedStream, TLSCodec>;

#[derive(Debug)]
enum RecordChecker {
    Outbound,
    NewInbound,
    InboundAfterClientHello,
}

impl RecordChecker {
    fn check(&mut self, record: &[u8]) -> bool {
        use RecordChecker::*;
        match self {
            Outbound => true,
            NewInbound => {
                if record[..3] == [0x16, 0x03, 0x01] {
                    *self = InboundAfterClientHello;
                    true
                } else {
                    false
                }
            }
            InboundAfterClientHello => {
                record[0] >= 0x14 && record[0] <= 0x18 && record[1..3] == [0x03, 0x03]
            }
        }
    }
}

pub struct TLSCodec {
    checker: RecordChecker,
    buf: Vec<u8>,
    cursor: usize,
    pub enable_codec: bool,
}

impl TLSCodec {
    pub fn new_outbound() -> Self {
        Self {
            checker: RecordChecker::NewInbound,
            buf: Vec::with_capacity(0x2000),
            enable_codec: true,
            cursor: 0,
        }
    }

    pub fn new_inbound() -> Self {
        Self {
            checker: RecordChecker::Outbound,
            buf: Vec::with_capacity(0x2000),
            enable_codec: true,
            cursor: 0,
        }
    }

    pub fn reset(&mut self) {
        assert!(self.cursor == self.buf.len());
        self.buf.clear();
        self.cursor = 0;
    }

    fn peek_record_length(&self) -> usize {
        5 + ((self.buf[self.cursor + 3] as usize) << 8 | self.buf[self.cursor + 4] as usize)
    }

    fn check_codec_failure(&self) -> Result<()> {
        if !self.enable_codec || self.buf.len().saturating_sub(self.cursor) < 5 {
            Err(anyhow!("invalid or unavailable TLS record"))
        } else {
            Ok(())
        }
    }

    pub fn next_record(&mut self) -> Result<&mut [u8]> {
        self.check_codec_failure()?;
        let start = self.cursor;
        self.cursor += self.peek_record_length();
        Ok(&mut self.buf[start..self.cursor])
    }

    pub fn peek_record(&self) -> Result<&[u8]> {
        self.check_codec_failure()?;
        let len = self.peek_record_length();
        Ok(&self.buf[self.cursor..self.cursor + len])
    }

    pub fn peek_record_mut(&mut self) -> Result<&mut [u8]> {
        self.check_codec_failure()?;
        let len = self.peek_record_length();
        Ok(&mut self.buf[self.cursor..self.cursor + len])
    }

    pub fn peek_record_type(&self) -> Result<u8> {
        self.check_codec_failure()?;
        Ok(self.buf[self.cursor])
    }

    pub fn has_next(&self) -> bool {
        self.cursor < self.buf.len()
    }

    pub fn skip_to_end(&mut self) {
        self.cursor = self.buf.len();
    }

    pub fn raw_buf(&self) -> &[u8] {
        assert!(self.cursor == self.buf.len());
        &self.buf
    }
}

impl Decoder for TLSCodec {
    type Item = ();

    type Error = anyhow::Error;

    fn decode(
        &mut self,
        src: &mut bytes::BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        self.reset();

        if !self.enable_codec {
            if src.is_empty() {
                return Ok(None);
            }
            self.buf.extend_from_slice(src);
            src.advance(src.len());
            return Ok(Some(()));
        }

        let mut cursor = 0;
        while cursor + 5 <= src.len() {
            let record_len = ((src[cursor + 3] as usize) << 8) | src[cursor + 4] as usize;
            if record_len > 18432 {
                return Err(anyhow!("TLS record exceeds limit"));
            }
            if src.len() < cursor + 5 + record_len {
                break;
            }
            if !self.checker.check(&src[cursor..]) {
                self.enable_codec = false;
                return self.decode(src);
            }
            cursor += 5 + record_len;
        }
        if cursor == 0 {
            return Ok(None);
        }
        self.buf.extend_from_slice(&src[..cursor]);
        src.advance(cursor);
        Ok(Some(()))
    }
}

pub(crate) fn read_length_padded_header<const N: usize, T: Buf>(buf: &mut T) -> Result<usize> {
    let mut len = 0;
    let mut tmp = [0; 8];
    if buf.remaining() < N {
        return Err(anyhow!(
            "read_length_padded_header failed: expect {}, actual {}",
            N,
            buf.remaining()
        ));
    }
    buf.copy_to_slice(&mut tmp[..N]);
    for byte in tmp.iter().take(N) {
        len = (len << 8) | (*byte as usize);
    }
    Ok(len)
}

pub(crate) fn skip_length_padded<const N: usize, T: Buf>(buf: &mut T) -> Result<usize> {
    let len = read_length_padded_header::<N, T>(buf)?;
    buf.checked_advance(len, "skip_length_padded failed")?;
    Ok(len)
}

pub(crate) fn read_length_padded<const N: usize, T: Buf>(
    buf: &mut T,
    copy_to: &mut [u8],
) -> Result<usize> {
    let len = read_length_padded_header::<N, T>(buf)?;
    if copy_to.len() < len || buf.remaining() < len {
        return Err(anyhow!("truncated length padded content"));
    }
    buf.copy_to_slice(&mut copy_to[..len]);
    Ok(len)
}

pub(crate) fn extend_from_length_prefixed<const N: usize, T: Buf>(
    buf: &mut T,
    copy_to: &mut Vec<u8>,
) -> Result<()> {
    let len = read_length_padded_header::<N, T>(buf)?;
    if len > buf.remaining() {
        return Err(anyhow!(
            "extend_from_length_prefixed failed: expect {}, actual {}",
            len,
            buf.remaining()
        ));
    }
    copy_to.extend_from_slice(&buf.chunk()[..len]);
    buf.advance(len);
    Ok(())
}

pub(crate) fn length_prefixed<const N: usize, T: Buf, P: FnOnce(Cursor<&[u8]>) -> Result<()>>(
    buf: &mut T,
    parse: P,
) -> Result<()> {
    let len = read_length_padded_header::<N, _>(buf)?;
    if len > buf.remaining() {
        return Err(anyhow!(
            "read length_prefixed bytes failed: expect {}, actual {}",
            len,
            buf.remaining()
        ));
    }
    parse(Cursor::new(&buf.chunk()[..len]))?;
    buf.advance(len);
    Ok(())
}

pub(crate) fn u8_length_prefixed<T: Buf, P: FnOnce(Cursor<&[u8]>) -> Result<()>>(
    buf: &mut T,
    parse: P,
) -> Result<()> {
    length_prefixed::<1, _, _>(buf, parse)
}

pub(crate) fn u16_length_prefixed<T: Buf, P: FnOnce(Cursor<&[u8]>) -> Result<()>>(
    buf: &mut T,
    parse: P,
) -> Result<()> {
    length_prefixed::<2, _, _>(buf, parse)
}

pub(crate) fn xor_bytes(secret: &[u8], msg: &mut [u8]) {
    for i in 0..min(secret.len(), msg.len()) {
        msg[i] ^= secret[i];
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RestlsCommand {
    Noop,
    Response(u8),
}

impl RestlsCommand {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        match buf {
            [0, 0] => Ok(Self::Noop),
            [1, count] => Ok(Self::Response(*count)),
            _ => Err(anyhow!("Unsupported Restls command")),
        }
    }

    pub fn to_bytes(self) -> [u8; 2] {
        match self {
            Self::Noop => [0, 0],
            Self::Response(count) => [1, count],
        }
    }
}

#[derive(Debug, Clone)]
struct TargetLen(u16, u16);

impl TargetLen {
    fn len(&self) -> usize {
        (self.0
            + if self.1 == 0 {
                0
            } else {
                rand::thread_rng().gen_range(0..self.1)
            }) as usize
    }
}

#[derive(Debug, Clone)]
pub struct Line {
    target_len: TargetLen,
    pub command: RestlsCommand,
}

impl Line {
    pub fn len(&self) -> usize {
        self.target_len.len()
    }
    pub fn from_str(raw: &str) -> Result<Self> {
        let (length, response) = raw
            .split_once('<')
            .map_or((raw, None), |(a, b)| (a, Some(b)));
        let command = match response {
            None => RestlsCommand::Noop,
            Some(n) => {
                let n = n.parse::<u8>()?;
                if n == 255 {
                    return Err(anyhow!("Restls response count exceeds limit"));
                }
                RestlsCommand::Response(n)
            }
        };
        let (base, range, fixed) = if let Some((a, b)) = length.split_once('?') {
            (a, b, true)
        } else if let Some((a, b)) = length.split_once('~') {
            (a, b, false)
        } else {
            (length, "0", false)
        };
        let base = base.parse::<u16>()?;
        let range = range.parse::<u16>()?;
        if base == 0 || base as usize + range as usize > BUF_SIZE - 25 {
            return Err(anyhow!("Restls script record length out of bounds"));
        }
        let target_len = if fixed && range > 0 {
            TargetLen(base + rand::thread_rng().gen_range(0..range), 0)
        } else {
            TargetLen(base, range)
        };
        Ok(Self {
            target_len,
            command,
        })
    }
}

pub struct DoubleCursorBuf {
    inner: [u8; BUF_SIZE],
    front_cursor: usize,
    back_cursor: usize,
    load_len: usize,
    conent_offset: usize,
}

impl DoubleCursorBuf {
    pub fn new(conent_offset: usize) -> Self {
        Self {
            inner: [0; BUF_SIZE],
            front_cursor: 0,
            back_cursor: conent_offset,
            load_len: 0,
            conent_offset,
        }
    }

    fn shift_to_head(&mut self) {
        if self.front_cursor == 0 {
            return;
        }
        self.inner
            .copy_within(self.front_cursor..self.back_cursor, 0);
        self.back_cursor -= self.front_cursor;
        self.front_cursor = 0;
    }

    pub fn len(&self) -> usize {
        self.back_cursor - self.front_cursor - self.conent_offset
    }

    pub fn load_mut(&mut self) -> &mut [u8] {
        &mut self.inner[self.front_cursor..self.front_cursor + self.conent_offset + self.load_len]
    }

    pub fn release(&mut self) {
        self.front_cursor += self.load_len;
        self.load_len = 0;
        if self.front_cursor + self.conent_offset == self.back_cursor {
            self.reset()
        }
    }

    pub fn load(&mut self, len: usize) {
        assert!(self.load_len == 0);
        if len > self.len() {
            if self.front_cursor + self.conent_offset + len > self.inner.len() {
                self.shift_to_head();
            }
            let padding_len = len - self.len();
            rand::thread_rng()
                .fill(&mut self.inner[self.back_cursor..self.back_cursor + padding_len]);
            self.back_cursor += padding_len;
            assert!(self.back_cursor <= self.inner.len());
        }
        self.load_len = len;
    }

    pub fn reset(&mut self) {
        self.front_cursor = 0;
        self.back_cursor = self.conent_offset;
    }

    pub fn back_mut(&mut self) -> &mut [u8] {
        if self.inner.len() - self.back_cursor < 1500 {
            self.shift_to_head()
        }
        &mut self.inner[self.back_cursor..]
    }

    pub fn advance_back(&mut self, len: usize) {
        assert!(self.back_cursor + len <= self.inner.len());
        self.back_cursor += len;
    }
}

pub struct HandshakeRecord<'a> {
    hs_msg_cursor: usize,
    record: &'a mut [u8],
}

impl<'a> HandshakeRecord<'a> {
    pub fn new(record: &'a mut [u8]) -> Self {
        assert!(record[0] == RECORD_HANDSHAKE);
        Self {
            hs_msg_cursor: 5,
            record,
        }
    }

    fn peek_handshake_message_len(&self) -> Result<usize> {
        if self.record.len().saturating_sub(self.hs_msg_cursor) < 4 {
            return Err(anyhow!("Truncated handshake header"));
        }
        Ok(4 + ((self.record[self.hs_msg_cursor + 1] as usize) << 16
            | (self.record[self.hs_msg_cursor + 2] as usize) << 8
            | (self.record[self.hs_msg_cursor + 3] as usize)))
    }

    pub fn next_handshake_message(&mut self) -> Result<&mut [u8]> {
        let len = self.peek_handshake_message_len()?;
        let start = self.hs_msg_cursor;
        if len > self.record.len() - start {
            return Err(anyhow!("Truncated handshake message"));
        }
        self.hs_msg_cursor += len;
        Ok(&mut self.record[start..self.hs_msg_cursor])
    }

    pub fn has_next(&self) -> bool {
        self.hs_msg_cursor < self.record.len()
    }
}

pub trait CheckedAdvance {
    fn checked_advance(&mut self, cnt: usize, err_msg: &str) -> Result<()>;
}

impl<T: Buf> CheckedAdvance for T {
    fn checked_advance(&mut self, cnt: usize, err_msg: &str) -> Result<()> {
        if cnt > self.remaining() {
            return Err(anyhow!(
                "{err_msg}, expect {}, actual {}",
                cnt,
                self.remaining()
            ));
        }
        self.advance(cnt);
        Ok(())
    }
}
