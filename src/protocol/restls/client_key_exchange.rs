// Adapted from 3andne/restls d3d7c87; BSD-3-Clause, see LICENSE.
use anyhow::{anyhow, Result};
use blake3::traits::digest::Mac;
use blake3::Hasher;
use bytes::Buf;
use std::io::Cursor;

use super::{
    client_hello::ClientHello,
    common::{
        curve_id_to_index, CLIENT_AUTH_LAYOUT3, CLIENT_AUTH_LAYOUT4,
        HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, RECORD_HANDSHAKE,
    },
};

pub struct ClientKeyExchange {}

impl ClientKeyExchange {
    pub(crate) fn check(
        buf: &mut Cursor<&[u8]>,
        client_hello: &ClientHello,
        curve: usize,
        mut hasher: Hasher,
    ) -> Result<()> {
        if buf.remaining() < 10 || buf.get_u8() != RECORD_HANDSHAKE {
            return Err(anyhow!("Invalid ClientKeyExchange record"));
        }
        buf.advance(4);
        let htype = buf.get_u8();
        if htype != HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE {
            return Err(anyhow!("expecting handshake type 0x10, got {}", htype));
        }
        let length = buf.get_uint(3) as usize;
        if length != buf.remaining() || length == 0 {
            return Err(anyhow!("Invalid ClientKeyExchange length"));
        }
        let key_len = buf.get_u8() as usize;
        if key_len != buf.remaining() {
            return Err(anyhow!("Invalid ClientKeyExchange key length"));
        }

        hasher.update(buf.chunk());

        let curve_index = curve_id_to_index(curve)?;
        let range = if !client_hello.session_ticket.is_empty() {
            CLIENT_AUTH_LAYOUT4[curve_index]..CLIENT_AUTH_LAYOUT4[curve_index + 1]
        } else {
            CLIENT_AUTH_LAYOUT3[curve_index]..CLIENT_AUTH_LAYOUT3[curve_index + 1]
        };

        hasher
            .verify_truncated_left(&client_hello.session_id[range])
            .map_err(|_| anyhow!("TLS 1.2 client key authentication failed"))
    }
}
