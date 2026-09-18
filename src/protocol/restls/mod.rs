// Adapted from 3andne/restls d3d7c87; BSD-3-Clause, see LICENSE.
mod args;
mod client_hello;
mod client_key_exchange;
mod common;
mod server_hello;
mod utils;
use anyhow::{anyhow, Context, Result};
use blake3::traits::digest::Mac;
use blake3::Hasher;
use futures_util::stream::StreamExt;
use rand::Rng;
use std::io::Cursor;
use tokio::{
    io::DuplexStream,
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};
use tokio_util::codec::Decoder;

use self::{
    args::Script,
    client_hello::ClientHello,
    client_key_exchange::ClientKeyExchange,
    common::{
        CCS_RECORD, CLIENT_AUTH_SESSION_TICKET_LEN, CLIENT_AUTH_SESSION_TICKET_OFFSET,
        HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, RECORD_ALERT, RECORD_APPLICATION_DATA, RECORD_CCS,
        RECORD_HANDSHAKE, RESTLS_APPDATA_HMAC_LEN, RESTLS_APPDATA_LEN_OFFSET,
        RESTLS_APPDATA_OFFSET, RESTLS_HANDSHAKE_HMAC_LEN, RESTLS_MASK_LEN, TLS_RECORD_HEADER_LEN,
        TO_CLIENT_MAGIC, TO_SERVER_MAGIC,
    },
    server_hello::ServerHello,
    utils::{xor_bytes, DoubleCursorBuf, HandshakeRecord, RestlsCommand, TLSCodec, TLSStream},
};

#[derive(Debug)]
enum TLS12Flow {
    Initial,
    CKEVerified,
    FullHandshakeClientCCS,
    ResumeClientCCS,
    FullHandshakeServerCCS,
    FullHandshakeServerFinished,
    ResumeServerFinished,
    ResumeServerCCS,
    Client0x17,
}

impl TLS12Flow {
    fn ccs_from_client(&mut self) -> Result<()> {
        match self {
            TLS12Flow::CKEVerified => {
                *self = TLS12Flow::FullHandshakeClientCCS;
                Ok(())
            }
            TLS12Flow::ResumeServerFinished => {
                *self = TLS12Flow::ResumeClientCCS;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect CKEVerified or ResumeServerCCS, actual: {:?}",
                self
            )),
        }
    }

    fn ccs_from_server(&mut self) -> Result<()> {
        match self {
            TLS12Flow::Initial => {
                *self = TLS12Flow::ResumeServerCCS;
                Ok(())
            }
            TLS12Flow::FullHandshakeClientCCS => {
                *self = TLS12Flow::FullHandshakeServerCCS;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect Initial or FullHandshakeClientCCS, actual: {:?}",
                self
            )),
        }
    }

    fn cke_verified(&mut self) -> Result<()> {
        match self {
            TLS12Flow::Initial => {
                *self = TLS12Flow::CKEVerified;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect Initial, actual: {:?}",
                self
            )),
        }
    }

    fn client_0x17(&mut self) -> Result<()> {
        use TLS12Flow::*;
        match self {
            FullHandshakeServerFinished | ResumeClientCCS => {
                *self = TLS12Flow::Client0x17;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect FullHandshakeServerFinished | ResumeClientCCS, actual: {:?}",
                self
            )),
        }
    }

    fn is_server_finished(&self) -> bool {
        matches!(
            self,
            TLS12Flow::ResumeServerFinished | TLS12Flow::FullHandshakeServerFinished
        )
    }

    fn is_resume_ccs_from_client(&self) -> bool {
        matches!(self, TLS12Flow::ResumeClientCCS)
    }

    fn is_resume(&self) -> bool {
        use TLS12Flow::*;

        matches!(
            self,
            ResumeClientCCS | ResumeServerCCS | ResumeServerFinished
        )
    }

    fn expect_cke(&self) -> bool {
        matches!(self, TLS12Flow::Initial)
    }

    fn is_client_0x17(&self) -> bool {
        matches!(self, TLS12Flow::Client0x17)
    }

    fn server_0x16(&mut self) -> Result<()> {
        use TLS12Flow::*;

        match self {
            FullHandshakeServerCCS => {
                *self = FullHandshakeServerFinished;
                Ok(())
            }
            ResumeServerCCS => {
                *self = ResumeServerFinished;
                Ok(())
            }
            FullHandshakeServerFinished | ResumeServerFinished => Err(anyhow!(
                "reject: there should be no 0x16 from server after ServerFinished"
            )),
            _ => Ok(()),
        }
    }
}

pub struct RestlsState {
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    curve_id: Option<usize>,
    client_finished: Vec<u8>,
    restls_password: [u8; 32],
    to_client_counter: u64,
    to_server_counter: u64,
    script: Script,
    min_record_len: usize,
    parrot_tls12_gcm: bool,
    id: usize,
}

fn sample_slice(data: &[u8]) -> &[u8] {
    &data[..std::cmp::min(32, data.len())]
}

impl RestlsState {
    fn restls_hmac(&self) -> Hasher {
        Hasher::new_keyed(&self.restls_password)
    }

    pub fn restls_appdata_auth_hmac(&self, is_to_client: bool) -> Hasher {
        let mut hasher = self.restls_hmac();
        hasher.update(&self.server_hello.as_ref().unwrap().server_random);
        if is_to_client {
            hasher.update(TO_CLIENT_MAGIC);
            hasher.update(&self.to_client_counter.to_be_bytes());
        } else {
            hasher.update(TO_SERVER_MAGIC);
            hasher.update(&self.to_server_counter.to_be_bytes());
        }
        hasher
    }

    #[inline]
    fn restls_data_offset(&self, to_client: bool) -> usize {
        self.restls_header_offset(to_client) + RESTLS_APPDATA_OFFSET
    }

    #[inline]
    fn restls_header_offset(&self, to_client: bool) -> usize {
        TLS_RECORD_HEADER_LEN
            + if !to_client && self.server_hello.as_ref().unwrap().is_tls12_gcm
                || to_client && self.parrot_tls12_gcm
            {
                8
            } else {
                0
            }
    }

    pub fn read_app_data<'b>(&mut self, record: &'b mut [u8]) -> Result<(&'b [u8], RestlsCommand)> {
        let is_tls12_gcm = self.server_hello.as_ref().unwrap().is_tls12_gcm;

        if record.len() < self.restls_data_offset(false) {
            return Err(anyhow!(
                "[{}]reject: restls application data isn't long enough",
                self.id
            ));
        }
        if record[..3] != [RECORD_APPLICATION_DATA, 0x03, 0x03] {
            return Err(anyhow!(
                "[{}]reject: restls application data must have 0x17 header",
                self.id
            ));
        }
        if is_tls12_gcm {
            let to_server_counter = u64::from_be_bytes(
                record[TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + 8]
                    .try_into()
                    .unwrap(),
            );
            if to_server_counter
                != self
                    .to_server_counter
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("ResTLS receive counter exhausted"))?
            {
                return Err(anyhow!(
                    "[{}]reject: invalid to server counter for tls 1.2 aes-gcm, expect {}, actual {}",
                    self.id,
                    self.to_server_counter.checked_add(1).ok_or_else(|| anyhow!("ResTLS receive counter exhausted"))?, to_server_counter
                ));
            }
        }
        let mut hmac_auth = self.restls_appdata_auth_hmac(false);
        if !self.client_finished.is_empty() {
            hmac_auth.update(&self.client_finished);
        }
        let header_offset = self.restls_header_offset(false);
        hmac_auth.update(&record[..header_offset]);
        let record = &mut record[header_offset..];
        let actual_auth = &record[..RESTLS_APPDATA_HMAC_LEN];
        hmac_auth.update(&record[RESTLS_APPDATA_LEN_OFFSET..]);

        if hmac_auth.verify_truncated_left(actual_auth).is_err() {
            return Err(anyhow!("reject: bad mac record"));
        }

        self.client_finished.clear();
        let mut hmac_mask = self.restls_appdata_auth_hmac(false);
        hmac_mask.update(sample_slice(&record[RESTLS_APPDATA_OFFSET..]));
        let mask = *hmac_mask.finalize().as_bytes();
        let masked_section = &mut record[RESTLS_APPDATA_LEN_OFFSET..][..RESTLS_MASK_LEN];
        xor_bytes(&mask[..RESTLS_MASK_LEN], masked_section);
        let data_len = (masked_section[0] as usize) << 8 | (masked_section[1] as usize);
        let command = RestlsCommand::from_bytes(&masked_section[2..])?;
        if data_len > record.len() - RESTLS_APPDATA_OFFSET {
            return Err(anyhow!("ResTLS payload length exceeds record"));
        }
        self.to_server_counter = self
            .to_server_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("ResTLS receive counter exhausted"))?;

        Ok((&record[RESTLS_APPDATA_OFFSET..][..data_len], command))
    }

    fn act_according_to_script(&self, data_len: usize) -> (usize, usize, RestlsCommand) {
        let line = self.script.get_line(self.to_client_counter as usize);
        let min_record_len = self.min_record_len + rand::thread_rng().gen_range(0..100);
        let (real_data_len, padding) = match (data_len < min_record_len, line) {
            (_, Some(line)) => {
                let target_len = line.len();
                if target_len < data_len {
                    (target_len, 0)
                } else {
                    (data_len, target_len - data_len)
                }
            }
            (true, None) => (data_len, min_record_len - data_len),
            (false, None) => (data_len, 0),
        };
        let command = match line {
            Some(line) => line.command,
            None => RestlsCommand::Noop,
        };
        (real_data_len, padding, command)
    }

    fn parrot_tls12_nonce(&self, record: &mut [u8]) {
        if self.parrot_tls12_gcm {
            record[5..13].copy_from_slice(&(self.to_client_counter + 1).to_be_bytes());
        }
    }

    fn prepare_app_data_header(
        &mut self,
        out_buf: &mut DoubleCursorBuf,
        data_len: usize,
        command: RestlsCommand,
    ) -> Result<()> {
        if self.to_client_counter == u64::MAX {
            return Err(anyhow!("ResTLS send counter exhausted"));
        }
        let record = out_buf.load_mut();

        record[0..3].copy_from_slice(&[0x17, 0x3, 0x3]);
        let payload_len = (record.len() - 5) as u16;
        record[3..5].copy_from_slice(&payload_len.to_be_bytes());

        self.parrot_tls12_nonce(record);
        let mut hmac_auth = self.restls_appdata_auth_hmac(true);
        let header_offset = self.restls_header_offset(true);
        hmac_auth.update(&record[..header_offset]);
        let record = &mut record[header_offset..];

        let mut hmac_mask = self.restls_appdata_auth_hmac(true);
        hmac_mask.update(sample_slice(&record[RESTLS_APPDATA_OFFSET..]));
        let mask = *hmac_mask.finalize().as_bytes();
        record[RESTLS_APPDATA_LEN_OFFSET..][..2].copy_from_slice(&(data_len as u16).to_be_bytes());

        record[RESTLS_APPDATA_LEN_OFFSET + 2..][..2].copy_from_slice(&command.to_bytes());
        xor_bytes(
            &mask[..RESTLS_MASK_LEN],
            &mut record[RESTLS_APPDATA_LEN_OFFSET..],
        );

        hmac_auth.update(&record[RESTLS_APPDATA_LEN_OFFSET..]);
        let auth = *hmac_auth.finalize().as_bytes();
        record[..RESTLS_APPDATA_HMAC_LEN].copy_from_slice(&auth[..RESTLS_APPDATA_HMAC_LEN]);

        self.to_client_counter = self
            .to_client_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("ResTLS send counter exhausted"))?;
        Ok(())
    }

    async fn read_from_stream(&self, stream: &mut TLSStream, eof_pending: bool) -> Result<()> {
        if stream.codec().has_next() {
            Ok(())
        } else {
            match stream.next().await {
                None => {
                    if eof_pending {
                        std::future::pending().await
                    } else {
                        Err(anyhow!("unexpected eof"))
                    }
                }
                Some(res) => res,
            }
        }
    }

    async fn try_read_client_hello(&mut self, inbound: &mut TLSStream) -> Result<()> {
        self.read_from_stream(inbound, false)
            .await
            .context("failed to read client hello")?;
        let rtype = inbound.codec().peek_record_type()?;
        if rtype != RECORD_HANDSHAKE {
            return Err(anyhow!(
                "reject: incorrect record type for client hello, actual: {}",
                rtype
            ));
        }
        let record = inbound
            .codec_mut()
            .next_record()
            .expect("unexpected error: record has been checked");
        let mut cursor = Cursor::new(&*record);
        self.client_hello = Some(
            ClientHello::parse(&mut cursor, self.id).context("unable to parse client hello: ")?,
        );
        Ok(())
    }

    async fn try_read_server_hello(&mut self, outbound: &mut TLSStream) -> Result<()> {
        self.read_from_stream(outbound, false)
            .await
            .context("failed to read server hello: ")?;
        let rtype = outbound.codec().peek_record_type()?;
        if rtype != RECORD_HANDSHAKE {
            return Err(anyhow!(
                "reject: incorrect record type for server hello, actual: {}",
                rtype
            ));
        }
        let mut record = HandshakeRecord::new(
            outbound
                .codec_mut()
                .peek_record_mut()
                .expect("unexpected error: record has been checked"),
        );
        let mut cursor = Cursor::new(&*record.next_handshake_message()?);
        self.server_hello =
            Some(ServerHello::parse(&mut cursor).context("unable to parse client hello: ")?);
        if !record.has_next() {
            outbound.codec_mut().next_record().unwrap();
        }
        Ok(())
    }

    async fn try_read_tls13_till_first_0x17(
        &mut self,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut ccs_from_server = false;
        loop {
            self.read_from_stream(outbound, false).await?;
            let rtype = outbound.codec().peek_record_type()?;

            match rtype {
                RECORD_CCS if !ccs_from_server => {
                    ccs_from_server = true;
                }
                RECORD_APPLICATION_DATA if ccs_from_server => {
                    break;
                }
                _ => {
                    return Err(anyhow!(
                    "reject: incorrect outbound tls13 record type, expected 1 CCS or Application Data, actual {rtype}",
                ))
                }
            }
            outbound
                .codec_mut()
                .next_record()
                .expect("unexpected error: record has been checked");
            self.relay_to(inbound, outbound).await?;
        }

        Ok(())
    }

    fn prepare_server_auth(&mut self, outbound: &mut TLSStream) -> Result<()> {
        let mut hasher = self.restls_hmac();
        hasher.update(&self.server_hello.as_ref().unwrap().server_random);
        let secret = *hasher.finalize().as_bytes();

        let record = outbound
            .codec_mut()
            .peek_record_mut()
            .expect("unexpected error: record has been checked");
        if record.len() < 21 {
            return Err(anyhow!("Truncated ResTLS server authentication record"));
        }
        let mut offset = 5;
        if self.server_hello.as_ref().unwrap().is_tls12_gcm {
            if record.len() < 29 {
                return Err(anyhow!("Truncated TLS 1.2 server authentication"));
            }
            if u64::from_be_bytes(record[5..13].try_into().unwrap()) == 0 {
                offset = 13;
                self.parrot_tls12_gcm = true;
            }
        }

        xor_bytes(&secret[..RESTLS_HANDSHAKE_HMAC_LEN], &mut record[offset..]);
        Ok(())
    }

    async fn try_read_tl13_till_client_application_data(
        &mut self,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut seen_client_application_data = 0;
        let mut ccs_from_client = false;
        loop {
            select! {
                res = self.read_from_stream(inbound, false) => {
                    res.context("try_read_tl13_till_client_application_data inbound: ")?;
                    match inbound.codec().peek_record_type()? {
                        RECORD_CCS if !ccs_from_client => {
                            if inbound.codec().peek_record().unwrap() != CCS_RECORD {
                                return Err(anyhow!(
                                    "reject: tls13 incorrect CCS record from client",
                                ));
                            }
                            ccs_from_client = true;
                        }
                        RECORD_APPLICATION_DATA if ccs_from_client => {
                            seen_client_application_data += 1;
                            if seen_client_application_data == 1 {
                                self.client_finished.extend_from_slice(inbound.codec().peek_record().unwrap());
                            } else if seen_client_application_data == 2 {
                                break;
                            }
                        }
                        rtype => {
                            return Err(anyhow!(
                                "reject: incorrect inbound tls13 record type, expected 1 CCS or Application Data, actual {rtype}",
                            ));
                        }
                    }
                    inbound.codec_mut().next_record().expect("unexpected error: record has been checked");
                    self.relay_to(outbound, inbound).await?;
                }
                res = self.read_from_stream(outbound, false) => {
                    res.context("try_read_tl13_till_client_application_data outbound: ")?;
                    outbound.codec_mut().next_record().unwrap();
                    if seen_client_application_data == 1 {
                        self.to_client_counter = self.to_client_counter.checked_add(1).ok_or_else(|| anyhow!("ResTLS send counter exhausted"))?;
                    }
                    self.relay_to(inbound, outbound).await?;
                }
            }
        }
        Ok(())
    }

    fn check_tls13_session_id(&self) -> Result<()> {
        let mut hasher = self.restls_hmac();
        let client_hello = self.client_hello.as_ref().unwrap();
        hasher.update(&client_hello.key_share);
        hasher.update(&client_hello.psk);

        let actual = &client_hello.session_id[..RESTLS_HANDSHAKE_HMAC_LEN];
        if hasher.verify_truncated_left(actual).is_ok() {
            Ok(())
        } else {
            Err(anyhow!("ResTLS session authentication failed"))
        }
    }

    fn handle_tls12_plaintext_handshake_msg(&mut self, record: &mut [u8]) -> Result<()> {
        let mut hs = HandshakeRecord::new(record);
        while hs.has_next() {
            let msg = hs.next_handshake_message()?;
            if msg.len() < 7 && msg[0] == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE {
                return Err(anyhow!("Truncated TLS 1.2 key exchange"));
            }
            if msg[0] == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE && msg[4] == 3 {
                let curve_id_u16 = u16::from_be_bytes([msg[5], msg[6]]);
                self.curve_id = Some(curve_id_u16 as usize);
            }
        }
        Ok(())
    }

    fn handle_tls12_outbound(
        &mut self,
        outbound: &mut TLSStream,
        flow: &mut TLS12Flow,
    ) -> Result<()> {
        let rtype = outbound.codec().peek_record_type()?;
        match rtype {
            RECORD_CCS => {
                flow.ccs_from_server()?;
            }
            RECORD_HANDSHAKE => {
                flow.server_0x16()?;
                if flow.is_server_finished() {
                    if flow.is_resume() {
                        self.check_tls12_session_ticket()?;
                    }
                    self.prepare_server_auth(outbound)?;

                    return Ok(());
                }
                let record = outbound.codec_mut().peek_record_mut().unwrap();
                self.handle_tls12_plaintext_handshake_msg(record)?;
            }
            RECORD_APPLICATION_DATA if flow.is_server_finished() => {
                self.to_client_counter = self.to_client_counter.checked_add(1).ok_or_else(|| anyhow!("ResTLS send counter exhausted"))?;
            },
            _ => return Err(anyhow!("reject: incorrect outbound tls12 record type, expected 1 CCS or Handshake, actual {rtype}",)),
        }
        Ok(())
    }

    fn handle_tls12_inbound(&mut self, inbound: &TLSStream, flow: &mut TLS12Flow) -> Result<()> {
        let rtype = inbound.codec().peek_record_type()?;
        match rtype {
            RECORD_CCS => {
                if inbound.codec().peek_record().unwrap() != CCS_RECORD {
                    return Err(anyhow!(
                        "reject: tls12 incorrect CCS record from client",
                    ));
                }
                flow.ccs_from_client()?;
                Ok(())
            }
            RECORD_HANDSHAKE if flow.expect_cke() => {
                // We expect CKE to be the first 0x16 after client hello.
                let maybe_cke = inbound
                    .codec()
                    .peek_record()
                    .expect("unexpected error: record has been checked");
                if self.curve_id.is_none() {

                    return Err(anyhow!("reject: curve_id is not set"));
                }
                ClientKeyExchange::check(
                    &mut Cursor::new(maybe_cke),
                    self.client_hello.as_ref().unwrap(),
                    self.curve_id.unwrap(),
                    self.restls_hmac(),
                )?;
                flow.cke_verified()
            }
            RECORD_HANDSHAKE if flow.is_resume_ccs_from_client() => {
                // For tls 1.2 w/ resume, we need to hash the client finished.
                self.client_finished
                    .extend_from_slice(inbound.codec().peek_record().unwrap());

                Ok(())
            }
            RECORD_HANDSHAKE => Ok(()),
            RECORD_APPLICATION_DATA => flow.client_0x17(),
            _ => Err(anyhow!(
                "reject: incorrect tls12 inbound record type, expected 1 CCS or Handshake, actual {rtype}",
            )),
        }
    }

    async fn try_read_tls12_till_client_application_data(
        &mut self,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut flow = TLS12Flow::Initial;
        loop {
            select! {
                ret = self.read_from_stream(outbound, false) => {
                    ret?;
                    self.handle_tls12_outbound(outbound, &mut flow)?;
                    outbound
                        .codec_mut()
                        .next_record()
                        .expect("unexpected error: record has been checked");
                    self.relay_to(inbound, outbound).await?;
                }
                ret = self.read_from_stream(inbound, false) => {
                    ret.context("try_read_tls12_till_client_application_data inbound: ")?;
                    self.handle_tls12_inbound(inbound, &mut flow)?;
                    if flow.is_client_0x17() {
                        break;
                    }
                    inbound
                        .codec_mut()
                        .next_record()
                        .expect("unexpected error: record has been checked");
                    self.relay_to(outbound, inbound).await?;
                }
            }
        }
        Ok(())
    }

    fn check_tls12_session_ticket(&self) -> Result<()> {
        let mut hasher = self.restls_hmac();
        let client_hello = self.client_hello.as_ref().unwrap();
        hasher.update(&client_hello.session_ticket);
        if hasher
            .verify_truncated_left(
                &client_hello.session_id[CLIENT_AUTH_SESSION_TICKET_OFFSET
                    ..CLIENT_AUTH_SESSION_TICKET_OFFSET + CLIENT_AUTH_SESSION_TICKET_LEN],
            )
            .is_err()
        {
            Err(anyhow!("reject: tls 1.2 session ticket mismatched"))
        } else {
            Ok(())
        }
    }

    async fn relay_to(
        &mut self,
        to_stream: &mut TLSStream,
        from_stream: &mut TLSStream,
    ) -> Result<()> {
        if from_stream.codec().has_next() {
            return Ok(());
        }

        let res = match to_stream
            .get_mut()
            .write_all(from_stream.codec().raw_buf())
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into()),
        };
        from_stream.codec_mut().reset();
        res
    }

    fn prepare_packet_to_client(&mut self, out_buf: &mut DoubleCursorBuf) -> Result<RestlsCommand> {
        let (data_len, padding_len, command) = self.act_according_to_script(out_buf.len());
        out_buf.load(data_len + padding_len);
        self.prepare_app_data_header(out_buf, data_len, command)?;
        Ok(command)
    }

    async fn try_handshake(
        &mut self,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        self.try_read_client_hello(inbound).await?;
        self.relay_to(outbound, inbound).await?;

        self.try_read_server_hello(outbound).await?;
        self.relay_to(inbound, outbound).await?;

        if self.server_hello.as_ref().unwrap().is_tls13 {
            self.check_tls13_session_id()?;
            self.try_read_tls13_till_first_0x17(outbound, inbound)
                .await?;
            self.prepare_server_auth(outbound)?;
            outbound.codec_mut().next_record().unwrap();
            self.relay_to(inbound, outbound).await?;
            self.try_read_tl13_till_client_application_data(outbound, inbound)
                .await?;
        } else {
            self.try_read_tls12_till_client_application_data(outbound, inbound)
                .await?;
        }
        Ok(())
    }
}

pub use args::Config;

pub struct Session {
    state: RestlsState,
    inbound: TLSStream,
    decoy: TLSStream,
}

impl Config {
    pub async fn accept(
        &self,
        client: crate::conn::BoxedStream,
        decoy: crate::conn::BoxedStream,
    ) -> Result<crate::protocol::shadowsocks::transport::Accepted> {
        let mut inbound = TLSCodec::new_outbound().framed(client);
        let mut decoy = TLSCodec::new_inbound().framed(decoy);
        let mut state = RestlsState {
            client_hello: None,
            server_hello: None,
            curve_id: None,
            client_finished: Vec::new(),
            restls_password: self.password,
            to_client_counter: 0,
            to_server_counter: 0,
            script: self.script.clone(),
            min_record_len: self.min_record_len,
            parrot_tls12_gcm: false,
            id: 0,
        };
        match state.try_handshake(&mut decoy, &mut inbound).await {
            Ok(()) => Ok(crate::protocol::shadowsocks::transport::Accepted::Restls(Box::new(Session {
                state,
                inbound,
                decoy,
            }))),
            Err(_) => {
                // Replay only bytes still buffered locally; relayed batches were reset.
                fn buffered(stream: TLSStream) -> crate::conn::BoxedStream {
                    let mut parts = stream.into_parts();
                    parts.codec.skip_to_end();
                    let mut prefix = parts.codec.raw_buf().to_vec();
                    prefix.extend_from_slice(&parts.read_buf);
                    Box::new(crate::conn::PrefixedStream::new(parts.io, Some(prefix)))
                }
                Ok(crate::protocol::shadowsocks::transport::Accepted::Fallback(
                    buffered(inbound),
                    buffered(decoy),
                ))
            }
        }
    }
}

impl Session {
    pub async fn relay(self, plain: DuplexStream) -> Result<()> {
        use bytes::{Buf, BytesMut};
        use tokio_util::codec::FramedRead;
        let Self {
            mut state,
            inbound,
            decoy,
        } = self;
        let parts = inbound.into_parts();
        let (read, mut write) = tokio::io::split(parts.io);
        let mut inbound = FramedRead::new(read, parts.codec);
        inbound.read_buffer_mut().extend_from_slice(&parts.read_buf);
        let mut decoy = decoy;
        let (mut plain_read, mut plain_write) = tokio::io::split(plain);
        let mut to_plain = BytesMut::new();
        let mut to_client = BytesMut::new();
        let mut out_buf = DoubleCursorBuf::new(state.restls_data_offset(true));
        let mut input_closed = false;
        let mut output_closed = false;
        let mut plain_shutdown = false;
        let mut client_shutdown = false;
        let mut decoy_closed = false;
        let mut decoy_shutdown = false;
        let mut awaiting = false;
        let mut respond = 0usize;
        loop {
            while !input_closed && to_plain.is_empty() && inbound.decoder().has_next() {
                let record = inbound.decoder_mut().next_record()?;
                if record[0] == RECORD_ALERT {
                    input_closed = true;
                } else {
                    let (data, command) = state.read_app_data(record)?;
                    to_plain.extend_from_slice(data);
                    awaiting = false;
                    if let RestlsCommand::Response(count) = command {
                        respond = respond
                            .checked_add(count as usize)
                            .filter(|n| *n <= 4096)
                            .ok_or_else(|| anyhow!("ResTLS response backlog exceeded"))?;
                    }
                }
            }
            if to_client.is_empty()
                && (!awaiting || respond > 0 || input_closed)
                && (out_buf.len() > 0 || respond > 0)
            {
                let command = state.prepare_packet_to_client(&mut out_buf)?;
                to_client.extend_from_slice(out_buf.load_mut());
                out_buf.release();
                respond = respond.saturating_sub(1);
                awaiting = matches!(command, RestlsCommand::Response(n) if n > 0);
            }
            while to_client.is_empty() && !client_shutdown && decoy.codec().has_next() {
                let record = decoy.codec_mut().next_record()?;
                if record.len() >= 50 {
                    if state.to_client_counter == u64::MAX {
                        return Err(anyhow!("ResTLS send counter exhausted"));
                    }
                    state.parrot_tls12_nonce(record);
                    to_client.extend_from_slice(record);
                    state.to_client_counter += 1;
                }
            }
            if plain_shutdown && client_shutdown {
                return Ok(());
            }
            let can_read_client = !input_closed
                && to_plain.is_empty()
                && !inbound.decoder().has_next()
                && respond == 0;
            let can_read_decoy = !decoy_closed
                && !client_shutdown
                && to_client.is_empty()
                && !decoy.codec().has_next();
            let can_read_plain = !output_closed && !out_buf.back_mut().is_empty();
            if !decoy_shutdown && (state.to_client_counter > 5 || state.to_server_counter > 5) {
                decoy.get_mut().shutdown().await?;
                decoy_shutdown = true;
            }
            let close_plain = input_closed && to_plain.is_empty() && !plain_shutdown;
            let close_client = output_closed
                && out_buf.len() == 0
                && respond == 0
                && to_client.is_empty()
                && !client_shutdown;
            select! {
                result = inbound.next(), if can_read_client => {
                    match result { Some(result) => result?, None => input_closed = true }
                }
                result = decoy.next(), if can_read_decoy => {
                    match result { Some(result) => result?, None => decoy_closed = true }
                }
                result = plain_read.read(out_buf.back_mut()), if can_read_plain => {
                    let n = result?;
                    if n == 0 { output_closed = true; } else { out_buf.advance_back(n); }
                }
                result = async { if close_plain { plain_write.shutdown().await.map(|_| 0) } else { plain_write.write(&to_plain).await } }, if !to_plain.is_empty() || close_plain => {
                    let n = result?;
                    if close_plain { plain_shutdown = true; continue; }
                    if n == 0 { return Err(anyhow!("ResTLS plaintext write returned zero")); }
                    to_plain.advance(n);
                }
                result = async { if close_client { write.shutdown().await.map(|_| 0) } else { write.write(&to_client).await } }, if !to_client.is_empty() || close_client => {
                    let n = result?;
                    if close_client { client_shutdown = true; continue; }
                    if n == 0 { return Err(anyhow!("ResTLS transport write returned zero")); }
                    to_client.advance(n);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    const RECEIVE: &str = "17030300140f5872daa7bf708bded5c7c06162630000000000";
    const SEND: &str = "170303001413ca611b7ae047e5432ef4316162630000000000";

    fn state() -> RestlsState {
        let config = Config::new(
            &[
                ("host".into(), "localhost".into()),
                ("password".into(), "fixture".into()),
                ("script".into(), "1200".into()),
            ]
            .into(),
        )
        .unwrap();
        RestlsState {
            client_hello: None,
            server_hello: Some(ServerHello {
                is_tls13: true,
                server_random: std::array::from_fn(|i| i as u8),
                _key_share: Vec::new(),
                is_tls12_gcm: false,
            }),
            curve_id: None,
            client_finished: Vec::new(),
            restls_password: config.password,
            to_client_counter: 0,
            to_server_counter: 0,
            script: config.script,
            min_record_len: 15,
            parrot_tls12_gcm: false,
            id: 0,
        }
    }

    #[test]
    fn python_vectors_authentication_and_lengths() {
        let packet = hex::decode(RECEIVE).unwrap();
        for end in 0..packet.len() {
            assert!(state().read_app_data(&mut packet[..end].to_vec()).is_err());
        }
        let mut reader = state();
        let mut corrupted = packet.clone();
        corrupted[5] ^= 1;
        assert!(reader.read_app_data(&mut corrupted).is_err());
        assert_eq!(reader.to_server_counter, 0);
        assert_eq!(reader.read_app_data(&mut packet.clone()).unwrap().0, b"abc");
        assert!(reader.read_app_data(&mut packet.clone()).is_err());
        for value in [
            "1703030014d08570b633c76c072129c7c06162630000000000",
            "1703030014bfd7576df0355178ded5c5c06162630000000000",
        ] {
            assert!(state()
                .read_app_data(&mut hex::decode(value).unwrap())
                .is_err());
        }
        let mut writer = state();
        let mut buffer = DoubleCursorBuf::new(17);
        buffer.back_mut()[..8].copy_from_slice(b"abc\0\0\0\0\0");
        buffer.advance_back(8);
        buffer.load(8);
        writer
            .prepare_app_data_header(&mut buffer, 3, RestlsCommand::Noop)
            .unwrap();
        assert_eq!(buffer.load_mut(), hex::decode(SEND).unwrap());
        writer.to_client_counter = u64::MAX;
        assert!(writer
            .prepare_app_data_header(&mut buffer, 3, RestlsCommand::Noop)
            .is_err());
    }

    #[test]
    fn malformed_handshakes_records_and_scripts() {
        for length in 0..128 {
            let bytes = vec![0u8; length];
            assert!(ClientHello::parse(&mut Cursor::new(&bytes), 0).is_err());
            assert!(ServerHello::parse(&mut Cursor::new(&bytes)).is_err());
        }
        for value in ["0", "65535~1", "1200<255", "1<999", "abc", "1?65535"] {
            assert!(utils::Line::from_str(value).is_err());
        }
        let hello = [22, 3, 1, 0, 3, 1, 2, 3];
        for end in 0..hello.len() {
            let mut codec = TLSCodec::new_outbound();
            let mut bytes = BytesMut::from(&hello[..end]);
            assert!(codec.decode(&mut bytes).unwrap().is_none());
            bytes.extend_from_slice(&hello[end..]);
            assert!(codec.decode(&mut bytes).unwrap().is_some());
            assert_eq!(codec.next_record().unwrap(), hello);
            assert!(codec.next_record().is_err());
        }
        assert!(TLSCodec::new_inbound()
            .decode(&mut BytesMut::from(&b"\x17\x03\x03\xff\xff"[..]))
            .is_err());
    }

    #[tokio::test]
    async fn half_close_drains_response_with_backpressure() {
        let (mut client, transport) = tokio::io::duplex(64);
        let (decoy, _decoy_peer) = tokio::io::duplex(64);
        let (plain, mut target) = tokio::io::duplex(64);
        let session = Session {
            state: state(),
            inbound: TLSCodec::new_inbound().framed(Box::new(transport)),
            decoy: TLSCodec::new_inbound().framed(Box::new(decoy)),
        };
        let relay = session.relay(plain);
        let server = async {
            let mut upload = Vec::new();
            target.read_to_end(&mut upload).await.unwrap();
            assert_eq!(upload, b"abc");
            target.write_all(&vec![42; 128 * 1024]).await.unwrap();
            target.shutdown().await.unwrap();
        };
        let peer = async {
            client
                .write_all(&hex::decode(RECEIVE).unwrap())
                .await
                .unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            let mut cursor = 0;
            let mut counter = 0u64;
            let mut plain = Vec::new();
            while cursor < response.len() {
                let size = u16::from_be_bytes(response[cursor + 3..cursor + 5].try_into().unwrap())
                    as usize;
                let frame = &response[cursor..cursor + 5 + size];
                let mut hash = Hasher::new_keyed(&state().restls_password);
                hash.update(&state().server_hello.unwrap().server_random);
                hash.update(TO_CLIENT_MAGIC);
                hash.update(&counter.to_be_bytes());
                let mut auth = hash.clone();
                auth.update(&frame[..5]);
                auth.update(&frame[13..]);
                auth.verify_truncated_left(&frame[5..13]).unwrap();
                hash.update(sample_slice(&frame[17..]));
                let mask = hash.finalize();
                let length = u16::from_be_bytes([
                    frame[13] ^ mask.as_bytes()[0],
                    frame[14] ^ mask.as_bytes()[1],
                ]) as usize;
                plain.extend_from_slice(&frame[17..17 + length]);
                cursor += 5 + size;
                counter += 1;
            }
            assert_eq!(plain, vec![42; 128 * 1024]);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (result, _, _) = tokio::join!(relay, server, peer);
            result.unwrap();
        })
        .await
        .unwrap();
    }
}
