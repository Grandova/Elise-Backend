use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use rand::RngCore;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

const IV: [u8; 16] = [
    167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107,
];

enum Cipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
    None,
    Null,
}

impl Cipher {
    fn new(method: &str, password: &str) -> io::Result<Self> {
        let mut key = [0; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA1,
            std::num::NonZeroU32::new(4096).unwrap(),
            b"kcp-go",
            password.as_bytes(),
            &mut key,
        );
        Ok(match method {
            "aes" => Self::Aes256(Aes256::new_from_slice(&key).unwrap()),
            "aes-128" => Self::Aes128(Aes128::new_from_slice(&key[..16]).unwrap()),
            "aes-192" => Self::Aes192(Aes192::new_from_slice(&key[..24]).unwrap()),
            "none" => Self::None,
            "null" => Self::Null,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Unsupported KCPTun cipher",
                ))
            }
        })
    }

    fn crypt(&self, data: &mut [u8], decrypt: bool) {
        if matches!(self, Self::None | Self::Null) {
            return;
        }
        let mut feedback = IV;
        for chunk in data.chunks_mut(16) {
            let mut mask = feedback.into();
            match self {
                Self::Aes128(cipher) => cipher.encrypt_block(&mut mask),
                Self::Aes192(cipher) => cipher.encrypt_block(&mut mask),
                Self::Aes256(cipher) => cipher.encrypt_block(&mut mask),
                _ => unreachable!(),
            }
            for (index, byte) in chunk.iter_mut().enumerate() {
                let input = *byte;
                *byte ^= mask[index];
                feedback[index] = if decrypt { input } else { *byte };
            }
        }
    }

    fn decode(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if matches!(self, Self::Null) {
            return Ok(packet.to_vec());
        }
        if packet.len() < 20 {
            return Err(invalid("Truncated KCPTun encrypted packet"));
        }
        let mut packet = packet.to_vec();
        self.crypt(&mut packet, true);
        if crc32fast::hash(&packet[20..]) != u32::from_le_bytes(packet[16..20].try_into().unwrap())
        {
            return Err(invalid("KCPTun checksum mismatch"));
        }
        Ok(packet.split_off(20))
    }

    fn encode(&self, data: &[u8]) -> Vec<u8> {
        if matches!(self, Self::Null) {
            return data.to_vec();
        }
        let mut packet = vec![0; 20];
        rand::thread_rng().fill_bytes(&mut packet[..16]);
        packet[16..20].copy_from_slice(&crc32fast::hash(data).to_le_bytes());
        packet.extend_from_slice(data);
        self.crypt(&mut packet, false);
        packet
    }
}

struct Group {
    shards: Vec<Option<Vec<u8>>>,
    delivered: Vec<bool>,
    seen: Instant,
}

struct Fec {
    codec: Option<Arc<ReedSolomon>>,
    data: usize,
    total: usize,
    sequence: u32,
    outgoing: Vec<Vec<u8>>,
    groups: HashMap<u32, Group>,
}

impl Fec {
    fn new(data: usize, parity: usize) -> io::Result<Self> {
        if data > 128 || parity > 128 || data + parity > 128 {
            return Err(invalid("KCPTun FEC shard count exceeds limit"));
        }
        let codec = if data == 0 && parity == 0 {
            None
        } else {
            Some(Arc::new(
                ReedSolomon::new(data, parity).map_err(io::Error::other)?,
            ))
        };
        Ok(Self {
            codec,
            data,
            total: data + parity,
            sequence: 0,
            outgoing: Vec::new(),
            groups: HashMap::new(),
        })
    }

    fn encode(&mut self, payload: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let Some(codec) = &self.codec else {
            return Ok(vec![payload.to_vec()]);
        };
        if payload.len() > 65527 {
            return Err(invalid("KCPTun FEC payload exceeds limit"));
        }
        let mut shard = ((payload.len() + 2) as u16).to_le_bytes().to_vec();
        shard.extend_from_slice(payload);
        let mut packet = self.sequence.to_le_bytes().to_vec();
        packet.extend_from_slice(&0xf1u16.to_le_bytes());
        packet.extend_from_slice(&shard);
        self.sequence += 1;
        self.outgoing.push(shard);
        let mut packets = vec![packet];
        if self.outgoing.len() == self.data {
            let size = self.outgoing.iter().map(Vec::len).max().unwrap();
            for shard in &mut self.outgoing {
                shard.resize(size, 0);
            }
            self.outgoing.resize_with(self.total, || vec![0; size]);
            codec.encode(&mut self.outgoing).map_err(io::Error::other)?;
            for shard in &self.outgoing[self.data..] {
                let mut packet = self.sequence.to_le_bytes().to_vec();
                packet.extend_from_slice(&0xf2u16.to_le_bytes());
                packet.extend_from_slice(shard);
                packets.push(packet);
                self.sequence += 1;
            }
            self.sequence %= u32::MAX / self.total as u32 * self.total as u32;
            self.outgoing.clear();
        }
        Ok(packets)
    }

    fn decode(&mut self, packet: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let Some(codec) = &self.codec else {
            return Ok(vec![packet.to_vec()]);
        };
        if packet.len() < 8 || packet.len() > 65535 {
            return Err(invalid("Invalid KCPTun FEC length"));
        }
        let sequence = u32::from_le_bytes(packet[..4].try_into().unwrap());
        let flag = u16::from_le_bytes(packet[4..6].try_into().unwrap());
        let index = sequence as usize % self.total;
        if flag != if index < self.data { 0xf1 } else { 0xf2 } {
            return Err(invalid("KCPTun FEC shard type mismatch"));
        }
        let group_id = sequence / self.total as u32;
        self.groups
            .retain(|_, group| group.seen.elapsed() < Duration::from_secs(10));
        if !self.groups.contains_key(&group_id) && self.groups.len() >= 32 {
            let oldest = *self
                .groups
                .iter()
                .min_by_key(|(_, group)| group.seen)
                .unwrap()
                .0;
            self.groups.remove(&oldest);
        }
        let group = self.groups.entry(group_id).or_insert_with(|| Group {
            shards: vec![None; self.total],
            delivered: vec![false; self.data],
            seen: Instant::now(),
        });
        if group.shards[index].is_some() {
            return Ok(Vec::new());
        }
        group.shards[index] = Some(packet[6..].to_vec());
        let mut recovered = Vec::new();
        if index < self.data {
            let size = u16::from_le_bytes(packet[6..8].try_into().unwrap()) as usize;
            if size != packet.len() - 6 {
                return Err(invalid("KCPTun FEC data length mismatch"));
            }
            recovered.push(packet[8..].to_vec());
            group.delivered[index] = true;
        }
        if group.shards.iter().filter(|shard| shard.is_some()).count() >= self.data
            && group.delivered.iter().any(|delivered| !delivered)
        {
            let size = group.shards.iter().flatten().map(Vec::len).max().unwrap();
            for shard in group.shards.iter_mut().flatten() {
                shard.resize(size, 0);
            }
            codec
                .reconstruct_data(&mut group.shards)
                .map_err(io::Error::other)?;
            for (shard, delivered) in group.shards[..self.data].iter().zip(&mut group.delivered) {
                if *delivered {
                    continue;
                }
                let shard = shard.as_ref().unwrap();
                let length = u16::from_le_bytes(shard[..2].try_into().unwrap()) as usize;
                if !(2..=shard.len()).contains(&length) {
                    return Err(invalid("Invalid recovered KCPTun shard length"));
                }
                recovered.push(shard[2..length].to_vec());
                *delivered = true;
            }
        }
        Ok(recovered)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
