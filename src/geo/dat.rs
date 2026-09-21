use ipnet::{Ipv4Net, Ipv6Net};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use tracing::debug;

pub struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn is_eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    #[inline]
    pub fn read_varint(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        while self.pos < self.buf.len() {
            let b = self.buf[self.pos];
            self.pos += 1;
            result |= ((b & 0x7F) as u64) << shift;
            if (b & 0x80) == 0 {
                return Some(result);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        None
    }

    #[inline]
    pub fn read_tag(&mut self) -> Option<(u32, u8)> {
        let var = self.read_varint()?;
        let wire_type = (var & 0x07) as u8;
        let field_num = (var >> 3) as u32;
        Some((field_num, wire_type))
    }

    #[inline]
    pub fn read_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Some(slice)
    }

    #[inline]
    pub fn read_string(&mut self) -> Option<&'a str> {
        let b = self.read_bytes()?;
        std::str::from_utf8(b).ok()
    }

    pub fn skip_field(&mut self, wire_type: u8) -> bool {
        match wire_type {
            0 => self.read_varint().is_some(),
            1 => {
                if self.pos + 8 <= self.buf.len() {
                    self.pos += 8;
                    true
                } else {
                    false
                }
            }
            2 => {
                if let Some(len) = self.read_varint() {
                    let len = len as usize;
                    if self.pos + len <= self.buf.len() {
                        self.pos += len;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            5 if self.pos + 4 <= self.buf.len() => {
                self.pos += 4;
                true
            }
            5 => false,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CountryIpList {
    pub ipv4_ranges: Vec<(u32, u32)>,
    pub ipv6_ranges: Vec<(u128, u128)>,
}

impl CountryIpList {
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let val = u32::from(v4);
                self.ipv4_ranges
                    .binary_search_by(|&(start, end)| {
                        if val < start {
                            std::cmp::Ordering::Greater
                        } else if val > end {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
            }
            IpAddr::V6(v6) => {
                let val = u128::from(v6);
                self.ipv6_ranges
                    .binary_search_by(|&(start, end)| {
                        if val < start {
                            std::cmp::Ordering::Greater
                        } else if val > end {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
            }
        }
    }

    pub fn merge_and_sort(&mut self) {
        if !self.ipv4_ranges.is_empty() {
            self.ipv4_ranges.sort_unstable_by_key(|r| r.0);
            let mut merged = Vec::with_capacity(self.ipv4_ranges.len());
            let mut cur = self.ipv4_ranges[0];
            for &next in &self.ipv4_ranges[1..] {
                if next.0 <= cur.1.saturating_add(1) {
                    cur.1 = cur.1.max(next.1);
                } else {
                    merged.push(cur);
                    cur = next;
                }
            }
            merged.push(cur);
            merged.shrink_to_fit();
            self.ipv4_ranges = merged;
        }

        if !self.ipv6_ranges.is_empty() {
            self.ipv6_ranges.sort_unstable_by_key(|r| r.0);
            let mut merged = Vec::with_capacity(self.ipv6_ranges.len());
            let mut cur = self.ipv6_ranges[0];
            for &next in &self.ipv6_ranges[1..] {
                if next.0 <= cur.1.saturating_add(1) {
                    cur.1 = cur.1.max(next.1);
                } else {
                    merged.push(cur);
                    cur = next;
                }
            }
            merged.push(cur);
            merged.shrink_to_fit();
            self.ipv6_ranges = merged;
        }
    }
}

pub struct GeoIpFile {
    data: Vec<u8>,

    index: HashMap<String, (usize, usize)>,
}

impl GeoIpFile {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let data = fs::read(path)?;
        let mut index = HashMap::new();

        let mut reader = ProtoReader::new(&data);
        while !reader.is_eof() {
            let (tag, wire) = match reader.read_tag() {
                Some(t) => t,
                None => break,
            };
            if tag == 1 && wire == 2 {
                let entry_bytes = match reader.read_bytes() {
                    Some(b) => b,
                    None => break,
                };
                let entry_offset = entry_bytes.as_ptr() as usize - data.as_ptr() as usize;
                let entry_len = entry_bytes.len();

                let mut inner = ProtoReader::new(entry_bytes);
                while !inner.is_eof() {
                    let (itag, iwire) = match inner.read_tag() {
                        Some(t) => t,
                        None => break,
                    };
                    if itag == 1 && iwire == 2 {
                        if let Some(code) = inner.read_string() {
                            index.insert(code.to_uppercase(), (entry_offset, entry_len));
                        }
                        break;
                    } else {
                        inner.skip_field(iwire);
                    }
                }
            } else {
                reader.skip_field(wire);
            }
        }

        debug!("GeoIpFile loaded {} countries from dat", index.len());
        Ok(Self { data, index })
    }

    pub fn load_country(&self, country_code: &str) -> Option<CountryIpList> {
        let key = country_code.trim().to_uppercase();
        let &(offset, len) = self.index.get(&key)?;
        let entry_slice = &self.data[offset..offset + len];

        let mut country_list = CountryIpList::default();
        let mut reader = ProtoReader::new(entry_slice);

        while !reader.is_eof() {
            let (tag, wire) = match reader.read_tag() {
                Some(t) => t,
                None => break,
            };
            if tag == 2 && wire == 2 {
                let cidr_bytes = match reader.read_bytes() {
                    Some(b) => b,
                    None => break,
                };
                let mut cidr_reader = ProtoReader::new(cidr_bytes);
                let mut ip_bytes: Option<&[u8]> = None;
                let mut prefix = 0u32;

                while !cidr_reader.is_eof() {
                    let (ctag, cwire) = match cidr_reader.read_tag() {
                        Some(t) => t,
                        None => break,
                    };
                    match (ctag, cwire) {
                        (1, 2) => ip_bytes = cidr_reader.read_bytes(),
                        (2, 0) => prefix = cidr_reader.read_varint().unwrap_or(0) as u32,
                        _ => {
                            cidr_reader.skip_field(cwire);
                        }
                    }
                }

                if let Some(raw_ip) = ip_bytes {
                    if raw_ip.len() == 4 {
                        let octets: [u8; 4] = [raw_ip[0], raw_ip[1], raw_ip[2], raw_ip[3]];
                        let v4 = Ipv4Addr::from(octets);
                        let p = prefix.min(32) as u8;
                        if let Ok(net) = Ipv4Net::new(v4, p) {
                            let start = u32::from(net.network());
                            let end = u32::from(net.broadcast());
                            country_list.ipv4_ranges.push((start, end));
                        }
                    } else if raw_ip.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(raw_ip);
                        let v6 = Ipv6Addr::from(octets);
                        let p = prefix.min(128) as u8;
                        if let Ok(net) = Ipv6Net::new(v6, p) {
                            let start = u128::from(net.network());
                            let end = u128::from(net.broadcast());
                            country_list.ipv6_ranges.push((start, end));
                        }
                    }
                }
            } else {
                reader.skip_field(wire);
            }
        }

        country_list.merge_and_sort();
        Some(country_list)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SiteGroupList {
    pub exact_domains: HashSet<String>,
    pub domain_suffixes: Vec<String>,
    pub keywords: Vec<String>,
    pub regexes: Vec<Regex>,
}

impl SiteGroupList {
    #[inline]
    pub fn matches(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.exact_domains.contains(&lower) {
            return true;
        }
        for sfx in &self.domain_suffixes {
            if lower == *sfx || lower.ends_with(&format!(".{}", sfx)) {
                return true;
            }
        }
        for kw in &self.keywords {
            if lower.contains(kw) {
                return true;
            }
        }
        for re in &self.regexes {
            if re.is_match(&lower) {
                return true;
            }
        }
        false
    }
}

pub struct GeoSiteFile {
    data: Vec<u8>,
    index: HashMap<String, (usize, usize)>,
}

impl GeoSiteFile {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let data = fs::read(path)?;
        let mut index = HashMap::new();

        let mut reader = ProtoReader::new(&data);
        while !reader.is_eof() {
            let (tag, wire) = match reader.read_tag() {
                Some(t) => t,
                None => break,
            };
            if tag == 1 && wire == 2 {
                let entry_bytes = match reader.read_bytes() {
                    Some(b) => b,
                    None => break,
                };
                let entry_offset = entry_bytes.as_ptr() as usize - data.as_ptr() as usize;
                let entry_len = entry_bytes.len();

                let mut inner = ProtoReader::new(entry_bytes);
                while !inner.is_eof() {
                    let (itag, iwire) = match inner.read_tag() {
                        Some(t) => t,
                        None => break,
                    };
                    if itag == 1 && iwire == 2 {
                        if let Some(tag_str) = inner.read_string() {
                            index.insert(tag_str.to_lowercase(), (entry_offset, entry_len));
                        }
                        break;
                    } else {
                        inner.skip_field(iwire);
                    }
                }
            } else {
                reader.skip_field(wire);
            }
        }

        debug!("GeoSiteFile loaded {} site groups from dat", index.len());
        Ok(Self { data, index })
    }

    pub fn load_group(&self, tag: &str) -> Option<SiteGroupList> {
        let key = tag.trim().to_lowercase();
        let &(offset, len) = self.index.get(&key)?;
        let entry_slice = &self.data[offset..offset + len];

        let mut group = SiteGroupList::default();
        let mut reader = ProtoReader::new(entry_slice);

        while !reader.is_eof() {
            let (tag, wire) = match reader.read_tag() {
                Some(t) => t,
                None => break,
            };
            if tag == 2 && wire == 2 {
                let domain_bytes = match reader.read_bytes() {
                    Some(b) => b,
                    None => break,
                };
                let mut d_reader = ProtoReader::new(domain_bytes);
                let mut dtype = 0u32;
                let mut dval = String::new();

                while !d_reader.is_eof() {
                    let (dtag, dwire) = match d_reader.read_tag() {
                        Some(t) => t,
                        None => break,
                    };
                    match (dtag, dwire) {
                        (1, 0) => dtype = d_reader.read_varint().unwrap_or(0) as u32,
                        (2, 2) => {
                            if let Some(s) = d_reader.read_string() {
                                dval = s.to_lowercase();
                            }
                        }
                        _ => {
                            d_reader.skip_field(dwire);
                        }
                    }
                }

                if !dval.is_empty() {
                    match dtype {
                        0 => group.keywords.push(dval),
                        1 => {
                            if let Ok(re) = Regex::new(&dval) {
                                group.regexes.push(re);
                            }
                        }
                        2 => group.domain_suffixes.push(dval),
                        3 => {
                            group.exact_domains.insert(dval);
                        }
                        _ => group.domain_suffixes.push(dval),
                    }
                }
            } else {
                reader.skip_field(wire);
            }
        }

        group
            .domain_suffixes
            .sort_unstable_by_key(|a| std::cmp::Reverse(a.len()));
        group.domain_suffixes.dedup();
        group.keywords.dedup();

        Some(group)
    }
}
