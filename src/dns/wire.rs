use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub fn build_query(domain: &str, qtype: u16, id: u16) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);

    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    let clean_domain = domain.trim().trim_end_matches('.');
    if clean_domain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Domain name cannot be empty",
        ));
    }

    for label in clean_domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid DNS label length in '{domain}'"),
            ));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00);

    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());

    Ok(buf)
}

pub fn parse_response(buf: &[u8]) -> io::Result<Vec<IpAddr>> {
    if buf.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "DNS response header too short",
        ));
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Ok(Vec::new());
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    if ancount == 0 {
        return Ok(Vec::new());
    }

    let mut pos = 12;

    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        if pos + 4 > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DNS response truncated in Question section",
            ));
        }
        pos += 4;
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            break;
        }

        let atype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let _aclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let _ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > buf.len() {
            break;
        }

        let rdata = &buf[pos..pos + rdlength];
        pos += rdlength;

        match atype {
            TYPE_A if rdlength == 4 => {
                let octets: [u8; 4] = rdata.try_into().unwrap();
                ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            TYPE_AAAA if rdlength == 16 => {
                let octets: [u8; 16] = rdata.try_into().unwrap();
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }

    Ok(ips)
}

fn skip_name(buf: &[u8], mut pos: usize) -> io::Result<usize> {
    let mut jumps = 0;
    while pos < buf.len() {
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 2 > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Truncated compression pointer in DNS name",
                ));
            }
            return Ok(pos + 2);
        } else {
            let label_len = len as usize;
            pos += 1 + label_len;
            jumps += 1;
            if jumps > 128 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Too many DNS labels or pointer loop",
                ));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "DNS name extends beyond buffer",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query() {
        let q = build_query("google.com", TYPE_A, 0x1234).unwrap();
        assert_eq!(&q[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(q[2], 0x01);
        assert_eq!(q[5], 0x01);
        assert_eq!(q[12], 6);
        assert_eq!(&q[13..19], b"google");
        assert_eq!(q[19], 3);
        assert_eq!(&q[20..23], b"com");
        assert_eq!(q[23], 0);
    }

    #[test]
    fn test_parse_response() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());

        resp.push(6);
        resp.extend_from_slice(b"google");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());

        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[142, 250, 190, 46]);

        let ips = parse_response(&resp).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "142.250.190.46".parse::<IpAddr>().unwrap());
    }
}
