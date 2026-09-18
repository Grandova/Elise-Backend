use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// Construct standard DNS wireformat query packet for a domain and query type (A or AAAA)
pub fn build_query(domain: &str, qtype: u16, id: u16) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);

    // 1. Header (12 bytes)
    buf.extend_from_slice(&id.to_be_bytes()); // ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: Standard query, RD=1 (Recursion Desired)
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: 1 question
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT: 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: 0

    // 2. Question section: QNAME
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
    buf.push(0x00); // Terminating null label

    // QTYPE & QCLASS
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());

    Ok(buf)
}

/// Parse DNS wireformat response packet and extract resolved IP addresses
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
        // RCODE: 0 = NoError, 3 = NXDomain, etc.
        return Ok(Vec::new());
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    if ancount == 0 {
        return Ok(Vec::new());
    }

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        if pos + 4 > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DNS response truncated in Question section",
            ));
        }
        pos += 4; // Skip QTYPE (2 bytes) + QCLASS (2 bytes)
    }

    // Parse answers
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
            _ => {
                // Ignore CNAME (5), TXT, PTR etc.
            }
        }
    }

    Ok(ips)
}

/// Helper function to skip a DNS name (handling compression pointers RFC 1035 section 4.1.4)
fn skip_name(buf: &[u8], mut pos: usize) -> io::Result<usize> {
    let mut jumps = 0;
    while pos < buf.len() {
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer: 2 bytes
            if pos + 2 > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Truncated compression pointer in DNS name",
                ));
            }
            return Ok(pos + 2);
        } else {
            // Normal label
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
        assert_eq!(q[2], 0x01); // RD = 1
        assert_eq!(q[5], 0x01); // 1 question
        assert_eq!(q[12], 6);
        assert_eq!(&q[13..19], b"google");
        assert_eq!(q[19], 3);
        assert_eq!(&q[20..23], b"com");
        assert_eq!(q[23], 0);
    }

    #[test]
    fn test_parse_response() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Standard response, NoError
        resp.extend_from_slice(&1u16.to_be_bytes()); // 1 question
        resp.extend_from_slice(&1u16.to_be_bytes()); // 1 answer
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());

        // Question: google.com IN A
        resp.push(6);
        resp.extend_from_slice(b"google");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());

        // Answer: pointer 0xC00C, TYPE_A, CLASS_IN, TTL 300, RDLENGTH 4, 142.250.190.46
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
