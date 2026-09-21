use crate::conn::{AsyncStream, BoxedStream};
use crate::transport::types::{
    TcpHeaderType, TcpHttpRequestConfig, TcpHttpResponseConfig, TcpTransportConfig,
};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const CRLF: &str = "\r\n";
const DOUBLE_CRLF: &[u8] = b"\r\n\r\n";
const MAX_HEADER_LENGTH: usize = 8192;

const RESP_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nCache-Control: private\r\nContent-Length: 0\r\n\r\n";
const RESP_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nCache-Control: private\r\nContent-Length: 0\r\n\r\n";

pub async fn apply_tcp_transport(
    stream: BoxedStream,
    config: &TcpTransportConfig,
) -> io::Result<BoxedStream> {
    match config.header_type {
        TcpHeaderType::None => Ok(stream),
        TcpHeaderType::Http => {
            let camouflaged = HttpCamouflageStream::server_handshake(stream, config).await?;
            Ok(Box::new(camouflaged))
        }
    }
}

pub struct HttpCamouflageStream<S> {
    inner: S,
    unread_buf: Vec<u8>,
    unread_cursor: usize,
    pending_response: Option<Vec<u8>>,
    pending_resp_cursor: usize,
}

impl<S: AsyncStream> HttpCamouflageStream<S> {
    pub async fn server_handshake(mut inner: S, config: &TcpTransportConfig) -> io::Result<Self> {
        let mut header_bytes = Vec::with_capacity(1024);
        let mut temp_buf = [0u8; 1024];
        let mut ending_pos = None;

        while header_bytes.len() < MAX_HEADER_LENGTH {
            let n = inner.read(&mut temp_buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before HTTP camouflage header",
                ));
            }
            header_bytes.extend_from_slice(&temp_buf[..n]);

            if let Some(pos) = find_subslice(&header_bytes, DOUBLE_CRLF) {
                ending_pos = Some(pos);
                break;
            }
        }

        let ending_idx = match ending_pos {
            Some(pos) => pos,
            None => {
                let _ = inner.write_all(RESP_400).await;
                let _ = inner.flush().await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP camouflage header exceeded 8192 bytes",
                ));
            }
        };

        let raw_header = &header_bytes[..ending_idx + DOUBLE_CRLF.len()];
        let leftover = header_bytes[ending_idx + DOUBLE_CRLF.len()..].to_vec();

        if let Err(err_resp) = validate_http_request(raw_header, config.request.as_ref()) {
            let _ = inner.write_all(err_resp).await;
            let _ = inner.flush().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP camouflage request validation failed",
            ));
        }

        let resp_header_bytes = build_http_response_header(config.response.as_ref());

        Ok(Self {
            inner,
            unread_buf: leftover,
            unread_cursor: 0,
            pending_response: Some(resp_header_bytes),
            pending_resp_cursor: 0,
        })
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpCamouflageStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.unread_cursor < self.unread_buf.len() {
            let available = self.unread_buf.len() - self.unread_cursor;
            let to_read = available.min(buf.remaining());
            buf.put_slice(&self.unread_buf[self.unread_cursor..self.unread_cursor + to_read]);
            self.unread_cursor += to_read;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpCamouflageStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Self {
            inner,
            pending_response,
            pending_resp_cursor,
            ..
        } = self.get_mut();

        if let Some(resp) = pending_response {
            while *pending_resp_cursor < resp.len() {
                let to_write = &resp[*pending_resp_cursor..];
                match Pin::new(&mut *inner).poll_write(cx, to_write) {
                    Poll::Ready(Ok(n)) => {
                        *pending_resp_cursor += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            *pending_response = None;
        }

        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            inner,
            pending_response,
            pending_resp_cursor,
            ..
        } = self.get_mut();

        if let Some(resp) = pending_response {
            while *pending_resp_cursor < resp.len() {
                let to_write = &resp[*pending_resp_cursor..];
                match Pin::new(&mut *inner).poll_write(cx, to_write) {
                    Poll::Ready(Ok(n)) => {
                        *pending_resp_cursor += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            *pending_response = None;
        }
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self { inner, .. } = self.get_mut();
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn validate_http_request(
    raw_header: &[u8],
    expected: Option<&TcpHttpRequestConfig>,
) -> Result<(), &'static [u8]> {
    let text = match std::str::from_utf8(raw_header) {
        Ok(t) => t,
        Err(_) => return Err(RESP_400),
    };

    let mut lines = text.split(CRLF);
    let request_line = match lines.next() {
        Some(l) if !l.is_empty() => l,
        _ => return Err(RESP_400),
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(RESP_400);
    }
    let method = parts[0];
    let path = parts[1];

    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    if let Some(cfg) = expected {
        if !cfg.method.is_empty() && !method.eq_ignore_ascii_case(&cfg.method) {
            return Err(RESP_400);
        }

        if !cfg.path.is_empty() {
            let matched = cfg.path.iter().any(|expected_p| {
                if expected_p == "/" {
                    path == "/" || path.is_empty()
                } else {
                    path == expected_p || path.starts_with(expected_p)
                }
            });
            if !matched {
                return Err(RESP_404);
            }
        }

        if let Some(expected_hosts) = cfg.headers.get("Host").or_else(|| cfg.headers.get("host")) {
            if !expected_hosts.is_empty() {
                let client_host = headers.get("host").map(|s| s.as_str()).unwrap_or("");
                let host_matched = expected_hosts
                    .iter()
                    .any(|h| client_host.eq_ignore_ascii_case(h));
                if !host_matched {
                    return Err(RESP_400);
                }
            }
        }
    }

    Ok(())
}

fn build_http_response_header(config: Option<&TcpHttpResponseConfig>) -> Vec<u8> {
    let (version, status, reason) = match config {
        Some(c) => (c.version.as_str(), c.status.as_str(), c.reason.as_str()),
        None => ("1.1", "200", "OK"),
    };

    let mut resp = format!("HTTP/{} {} {}{}", version, status, reason, CRLF);

    let mut has_content_type = false;
    let mut has_connection = false;
    let mut has_date = false;

    if let Some(c) = config {
        for (k, vals) in &c.headers {
            let k_lower = k.to_ascii_lowercase();
            if k_lower == "content-type" {
                has_content_type = true;
            } else if k_lower == "connection" {
                has_connection = true;
            } else if k_lower == "date" {
                has_date = true;
            }
            let val_joined = vals.join(", ");
            resp.push_str(&format!("{}: {}{}", k, val_joined, CRLF));
        }
    }

    if !has_content_type {
        resp.push_str(&format!(
            "Content-Type: application/octet-stream, video/mpeg{}",
            CRLF
        ));
    }
    if !has_connection {
        resp.push_str(&format!("Connection: keep-alive{}", CRLF));
    }
    if !has_date {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let date_str = format_rfc2822_date(now_sec);
        resp.push_str(&format!("Date: {}{}", date_str, CRLF));
    }

    resp.push_str(CRLF);
    resp.into_bytes()
}

fn format_rfc2822_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let day_of_week = DAYS[((secs / 86400 + 4) % 7) as usize];
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut days_remaining = secs / 86400;
    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days_remaining < days_in_year {
            break;
        }
        days_remaining -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let mut month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if is_leap {
        month_lengths[1] = 29;
    }

    let mut month = 0;
    for (m, &len) in month_lengths.iter().enumerate() {
        if days_remaining < len {
            month = m;
            break;
        }
        days_remaining -= len;
    }
    let day = days_remaining + 1;

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        day_of_week, day, MONTHS[month], year, hours, minutes, seconds
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_tcp_http_camouflage_success() {
        let (client, server) = duplex(4096);

        let config = TcpTransportConfig {
            header_type: TcpHeaderType::Http,
            request: Some(TcpHttpRequestConfig {
                version: "1.1".to_string(),
                method: "GET".to_string(),
                path: vec!["/video/stream".to_string()],
                headers: {
                    let mut m = HashMap::new();
                    m.insert("Host".to_string(), vec!["cdn.example.com".to_string()]);
                    m
                },
            }),
            response: None,
        };

        let server_task = tokio::spawn(async move {
            let mut camouflaged = apply_tcp_transport(Box::new(server), &config)
                .await
                .unwrap();
            let mut buf = [0u8; 5];
            camouflaged.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HELLO");

            camouflaged.write_all(b"WORLD").await.unwrap();
            camouflaged.flush().await.unwrap();
        });

        let mut client = client;

        let req = b"GET /video/stream HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\nHELLO";
        client.write_all(req).await.unwrap();
        client.flush().await.unwrap();

        let mut resp_buf = vec![0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_text = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp_text.contains("Content-Type: application/octet-stream"));
        assert!(resp_text.ends_with("WORLD"));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_http_camouflage_path_mismatch_returns_404() {
        let (mut client, server) = duplex(4096);

        let config = TcpTransportConfig {
            header_type: TcpHeaderType::Http,
            request: Some(TcpHttpRequestConfig {
                version: "1.1".to_string(),
                method: "GET".to_string(),
                path: vec!["/secret".to_string()],
                headers: HashMap::new(),
            }),
            response: None,
        };

        let server_task = tokio::spawn(async move {
            let res = apply_tcp_transport(Box::new(server), &config).await;
            assert!(res.is_err());
        });

        let req = b"GET /wrong HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n";
        client.write_all(req).await.unwrap();

        let mut resp_buf = vec![0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_text = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_text.starts_with("HTTP/1.1 404 Not Found\r\n"));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_http_camouflage_oversize_header_returns_400() {
        let (mut client, server) = duplex(16384);

        let config = TcpTransportConfig {
            header_type: TcpHeaderType::Http,
            request: None,
            response: None,
        };

        let server_task = tokio::spawn(async move {
            let res = apply_tcp_transport(Box::new(server), &config).await;
            assert!(res.is_err());
        });

        let big_data = vec![b'A'; 9000];
        client.write_all(&big_data).await.unwrap();

        let mut resp_buf = vec![0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_text = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_text.starts_with("HTTP/1.1 400 Bad Request\r\n"));

        server_task.await.unwrap();
    }
}
