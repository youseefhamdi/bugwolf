// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-request_engine-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn new(method: &str, path: &str) -> Self {
        Request {
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(&mut self, k: &str, v: &str) -> &mut Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }

    pub fn body(&mut self, b: &[u8]) -> &mut Self {
        self.body = b.to_vec();
        self
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
pub enum RequestError {
    Io(String),
    Parse(String),
    Timeout,
    Unreachable,
    TooLarge,
    BadHeader(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::Io(s) => write!(f, "io: {}", s),
            RequestError::Parse(s) => write!(f, "parse: {}", s),
            RequestError::Timeout => write!(f, "timeout"),
            RequestError::Unreachable => write!(f, "unreachable"),
            RequestError::TooLarge => write!(f, "too large"),
            RequestError::BadHeader(s) => write!(f, "bad header: {}", s),
        }
    }
}

impl std::error::Error for RequestError {}

pub fn build_raw(req: &Request, host: &str, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(req.method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(req.path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host.as_bytes());
    if port != 80 {
        out.extend_from_slice(b":");
        out.extend_from_slice(port.to_string().as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    let mut has_content_length = false;
    let mut has_connection = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        if k.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !has_content_length && !req.body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
    }
    if !has_connection {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), RequestError> {
    for (k, v) in headers {
        if k.contains('\r') || k.contains('\n') || v.contains('\r') || v.contains('\n') {
            return Err(RequestError::BadHeader(format!(
                "CRLF in header value rejected"
            )));
        }
        if k.is_empty() {
            return Err(RequestError::BadHeader("empty header name".into()));
        }
    }
    Ok(())
}

pub fn execute(
    req: &Request,
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<Response, RequestError> {
    validate_headers(&req.headers)?;
    let raw = build_raw(req, host, port);
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(RequestError::TooLarge);
    }

    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms);
    let stream = TcpStream::connect(&addr).map_err(|e| {
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            RequestError::Unreachable
        } else {
            RequestError::Io(e.to_string())
        }
    })?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| RequestError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| RequestError::Io(e.to_string()))?;

    let start = Instant::now();
    let mut stream = stream;

    // Write request
    stream
        .write_all(&raw)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                RequestError::Timeout
            } else {
                RequestError::Io(e.to_string())
            }
        })?;

    // Read response with size cap
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(RequestError::TooLarge);
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                if buf.is_empty() {
                    return Err(RequestError::Timeout);
                }
                break;
            }
            Err(e) => return Err(RequestError::Io(e.to_string())),
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let parsed = crate::parsers::parse_http_response(&buf).map_err(|e| match e {
        crate::parsers::ParseError::Format(s) => RequestError::Parse(s),
    })?;
    Ok(Response {
        elapsed_ms,
        ..parsed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_raw_get_minimal() {
        let mut req = Request::new("GET", "/");
        req.header("User-Agent", "bugwolf/0.1");
        let raw = build_raw(&req, "example.com", 80);
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("User-Agent: bugwolf/0.1\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_raw_post_with_body_includes_content_length() {
        let mut req = Request::new("POST", "/api");
        req.body(b"{\"x\":1}");
        let raw = build_raw(&req, "api.test", 443);
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("POST /api HTTP/1.1\r\n"));
        assert!(s.contains("Host: api.test:443\r\n"));
        assert!(s.contains("Content-Length: 7\r\n"));
        assert!(s.ends_with("{\"x\":1}"));
    }

    #[test]
    fn rejects_crlf_in_header_value() {
        let mut req = Request::new("GET", "/");
        req.header("X-Test", "value\r\nEvil: yes");
        let err = execute(&req, "127.0.0.1", 1, 100).unwrap_err();
        assert!(matches!(err, RequestError::BadHeader(_)));
    }

    #[test]
    fn rejects_empty_header_name() {
        let mut req = Request::new("GET", "/");
        req.headers.push(("".to_string(), "v".to_string()));
        let err = execute(&req, "127.0.0.1", 1, 100).unwrap_err();
        assert!(matches!(err, RequestError::BadHeader(_)));
    }

    #[test]
    fn connection_refused_is_unreachable() {
        let req = Request::new("GET", "/");
        let err = execute(&req, "127.0.0.1", 1, 200).unwrap_err();
        assert!(matches!(err, RequestError::Unreachable));
    }

    #[test]
    fn build_raw_size_under_cap() {
        let mut req = Request::new("GET", "/");
        req.body(&vec![b'a'; 100]);
        let raw = build_raw(&req, "h", 80);
        assert!(raw.len() <= MAX_REQUEST_BYTES);
    }

    #[test]
    fn build_raw_default_close_header() {
        let req = Request::new("GET", "/");
        let raw = build_raw(&req, "h", 80);
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("Connection: close\r\n"));
    }
}