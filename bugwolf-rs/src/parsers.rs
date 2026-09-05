// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-parsers-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use std::collections::HashMap;

use crate::request_engine::Response;

#[derive(Debug)]
pub enum ParseError {
    Format(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Format(s) => write!(f, "format: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse_http_response(buf: &[u8]) -> Result<Response, ParseError> {
    let sep = find_double_crlf(buf).ok_or_else(|| ParseError::Format("no CRLF CRLF".into()))?;
    let head = &buf[..sep];
    let body = buf[sep + 4..].to_vec();

    let head_str = std::str::from_utf8(head).map_err(|e| ParseError::Format(e.to_string()))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().ok_or_else(|| ParseError::Format("empty head".into()))?;
    let mut parts = status_line.splitn(3, ' ');
    let http_ver = parts.next().ok_or_else(|| ParseError::Format("no version".into()))?;
    if !http_ver.starts_with("HTTP/") {
        return Err(ParseError::Format("not HTTP".into()));
    }
    let status: u16 = parts
        .next()
        .ok_or_else(|| ParseError::Format("no status".into()))?
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::Format(e.to_string()))?;
    let reason = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut hv = line.splitn(2, ':');
        let k = hv.next().unwrap_or("").trim().to_string();
        let v = hv.next().unwrap_or("").trim().to_string();
        if !k.is_empty() {
            headers.push((k, v));
        }
    }

    Ok(Response {
        status,
        reason,
        headers,
        body,
        elapsed_ms: 0,
    })
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

pub fn parse_query_string(qs: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    if qs.is_empty() {
        return out;
    }
    for raw in qs.split(|c| c == '&' || c == ';') {
        if raw.is_empty() {
            continue;
        }
        let (k, v) = match raw.split_once('=') {
            Some((k, v)) => (k, v),
            None => (raw, ""),
        };
        let key = url_decode(k);
        let val = url_decode(v);
        out.entry(key).or_default().push(val);
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'+' {
            out.push(b' ');
            i += 1;
        } else if b == b'%' && i + 2 < bytes.len() {
            let h1 = from_hex(bytes[i + 1]);
            let h2 = from_hex(bytes[i + 2]);
            if let (Some(a), Some(b2)) = (h1, h2) {
                out.push((a << 4) | b2);
                i += 3;
            } else {
                out.push(b);
                i += 1;
            }
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub attrs: HashMap<String, String>,
}

pub fn parse_set_cookie(value: &str) -> Vec<Cookie> {
    let mut out = Vec::new();
    let mut parts = value.split(';');
    let head = match parts.next() {
        Some(h) => h,
        None => return out,
    };
    let (raw_name, raw_value) = match head.split_once('=') {
        Some((n, v)) => (n.trim(), v.trim()),
        None => (head.trim(), ""),
    };

    let mut recorded_prefix = String::new();
    let mut name = raw_name.to_string();
    if name.starts_with("__Secure-") {
        recorded_prefix = "__Secure-".into();
        name = name.trim_start_matches("__Secure-").to_string();
    } else if name.starts_with("__Host-") {
        recorded_prefix = "__Host-".into();
        name = name.trim_start_matches("__Host-").to_string();
    }

    let mut attrs = HashMap::new();
    if !recorded_prefix.is_empty() {
        attrs.insert("__prefix".into(), recorded_prefix);
    }
    for a in parts {
        let a = a.trim();
        if a.is_empty() {
            continue;
        }
        let (k, v) = match a.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => (a.to_string(), String::new()),
        };
        let lk = k.to_ascii_lowercase();
        attrs.insert(lk, v);
    }
    out.push(Cookie {
        name,
        value: raw_value.to_string(),
        attrs,
    });
    out
}

#[derive(Debug, Clone)]
pub struct JwtParts {
    pub header_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
    pub header: String,
    pub payload: String,
    pub alg: String,
}

#[derive(Debug)]
pub enum JwtError {
    BadSegmentCount(usize),
    InvalidBase64,
    InvalidJson,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::BadSegmentCount(n) => write!(f, "expected 3 segments, got {}", n),
            JwtError::InvalidBase64 => write!(f, "invalid base64"),
            JwtError::InvalidJson => write!(f, "invalid json"),
        }
    }
}

impl std::error::Error for JwtError {}

pub fn parse_jwt(token: &str) -> Result<JwtParts, JwtError> {
    let segs: Vec<&str> = token.split('.').collect();
    if segs.len() != 3 {
        return Err(JwtError::BadSegmentCount(segs.len()));
    }
    let header_b64 = segs[0];
    let payload_b64 = segs[1];
    let signature_b64 = segs[2];

    let header_bytes = b64url_decode(header_b64).ok_or(JwtError::InvalidBase64)?;
    let header_str = String::from_utf8_lossy(&header_bytes).into_owned();

    // Extract alg (very small JSON parse — find "alg":"...")
    let alg = extract_json_string(&header_str, "alg").unwrap_or_default();

    let payload_bytes = b64url_decode(payload_b64).ok_or(JwtError::InvalidBase64)?;
    let payload_str = String::from_utf8_lossy(&payload_bytes).into_owned();

    Ok(JwtParts {
        header_b64: header_b64.to_string(),
        payload_b64: payload_b64.to_string(),
        signature_b64: signature_b64.to_string(),
        header: header_str,
        payload: payload_str,
        alg,
    })
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let idx = json.find(&needle)? + needle.len();
    let rest = &json[idx..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut s = s.to_string();
    let pad = (4 - s.len() % 4) % 4;
    for _ in 0..pad {
        s.push('=');
    }
    let s = s.replace('-', "+").replace('_', "/");
    let tbl: &[u8; 256] = &B64_TABLE;
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let c0 = tbl[bytes[i] as usize];
        let c1 = tbl[bytes[i + 1] as usize];
        let c2 = tbl[bytes[i + 2] as usize];
        let c3 = tbl[bytes[i + 3] as usize];
        if c0 == 255 || c1 == 255 {
            return None;
        }
        out.push((c0 << 2) | (c1 >> 4));
        if c2 != 255 {
            out.push((c1 << 4) | (c2 >> 2));
            if c3 != 255 {
                out.push((c2 << 6) | c3);
            } else if bytes[i + 3] != b'=' {
                return None;
            }
        } else if bytes[i + 2] != b'=' {
            return None;
        }
        i += 4;
    }
    Some(out)
}

const B64_TABLE: [u8; 256] = build_b64_table();

const fn build_b64_table() -> [u8; 256] {
    let mut t = [255u8; 256];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i < alphabet.len() {
        t[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    t
}

#[derive(Debug, Clone, Default)]
pub struct ServerFingerprint {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub cookies: Vec<String>,
    pub csp: Option<String>,
    pub hsts: bool,
    pub x_frame: Option<String>,
}

pub fn fingerprint_server(headers: &[(String, String)]) -> ServerFingerprint {
    let mut fp = ServerFingerprint::default();
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        match lk.as_str() {
            "server" => fp.server = Some(v.clone()),
            "x-powered-by" => fp.powered_by = Some(v.clone()),
            "set-cookie" => fp.cookies.push(v.clone()),
            "content-security-policy" => fp.csp = Some(v.clone()),
            "strict-transport-security" => fp.hsts = true,
            "x-frame-options" => fp.x_frame = Some(v.clone()),
            _ => {}
        }
    }
    fp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_parse_response() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 5\r\n\r\nhello";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.reason, "OK");
        assert_eq!(r.body, b"hello");
        assert!(r.headers.iter().any(|(k, v)| k == "Server" && v == "nginx"));
    }

    #[test]
    fn query_plus_and_percent20() {
        let m = parse_query_string("a=hello+world&b=hello%20world");
        assert_eq!(m.get("a").unwrap()[0], "hello world");
        assert_eq!(m.get("b").unwrap()[0], "hello world");
    }

    #[test]
    fn query_multivalued_semicolon() {
        let m = parse_query_string("a=1;a=2;a=3");
        assert_eq!(m.get("a").unwrap().len(), 3);
    }

    #[test]
    fn set_cookie_strips_secure_prefix() {
        let cookies = parse_set_cookie("__Secure-sid=abc; Path=/; Secure; HttpOnly");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "sid");
        assert_eq!(cookies[0].value, "abc");
        assert_eq!(cookies[0].attrs.get("__prefix").unwrap(), "__Secure-");
        assert_eq!(cookies[0].attrs.get("secure").unwrap(), "");
        assert_eq!(cookies[0].attrs.get("httponly").unwrap(), "");
    }

    #[test]
    fn set_cookie_strips_host_prefix() {
        let cookies = parse_set_cookie("__Host-csrf=xyz; Path=/; Secure");
        assert_eq!(cookies[0].name, "csrf");
        assert_eq!(cookies[0].attrs.get("__prefix").unwrap(), "__Host-");
    }

    #[test]
    fn jwt_no_signature() {
        let t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.";
        let p = parse_jwt(t).unwrap();
        assert_eq!(p.alg, "HS256");
        assert!(p.signature_b64.is_empty());
    }

    #[test]
    fn jwt_malformed_base64() {
        let t = "!!!!.!!!!.!!!!";
        assert!(parse_jwt(t).is_err());
    }

    #[test]
    fn jwt_bad_segment_count() {
        let t = "abc.def";
        match parse_jwt(t) {
            Err(JwtError::BadSegmentCount(2)) => {}
            _ => panic!("expected BadSegmentCount(2)"),
        }
    }

    #[test]
    fn fingerprint_all_headers() {
        let h = vec![
            ("Server".into(), "nginx/1.25".into()),
            ("X-Powered-By".into(), "PHP/8.2".into()),
            ("Set-Cookie".into(), "a=1".into()),
            ("Content-Security-Policy".into(), "default-src 'self'".into()),
            ("Strict-Transport-Security".into(), "max-age=31536000".into()),
            ("X-Frame-Options".into(), "DENY".into()),
        ];
        let fp = fingerprint_server(&h);
        assert_eq!(fp.server.as_deref(), Some("nginx/1.25"));
        assert_eq!(fp.powered_by.as_deref(), Some("PHP/8.2"));
        assert_eq!(fp.cookies.len(), 1);
        assert!(fp.hsts);
        assert_eq!(fp.x_frame.as_deref(), Some("DENY"));
        assert!(fp.csp.is_some());
    }

    #[test]
    fn fingerprint_only_server() {
        let h = vec![("Server".into(), "apache".into())];
        let fp = fingerprint_server(&h);
        assert_eq!(fp.server.as_deref(), Some("apache"));
        assert!(fp.csp.is_none());
        assert!(!fp.hsts);
    }

    #[test]
    fn fingerprint_no_headers() {
        let fp = fingerprint_server(&[]);
        assert!(fp.server.is_none());
        assert!(fp.csp.is_none());
        assert!(fp.cookies.is_empty());
        assert!(!fp.hsts);
    }
}