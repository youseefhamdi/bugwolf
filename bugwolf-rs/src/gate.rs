// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-gate-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

#[derive(Debug, Clone)]
pub struct ScopeRule {
    pub pattern: String,
    pub allowed: bool,
}

#[derive(Debug, Clone)]
pub struct Scope {
    pub rules: Vec<ScopeRule>,
    pub allow_internal: bool,
}

impl Scope {
    pub fn empty() -> Self {
        Scope {
            rules: Vec::new(),
            allow_internal: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScopeVerdict {
    Allow { reason: String },
    Deny { reason: String },
}

pub fn check(scope: &Scope, host: &str) -> ScopeVerdict {
    if scope.rules.is_empty() {
        return ScopeVerdict::Deny {
            reason: "no rules configured".into(),
        };
    }
    if is_internal(host) && !scope.allow_internal {
        return ScopeVerdict::Deny {
            reason: format!("internal host {} refused by default", host),
        };
    }
    let mut allowed_match: Option<String> = None;
    let mut denied_match: Option<String> = None;
    for rule in &scope.rules {
        if glob_match(&rule.pattern, host) {
            if rule.allowed {
                allowed_match = Some(rule.pattern.clone());
            } else {
                denied_match = Some(rule.pattern.clone());
            }
        }
    }
    if let Some(p) = denied_match {
        return ScopeVerdict::Deny {
            reason: format!("matched deny rule {}", p),
        };
    }
    if let Some(p) = allowed_match {
        return ScopeVerdict::Allow {
            reason: format!("matched allow rule {}", p),
        };
    }
    ScopeVerdict::Deny {
        reason: "no rule matched".into(),
    }
}

pub fn is_internal(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 10
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168)
                    || o[0] == 127
                    || (o[0] == 169 && o[1] == 254)
                    || v4.is_link_local()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return true;
                }
                let s = v6.segments();
                // fc00::/7 — first 7 bits 1111110x
                (s[0] & 0xfe00) == 0xfc00
            }
        };
    }
    // Strip IPv6 brackets if present
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        return is_internal(inner);
    }
    false
}

fn glob_match(pattern: &str, host: &str) -> bool {
    let p = pattern.as_bytes();
    let h = host.as_bytes();
    glob_match_inner(p, h)
}

fn glob_match_inner(p: &[u8], h: &[u8]) -> bool {
    let mut pi = 0;
    let mut hi = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_hi: Option<usize> = None;
    while hi < h.len() {
        if pi < p.len() {
            match p[pi] {
                b'*' => {
                    star_pi = Some(pi);
                    star_hi = Some(hi);
                    pi += 1;
                    continue;
                }
                b'?' => {
                    pi += 1;
                    hi += 1;
                    continue;
                }
                c if c.eq_ignore_ascii_case(&h[hi]) => {
                    pi += 1;
                    hi += 1;
                    continue;
                }
                _ => {}
            }
        }
        if let (Some(spi), Some(shi)) = (star_pi, star_hi) {
            pi = spi + 1;
            star_hi = Some(shi + 1);
            hi = shi + 1;
            continue;
        }
        return false;
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_denies() {
        let s = Scope::empty();
        match check(&s, "example.com") {
            ScopeVerdict::Deny { reason } => assert!(reason.contains("no rules")),
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn wildcard_allows() {
        let s = Scope {
            rules: vec![ScopeRule { pattern: "*.example.com".into(), allowed: true }],
            allow_internal: false,
        };
        match check(&s, "api.example.com") {
            ScopeVerdict::Allow { .. } => {}
            _ => panic!("expected allow"),
        }
    }

    #[test]
    fn specific_host_allows() {
        let s = Scope {
            rules: vec![ScopeRule { pattern: "test.example.com".into(), allowed: true }],
            allow_internal: false,
        };
        match check(&s, "test.example.com") {
            ScopeVerdict::Allow { .. } => {}
            _ => panic!("expected allow"),
        }
    }

    #[test]
    fn internal_refused_by_default() {
        let s = Scope {
            rules: vec![ScopeRule { pattern: "*".into(), allowed: true }],
            allow_internal: false,
        };
        match check(&s, "127.0.0.1") {
            ScopeVerdict::Deny { .. } => {}
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn internal_allowed_with_optin() {
        let s = Scope {
            rules: vec![ScopeRule { pattern: "*".into(), allowed: true }],
            allow_internal: true,
        };
        match check(&s, "127.0.0.1") {
            ScopeVerdict::Allow { .. } => {}
            _ => panic!("expected allow"),
        }
    }

    #[test]
    fn is_internal_various() {
        assert!(is_internal("10.0.0.1"));
        assert!(is_internal("172.16.0.1"));
        assert!(is_internal("172.31.255.255"));
        assert!(is_internal("192.168.1.1"));
        assert!(is_internal("127.0.0.1"));
        assert!(is_internal("169.254.169.254"));
        assert!(is_internal("::1"));
        assert!(is_internal("fc00::1"));
        assert!(is_internal("fd00::1"));
        assert!(is_internal("localhost"));
        assert!(!is_internal("8.8.8.8"));
        assert!(!is_internal("172.32.0.1"));
    }

    #[test]
    fn deny_rule_overrides_allow() {
        let s = Scope {
            rules: vec![
                ScopeRule { pattern: "*".into(), allowed: true },
                ScopeRule { pattern: "evil.example.com".into(), allowed: false },
            ],
            allow_internal: false,
        };
        match check(&s, "evil.example.com") {
            ScopeVerdict::Deny { .. } => {}
            _ => panic!("expected deny"),
        }
    }
}