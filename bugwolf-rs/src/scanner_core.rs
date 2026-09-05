// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-scanner_core-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use std::cell::{Cell, RefCell};

use crate::gate::is_internal;
use crate::request_engine::{Request, Response};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    Passive,
    Active,
    Destructive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub scanner: String,
    pub severity: Severity,
    pub title: String,
    pub evidence: String,
    pub opt_in_required: bool,
}

pub trait Scanner {
    fn name(&self) -> &str;
    fn risk_class(&self) -> RiskClass;
    fn check(&self, req: &Request, resp: &Response) -> Vec<Finding>;
}

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub allow_internal_hosts: bool,
    pub opt_in_destructive: bool,
    pub max_requests: u32,
}

impl Default for ScanContext {
    fn default() -> Self {
        ScanContext {
            allow_internal_hosts: false,
            opt_in_destructive: false,
            max_requests: 1000,
        }
    }
}

#[derive(Debug)]
pub enum ScanError {
    OutOfBudget,
    DestructiveNotOptedIn,
    InternalHostNotAllowed(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::OutOfBudget => write!(f, "out of request budget"),
            ScanError::DestructiveNotOptedIn => write!(f, "destructive scanner not opted in"),
            ScanError::InternalHostNotAllowed(h) => write!(f, "internal host {} not allowed", h),
        }
    }
}

impl std::error::Error for ScanError {}

pub struct ScanEngine {
    pub scanners: Vec<Box<dyn Scanner + Send + Sync>>,
    pub context: ScanContext,
    pub findings: RefCell<Vec<Finding>>,
    pub request_budget: Cell<u32>,
}

impl ScanEngine {
    pub fn new(ctx: ScanContext) -> Self {
        let budget = ctx.max_requests;
        ScanEngine {
            scanners: Vec::new(),
            context: ctx,
            findings: RefCell::new(Vec::new()),
            request_budget: Cell::new(budget),
        }
    }

    pub fn register(&mut self, s: Box<dyn Scanner + Send + Sync>) {
        self.scanners.push(s);
    }

    pub fn record(&self, f: Finding, target_host: &str) -> Result<(), ScanError> {
        if is_internal(target_host) && !self.context.allow_internal_hosts {
            return Err(ScanError::InternalHostNotAllowed(target_host.to_string()));
        }
        if f.opt_in_required && !self.context.opt_in_destructive {
            return Err(ScanError::DestructiveNotOptedIn);
        }
        let current = self.request_budget.get();
        if current == 0 {
            return Err(ScanError::OutOfBudget);
        }
        self.request_budget.set(current - 1);
        self.findings.borrow_mut().push(f);
        Ok(())
    }

    pub fn run(&self, req: &Request, resp: &Response, host: &str) -> Vec<Result<(), ScanError>> {
        let mut results = Vec::new();
        for s in &self.scanners {
            for f in s.check(req, resp) {
                results.push(self.record(f, host));
            }
        }
        results
    }

    pub fn drain(&self) -> Vec<Finding> {
        let mut f = self.findings.borrow_mut();
        let out = f.clone();
        f.clear();
        out
    }
}

pub struct MissingSecurityHeaders;

impl Scanner for MissingSecurityHeaders {
    fn name(&self) -> &str {
        "missing_security_headers"
    }
    fn risk_class(&self) -> RiskClass {
        RiskClass::Passive
    }
    fn check(&self, _req: &Request, resp: &Response) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut has_xframe = false;
        let mut has_csp = false;
        let mut has_server = false;
        for (k, v) in &resp.headers {
            let lk = k.to_ascii_lowercase();
            match lk.as_str() {
                "x-frame-options" => has_xframe = true,
                "content-security-policy" => has_csp = true,
                "server" => has_server = true,
                _ => {}
            }
            let _ = v;
        }
        if has_server {
            out.push(Finding {
                id: "missing_security_headers/server".into(),
                scanner: self.name().into(),
                severity: Severity::Info,
                title: "Server header exposes software".into(),
                evidence: "Server header present".into(),
                opt_in_required: false,
            });
        }
        if !has_xframe {
            out.push(Finding {
                id: "missing_security_headers/xfo".into(),
                scanner: self.name().into(),
                severity: Severity::Low,
                title: "Missing X-Frame-Options".into(),
                evidence: "X-Frame-Options header absent".into(),
                opt_in_required: false,
            });
        }
        if !has_csp {
            out.push(Finding {
                id: "missing_security_headers/csp".into(),
                scanner: self.name().into(),
                severity: Severity::Low,
                title: "Missing Content-Security-Policy".into(),
                evidence: "Content-Security-Policy header absent".into(),
                opt_in_required: false,
            });
        }
        out
    }
}

pub struct CookieInsecure;

impl Scanner for CookieInsecure {
    fn name(&self) -> &str {
        "cookie_insecure"
    }
    fn risk_class(&self) -> RiskClass {
        RiskClass::Passive
    }
    fn check(&self, _req: &Request, resp: &Response) -> Vec<Finding> {
        let mut out = Vec::new();
        for (k, _v) in &resp.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                let v = _v;
                let v_lower = v.to_ascii_lowercase();
                if !v_lower.contains("secure") {
                    out.push(Finding {
                        id: "cookie_insecure/no_secure".into(),
                        scanner: self.name().into(),
                        severity: Severity::Low,
                        title: "Cookie missing Secure flag".into(),
                        evidence: v.clone(),
                        opt_in_required: false,
                    });
                }
                if !v_lower.contains("httponly") {
                    out.push(Finding {
                        id: "cookie_insecure/no_httponly".into(),
                        scanner: self.name().into(),
                        severity: Severity::Low,
                        title: "Cookie missing HttpOnly flag".into(),
                        evidence: v.clone(),
                        opt_in_required: false,
                    });
                }
                if v_lower.contains("samesite=none") {
                    out.push(Finding {
                        id: "cookie_insecure/samesite_none".into(),
                        scanner: self.name().into(),
                        severity: Severity::Medium,
                        title: "Cookie SameSite=None".into(),
                        evidence: v.clone(),
                        opt_in_required: false,
                    });
                }
            }
        }
        out
    }
}

pub struct ReflectedXssHeuristic;

impl Scanner for ReflectedXssHeuristic {
    fn name(&self) -> &str {
        "reflected_xss_heuristic"
    }
    fn risk_class(&self) -> RiskClass {
        RiskClass::Active
    }
    fn check(&self, req: &Request, resp: &Response) -> Vec<Finding> {
        let mut probe_present = false;
        let path_hits = req.path.contains("<script>");
        let body_hits = req.body.as_slice().windows(8).any(|w| w == b"<script>");
        let query_hits = req
            .headers
            .iter()
            .any(|(k, v)| k.to_ascii_lowercase() == "x-probe-payload" && v.contains("<script>"));
        if path_hits || body_hits || query_hits {
            probe_present = true;
        }
        if !probe_present {
            return Vec::new();
        }
        let body_str = String::from_utf8_lossy(&resp.body);
        let pre_ctx = body_str.contains("<pre>") && !body_str.contains("</pre>");
        if body_str.contains("<script>") && !pre_ctx {
            return vec![Finding {
                id: "reflected_xss_heuristic/reflected".into(),
                scanner: self.name().into(),
                severity: Severity::Medium,
                title: "Possible reflected XSS".into(),
                evidence: "Script tag reflected verbatim in response".into(),
                opt_in_required: false,
            }];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_resp(headers: Vec<(&str, &str)>, body: &[u8]) -> Response {
        Response {
            status: 200,
            reason: "OK".into(),
            headers: headers.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
            body: body.to_vec(),
            elapsed_ms: 0,
        }
    }

    fn mk_req() -> Request {
        Request::new("GET", "/")
    }

    #[test]
    fn register_and_drain() {
        let mut engine = ScanEngine::new(ScanContext::default());
        engine.register(Box::new(MissingSecurityHeaders));
        let req = mk_req();
        let resp = mk_resp(vec![], b"");
        engine.run(&req, &resp, "example.com");
        let findings = engine.drain();
        assert!(!findings.is_empty());
    }

    #[test]
    fn budget_enforced() {
        let ctx = ScanContext { max_requests: 0, ..ScanContext::default() };
        let engine = ScanEngine::new(ctx);
        let f = Finding {
            id: "x".into(),
            scanner: "s".into(),
            severity: Severity::Info,
            title: "t".into(),
            evidence: "e".into(),
            opt_in_required: false,
        };
        let err = engine.record(f, "example.com").unwrap_err();
        assert!(matches!(err, ScanError::OutOfBudget));
    }

    #[test]
    fn destructive_requires_opt_in() {
        let ctx = ScanContext::default();
        let engine = ScanEngine::new(ctx);
        let f = Finding {
            id: "x".into(),
            scanner: "s".into(),
            severity: Severity::High,
            title: "t".into(),
            evidence: "e".into(),
            opt_in_required: true,
        };
        let err = engine.record(f, "example.com").unwrap_err();
        assert!(matches!(err, ScanError::DestructiveNotOptedIn));
    }

    #[test]
    fn internal_host_refused() {
        let engine = ScanEngine::new(ScanContext::default());
        let f = Finding {
            id: "x".into(),
            scanner: "s".into(),
            severity: Severity::Info,
            title: "t".into(),
            evidence: "e".into(),
            opt_in_required: false,
        };
        let err = engine.record(f, "192.168.1.5").unwrap_err();
        assert!(matches!(err, ScanError::InternalHostNotAllowed(_)));
    }

    #[test]
    fn missing_headers_detection() {
        let s = MissingSecurityHeaders;
        let resp = mk_resp(vec![("Server", "nginx")], b"");
        let f = s.check(&mk_req(), &resp);
        assert!(f.iter().any(|x| x.id == "missing_security_headers/csp"));
        assert!(f.iter().any(|x| x.id == "missing_security_headers/xfo"));
    }

    #[test]
    fn cookie_insecure_detection() {
        let s = CookieInsecure;
        let resp = mk_resp(vec![("Set-Cookie", "sid=abc; SameSite=None")], b"");
        let f = s.check(&mk_req(), &resp);
        assert!(f.iter().any(|x| x.id == "cookie_insecure/no_secure"));
        assert!(f.iter().any(|x| x.id == "cookie_insecure/no_httponly"));
        assert!(f.iter().any(|x| x.id == "cookie_insecure/samesite_none"));
    }

    #[test]
    fn cookie_secure_passes() {
        let s = CookieInsecure;
        let resp = mk_resp(
            vec![("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict")],
            b"",
        );
        let f = s.check(&mk_req(), &resp);
        assert!(f.is_empty());
    }

    #[test]
    fn reflected_xss_detects() {
        let s = ReflectedXssHeuristic;
        let mut req = mk_req();
        req.body = b"q=<script>alert(1)</script>".to_vec();
        let resp = mk_resp(vec![], b"<html><script>alert(1)</script></html>");
        let f = s.check(&req, &resp);
        assert!(f.iter().any(|x| x.id == "reflected_xss_heuristic/reflected"));
    }
}