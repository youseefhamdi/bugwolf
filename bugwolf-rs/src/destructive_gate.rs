// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-destructive_gate-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use crate::hash::{constant_time_eq, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructiveKind {
    StateChange,
    DataExfil,
    Persistence,
    DenialOfService,
    FileSystem,
}

#[derive(Debug, Clone)]
pub struct Primitive {
    pub name: String,
    pub kind: DestructiveKind,
    pub opt_in_key: &'static str,
}

#[derive(Debug)]
pub struct DestructiveRegistry {
    pub primitives: Vec<Primitive>,
    granted: bool,
}

#[derive(Debug)]
pub enum GateError {
    NotRegistered(String),
    RequiresOptIn { key: &'static str },
    BadSecret,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::NotRegistered(n) => write!(f, "primitive {} not registered", n),
            GateError::RequiresOptIn { key } => write!(f, "requires opt-in key {}", key),
            GateError::BadSecret => write!(f, "bad secret"),
        }
    }
}

impl std::error::Error for GateError {}

impl DestructiveRegistry {
    pub fn new() -> Self {
        // DESTRUCTIVE-CAPABILITY: registry ships empty; no primitives enabled by default.
        DestructiveRegistry {
            primitives: Vec::new(),
            granted: false,
        }
    }

    pub fn register(&mut self, p: Primitive) {
        self.primitives.push(p);
    }

    pub fn grant_opt_in(&mut self, opt_in_key: &str) -> Result<(), GateError> {
        // Pre-shared secret SHA-256("bugwolf-destructive-opt-in-v1")
        let expected = sha256(b"bugwolf-destructive-opt-in-v1");
        let provided = sha256(opt_in_key.as_bytes());
        if !constant_time_eq(&expected, &provided) {
            return Err(GateError::BadSecret);
        }
        self.granted = true;
        Ok(())
    }

    pub fn allow(&mut self, name: &str) -> Result<&Primitive, GateError> {
        let p = self
            .primitives
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| GateError::NotRegistered(name.to_string()))?;
        if !self.granted {
            return Err(GateError::RequiresOptIn { key: p.opt_in_key });
        }
        Ok(p)
    }
}

impl Default for DestructiveRegistry {
    fn default() -> Self {
        DestructiveRegistry::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_empty_by_default() {
        let r = DestructiveRegistry::new();
        assert!(r.primitives.is_empty());
        assert!(!r.granted);
    }

    #[test]
    fn allow_unknown_returns_error() {
        let mut r = DestructiveRegistry::new();
        let err = r.allow("ghost").unwrap_err();
        assert!(matches!(err, GateError::NotRegistered(_)));
    }

    #[test]
    fn allow_registered_without_optin_returns_error() {
        let mut r = DestructiveRegistry::new();
        r.register(Primitive {
            name: "rce.pwn".into(),
            kind: DestructiveKind::StateChange,
            opt_in_key: "OPSEC_KEY",
        });
        let err = r.allow("rce.pwn").unwrap_err();
        match err {
            GateError::RequiresOptIn { key } => assert_eq!(key, "OPSEC_KEY"),
            _ => panic!("expected RequiresOptIn"),
        }
    }

    #[test]
    fn opt_in_requires_correct_secret() {
        let mut r = DestructiveRegistry::new();
        r.register(Primitive {
            name: "x".into(),
            kind: DestructiveKind::DataExfil,
            opt_in_key: "K",
        });
        // Wrong secret
        assert!(matches!(r.grant_opt_in("nope"), Err(GateError::BadSecret)));
        // Correct secret (the pre-shared phrase)
        r.grant_opt_in("bugwolf-destructive-opt-in-v1").unwrap();
        assert!(r.allow("x").is_ok());
    }
}