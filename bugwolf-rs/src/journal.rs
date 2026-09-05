// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-journal-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::hash::sha256;

pub const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub seq: u64,
    pub timestamp: i64,
    pub kind: String,
    pub payload: String,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

#[derive(Debug)]
pub struct Journal {
    pub path: PathBuf,
    pub last_hash: [u8; 32],
    pub entries: Vec<JournalEntry>,
}

#[derive(Debug)]
pub enum JournalError {
    Io(String),
    Parse(String),
    Broken {
        seq: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io(s) => write!(f, "io: {}", s),
            JournalError::Parse(s) => write!(f, "parse: {}", s),
            JournalError::Broken { seq, expected, actual } => {
                write!(
                    f,
                    "broken chain at seq {}: expected {:02x?} got {:02x?}",
                    seq, expected, actual
                )
            }
        }
    }
}

impl std::error::Error for JournalError {}

pub fn open(path: &Path) -> Result<Journal, JournalError> {
    let mut j = Journal {
        path: path.to_path_buf(),
        last_hash: GENESIS,
        entries: Vec::new(),
    };
    if path.exists() {
        let mut f = fs::File::open(path).map_err(|e| JournalError::Io(e.to_string()))?;
        let mut buf = String::new();
        f.read_to_string(&mut buf).map_err(|e| JournalError::Io(e.to_string()))?;
        for line in buf.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed = parse_line(line).ok_or_else(|| {
                JournalError::Parse(format!("bad line: {}", line))
            })?;
            j.last_hash = parsed.hash;
            j.entries.push(parsed);
        }
    } else if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| JournalError::Io(e.to_string()))?;
        }
    }
    Ok(j)
}

fn parse_line(line: &str) -> Option<JournalEntry> {
    // format: seq|ts|kind|payload|prevhex|hex
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 6 {
        return None;
    }
    let seq: u64 = parts[0].parse().ok()?;
    let ts: i64 = parts[1].parse().ok()?;
    let kind = parts[2].to_string();
    let payload = parts[3].to_string();
    let prev = hex_to_32(&parts[4])?;
    let hash = hex_to_32(&parts[5])?;
    Some(JournalEntry {
        seq,
        timestamp: ts,
        kind,
        payload,
        prev_hash: prev,
        hash,
    })
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = hex_nyb(bytes[i * 2])?;
        let lo = hex_nyb(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nyb(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl Journal {
    pub fn append(&mut self, kind: &str, payload: &str) -> Result<u64, JournalError> {
        let seq = self.entries.len() as u64 + 1;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| JournalError::Io(e.to_string()))?
            .as_secs() as i64;
        let prev = self.last_hash;
        let hash = compute_entry_hash(prev, seq, ts, kind, payload);
        let entry = JournalEntry {
            seq,
            timestamp: ts,
            kind: kind.to_string(),
            payload: payload.to_string(),
            prev_hash: prev,
            hash,
        };
        let line = format!(
            "{}|{}|{}|{}|{}|{}\n",
            entry.seq,
            entry.timestamp,
            entry.kind,
            entry.payload.replace('|', "\\|"),
            hex32(&prev),
            hex32(&hash),
        );
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| JournalError::Io(e.to_string()))?;
        f.write_all(line.as_bytes())
            .map_err(|e| JournalError::Io(e.to_string()))?;
        f.sync_data().map_err(|e| JournalError::Io(e.to_string()))?;
        self.last_hash = hash;
        self.entries.push(entry);
        Ok(seq)
    }

    pub fn verify(&self) -> Result<(), JournalError> {
        let mut prev = GENESIS;
        for e in &self.entries {
            let expected = compute_entry_hash(prev, e.seq, e.timestamp, &e.kind, &e.payload);
            if expected != e.hash {
                return Err(JournalError::Broken {
                    seq: e.seq,
                    expected,
                    actual: e.hash,
                });
            }
            if e.prev_hash != prev {
                return Err(JournalError::Broken {
                    seq: e.seq,
                    expected: prev,
                    actual: e.prev_hash,
                });
            }
            prev = e.hash;
        }
        Ok(())
    }
}

fn compute_entry_hash(
    prev: [u8; 32],
    seq: u64,
    ts: i64,
    kind: &str,
    payload: &str,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&prev);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(kind.as_bytes());
    buf.extend_from_slice(payload.as_bytes());
    sha256(&buf)
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_new() {
        let dir = std::env::temp_dir().join("bugwolf_rs_journal_test_open_creates_new");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("j.log");
        let j = open(&path).unwrap();
        assert!(j.last_hash == GENESIS);
        assert!(j.entries.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_three_and_verify() {
        let dir = std::env::temp_dir().join("bugwolf_rs_journal_test_append3");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("j.log");
        let mut j = open(&path).unwrap();
        j.append("scan.start", "host=example.com").unwrap();
        j.append("finding", "id=missing_security_headers/csp").unwrap();
        j.append("scan.end", "count=1").unwrap();
        assert_eq!(j.entries.len(), 3);
        j.verify().unwrap();
        // Reopen and verify
        let j2 = open(&path).unwrap();
        j2.verify().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tamper_detected() {
        let dir = std::env::temp_dir().join("bugwolf_rs_journal_test_tamper");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("j.log");
        let mut j = open(&path).unwrap();
        j.append("a", "one").unwrap();
        j.append("b", "two").unwrap();
        // Tamper the on-disk file: flip one byte of the second entry's payload
        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
        // second line "two" → "ttt"
        if let Some(s) = lines.get_mut(1) {
            // crude: just rewrite payload field of line 1 (after 2nd '|')
            // Easier: rewrite the whole line for test simplicity
            let parts: Vec<&str> = s.split('|').collect();
            // seq|ts|kind|payload|prevhex|hex
            let new = format!("{}|{}|{}|{}|{}|{}", parts[0], parts[1], parts[2], "tampered", parts[4], parts[5]);
            *s = new;
        }
        let tampered = lines.join("\n") + "\n";
        fs::write(&path, tampered).unwrap();
        let j2 = open(&path).unwrap();
        let err = j2.verify().unwrap_err();
        assert!(matches!(err, JournalError::Broken { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_journal_verifies() {
        let dir = std::env::temp_dir().join("bugwolf_rs_journal_test_empty");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("j.log");
        let j = open(&path).unwrap();
        j.verify().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}