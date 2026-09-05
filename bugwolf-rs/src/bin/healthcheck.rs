// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-healthcheck-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let addr = "127.0.0.1:6379";
    let timeout = Duration::from_millis(500);

    match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
        Ok(mut s) => {
            let _ = s.set_read_timeout(Some(timeout));
            let _ = s.set_write_timeout(Some(timeout));
            // STUB-SAFE: write PING and read response; never panic.
            if s.write_all(b"PING\r\n").is_err() {
                println!("unavailable");
                std::process::exit(0);
            }
            let mut buf = [0u8; 64];
            match s.read(&mut buf) {
                Ok(n) if n > 0 => {
                    println!("OK");
                    std::process::exit(0);
                }
                _ => {
                    println!("unavailable");
                    std::process::exit(0);
                }
            }
        }
        Err(_) => {
            // STUB-SAFE: connection refused → "unavailable", exit 0 (NOT 1).
            println!("unavailable");
            std::process::exit(0);
        }
    }
}