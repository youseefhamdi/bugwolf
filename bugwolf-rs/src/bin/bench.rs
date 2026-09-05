// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-bench-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use std::time::Instant;

use bugwolf_rs::hash::sha256;

fn main() {
    let mut iterations: u64 = 10000;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--iterations" {
            if let Some(v) = args.next() {
                iterations = v.parse().unwrap_or(10000);
            }
        }
    }

    let payload = b"the quick brown fox jumps over the lazy dog";
    let start = Instant::now();
    let mut acc = [0u8; 32];
    for i in 0..iterations {
        let mut buf = Vec::with_capacity(payload.len() + 8);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&(i as u64).to_be_bytes());
        acc = sha256(&buf);
    }
    let elapsed = start.elapsed();
    println!(
        "bench: iterations={} elapsed_ms={} last_hash={:02x?}...",
        iterations,
        elapsed.as_millis(),
        &acc[..8]
    );
}