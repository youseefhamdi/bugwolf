// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-lib-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

pub mod request_engine;
pub mod parsers;
pub mod scanner_core;
pub mod gate;
pub mod journal;
pub mod hash;
pub mod fuzzer;
pub mod taint;
pub mod destructive_gate;
pub mod skill_loader;

pub fn version() -> &'static str {
    "0.1.0"
}