// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-taint-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use crate::scanner_core::Severity;

#[derive(Debug, Clone)]
pub struct TaintLabel {
    pub source: String,
    pub source_id: u64,
    pub path: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaintSet(pub u64);

impl TaintSet {
    pub fn empty() -> Self {
        TaintSet(0)
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn add(&mut self, label: TaintLabel) -> u64 {
        let id = label.source_id;
        if id >= 64 {
            return 64; // sentinel: overflow
        }
        self.0 |= 1u64 << id;
        id
    }

    pub fn intersects(&self, other: &TaintSet) -> bool {
        (self.0 & other.0) != 0
    }
}

#[derive(Debug, Clone)]
pub struct Sink {
    pub name: String,
    pub category: String,
    pub required_label: TaintSet,
}

impl Sink {
    pub fn matches(&self, labels: &TaintSet) -> bool {
        self.required_label.intersects(labels) || self.required_label.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub sink: String,
    pub source: String,
    pub path: Vec<String>,
    pub severity: Severity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_taint_set() {
        let s = TaintSet::empty();
        assert!(s.is_empty());
    }

    #[test]
    fn add_labels_and_intersect() {
        let mut a = TaintSet::empty();
        a.add(TaintLabel { source: "param".into(), source_id: 1, path: vec![], confidence: 1.0 });
        let mut b = TaintSet::empty();
        b.add(TaintLabel { source: "param".into(), source_id: 2, path: vec![], confidence: 1.0 });
        assert!(!a.intersects(&b));
        let mut c = TaintSet::empty();
        c.add(TaintLabel { source: "param".into(), source_id: 1, path: vec![], confidence: 1.0 });
        assert!(a.intersects(&c));
    }

    #[test]
    fn overflow_returns_specific_id() {
        let mut s = TaintSet::empty();
        let id = s.add(TaintLabel { source: "x".into(), source_id: 70, path: vec![], confidence: 1.0 });
        assert_eq!(id, 64);
        assert!(s.is_empty()); // overflow should not have set any bit
    }

    #[test]
    fn sink_matches_works() {
        let mut labels = TaintSet::empty();
        labels.add(TaintLabel { source: "q".into(), source_id: 5, path: vec![], confidence: 1.0 });
        let sink = Sink {
            name: "sql.exec".into(),
            category: "sqli".into(),
            required_label: TaintSet(1u64 << 5),
        };
        assert!(sink.matches(&labels));
        let labels2 = TaintSet::empty();
        let sink2 = Sink {
            name: "log".into(),
            category: "log".into(),
            required_label: TaintSet::empty(),
        };
        assert!(sink2.matches(&labels2));
    }

    #[test]
    fn add_64_labels_capacity() {
        let mut s = TaintSet::empty();
        for i in 0..63u64 {
            s.add(TaintLabel { source: format!("s{}", i), source_id: i, path: vec![], confidence: 1.0 });
        }
        assert!(!s.is_empty());
        // adding a 64th with id=63 fills the last bit
        s.add(TaintLabel { source: "s63".into(), source_id: 63, path: vec![], confidence: 1.0 });
        assert_eq!(s.0, u64::MAX);
    }
}