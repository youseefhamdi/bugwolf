// bugwolf-rs — Rust core
// SCHEMA: bugwolf-rs-skill_loader-v1
// ## Source: (no external port; original work for Phase 4.1)
// ## License: BugWolf internal
// ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub license: Option<String>,
    pub body: String,
}

#[derive(Debug)]
pub enum SkillError {
    Io(String),
    MissingField(&'static str),
    NoFrontmatter,
    Format(String),
}

impl std::fmt::Display for SkillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkillError::Io(s) => write!(f, "io: {}", s),
            SkillError::MissingField(s) => write!(f, "missing required field: {}", s),
            SkillError::NoFrontmatter => write!(f, "no frontmatter found"),
            SkillError::Format(s) => write!(f, "format: {}", s),
        }
    }
}

impl std::error::Error for SkillError {}

pub fn parse(text: &str) -> Result<Skill, SkillError> {
    if !text.starts_with("---\n") && text != "---\n" && !text.starts_with("---\r\n") {
        return Err(SkillError::NoFrontmatter);
    }
    let body_offset = if text.starts_with("---\r\n") {
        5
    } else {
        4
    };
    let after_open = &text[body_offset..];
    let close_seq = if text.starts_with("---\r\n") {
        "\r\n---\r\n"
    } else {
        "\n---\n"
    };
    let close = after_open
        .find(close_seq)
        .ok_or_else(|| SkillError::Format("no closing ---".into()))?;
    let fm = &after_open[..close];
    let body = after_open[close + close_seq.len()..].to_string();

    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut license: Option<String> = None;

    for line in fm.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (k, v) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        let v = v.trim_matches('"').to_string();
        match k {
            "name" => name = Some(v),
            "description" => description = Some(v),
            "license" => license = Some(v),
            _ => {}
        }
    }

    let name = name.ok_or(SkillError::MissingField("name"))?;
    let description = description.ok_or(SkillError::MissingField("description"))?;

    Ok(Skill {
        name,
        description,
        license,
        body,
    })
}

pub fn load_dir(dir: &Path) -> Result<Vec<Skill>, SkillError> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir).map_err(|e| SkillError::Io(e.to_string()))?;
    for ent in entries {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !text.starts_with("---\n") && !text.starts_with("---\r\n") {
            continue;
        }
        match parse(&text) {
            Ok(s) => out.push(s),
            Err(_) => continue,
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_frontmatter() {
        let text = "---\nname: my-skill\ndescription: does a thing\nlicense: MIT\n---\nbody here\n";
        let s = parse(text).unwrap();
        assert_eq!(s.name, "my-skill");
        assert_eq!(s.description, "does a thing");
        assert_eq!(s.license.as_deref(), Some("MIT"));
        assert_eq!(s.body, "body here\n");
    }

    #[test]
    fn missing_required_field() {
        let text = "---\nname: my-skill\n---\nbody\n";
        match parse(text).unwrap_err() {
            SkillError::MissingField("description") => {}
            e => panic!("expected MissingField(description), got {:?}", e),
        }
    }

    #[test]
    fn no_frontmatter_returns_error() {
        let text = "just a body, no frontmatter\n";
        assert!(matches!(parse(text).unwrap_err(), SkillError::NoFrontmatter));
    }

    #[test]
    fn multiline_body_preserved() {
        let text = "---\nname: a\ndescription: b\n---\nfirst\nsecond\nthird\n";
        let s = parse(text).unwrap();
        assert_eq!(s.body, "first\nsecond\nthird\n");
    }

    #[test]
    fn load_dir_skips_non_md_and_no_frontmatter() {
        let dir = std::env::temp_dir().join("bugwolf_rs_skill_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("good.md"), "---\nname: g\ndescription: d\n---\nbody\n").unwrap();
        fs::write(dir.join("skip.txt"), "---\nname: x\ndescription: y\n---\n").unwrap();
        fs::write(dir.join("nofm.md"), "no frontmatter\n").unwrap();
        let v = load_dir(&dir).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "g");
        let _ = fs::remove_dir_all(&dir);
    }
}