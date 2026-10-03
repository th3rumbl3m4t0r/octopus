//! Unified diffs between a rendered generation and the live files. Files
//! carrying secrets are never shown (INV-8), only that they changed.

use std::fs;

use octopus_render::Generation;
use similar::TextDiff;

pub fn render_vs_live(g: &Generation) -> String {
    let mut out = String::new();
    for f in &g.files {
        let live = fs::read_to_string(&f.path).ok();
        out += &one(&f.path, live.as_deref(), Some(&f.content), f.secret);
    }
    // files octopus owns that this generation no longer has
    if let Ok(rd) = fs::read_dir("/etc") {
        let mut gone: Vec<String> = rd
            .flatten()
            .map(|e| format!("/etc/{}", e.file_name().to_string_lossy()))
            .filter(|p| crate::gens::owned_by_glob(p) && g.get(p).is_none())
            .collect();
        gone.sort();
        for p in gone {
            out += &format!("--- {p} (removed: not in router.toml)\n");
        }
    }
    out
}

/// Diff of one file; empty when equal.
pub fn one(path: &str, old: Option<&str>, new: Option<&str>, secret: bool) -> String {
    if old == new {
        return String::new();
    }
    if secret {
        return match (old, new) {
            (None, _) => format!("+++ {path} (new, contains secrets: not shown)\n"),
            (_, None) => format!("--- {path} (removed, contains secrets)\n"),
            _ => format!("~~~ {path} (changed, contains secrets: not shown)\n"),
        };
    }
    let o = old.unwrap_or("");
    let n = new.unwrap_or("");
    let a = if old.is_some() { format!("a{path}") } else { "/dev/null".into() };
    let b = if new.is_some() { format!("b{path}") } else { "/dev/null".into() };
    TextDiff::from_lines(o, n).unified_diff().context_radius(3).header(&a, &b).to_string()
}
