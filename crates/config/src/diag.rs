use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Diag {
    pub level: Level,
    /// `INV-n` for the design invariants, `E-*` for structural errors.
    pub code: &'static str,
    pub msg: String,
}

#[derive(Debug, Clone, Default)]
pub struct Diagnostics(pub Vec<Diag>);

impl Diagnostics {
    pub fn error(&mut self, code: &'static str, msg: impl Into<String>) {
        self.0.push(Diag { level: Level::Error, code, msg: msg.into() });
    }

    pub fn warn(&mut self, code: &'static str, msg: impl Into<String>) {
        self.0.push(Diag { level: Level::Warning, code, msg: msg.into() });
    }

    pub fn has_errors(&self) -> bool {
        self.0.iter().any(|d| d.level == Level::Error)
    }

    pub fn extend(&mut self, other: Diagnostics) {
        self.0.extend(other.0);
    }

    pub fn errors(&self) -> impl Iterator<Item = &Diag> {
        self.0.iter().filter(|d| d.level == Level::Error)
    }
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l = match self.level {
            Level::Error => "error",
            Level::Warning => "warning",
        };
        write!(f, "{l}[{}]: {}", self.code, self.msg)
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for d in &self.0 {
            writeln!(f, "{d}")?;
        }
        Ok(())
    }
}
