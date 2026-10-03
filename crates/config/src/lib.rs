//! Octopus configuration: the router.toml schema, secrets, interface
//! resolution and the compile-time invariants.

pub mod check;
pub mod diag;
pub mod fcap;
pub mod ifmap;
pub mod model;
pub mod schema;
pub mod secrets;

pub use diag::{Diag, Diagnostics, Level};
pub use model::{Endpoint, Net, Router, WanIf};
pub use schema::Config;
pub use secrets::Secrets;

/// Parse router.toml text.
pub fn parse(text: &str) -> Result<Config, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}
