//! /etc/octopus/power.json for `octopus power`: the UPS feed and its delays
//! for the guard (octopus_power), and whether the boot repairs a failed file
//! system check, which `octopus boot` and `supervise` keep in /etc/rc.

use octopus_config::Router;
use serde_json::json;

use crate::{Generation, Service, Subsystem};

pub const POWER_CONF: &str = "/etc/octopus/power.json";

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let p = r.cfg.power.as_ref();
    g.services.push(Service {
        name: "octopus_power".into(),
        enabled: p.is_some_and(|p| p.ups.is_some()),
        flags: None,
        subsystem: Subsystem::Net,
        restart: true,
    });
    let Some(p) = p else { return };
    let s = serde_json::to_string_pretty(&json!({
        "ups": p.ups, "protect_after": p.protect_after, "root_after": p.root_after,
        "restore_after": p.restore_after, "fsck_repair": p.fsck_repair,
    }))
    .unwrap_or_default()
        + "\n";
    g.file(POWER_CONF, s, Subsystem::Net);
}
