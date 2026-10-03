//! /etc/octopus/analyzer.toml (phase 6): each rule's FCAP expression,
//! already translated to a pcap filter, on its network's interface.

use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::fcap::to_pcap;
use octopus_config::schema::AnalyzerAction;

use crate::{Generation, Service, Subsystem, header};

pub const PCAP_DIR: &str = "/var/octopus/pcap";

/// octopus-analyzer runs: enabled, with rules.
pub fn running(r: &Router) -> bool {
    r.cfg.analyzer.enabled && !r.cfg.analyzer.rules.is_empty()
}

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let c = &r.cfg;
    g.services.push(Service {
        name: "octopus_analyzer".into(),
        enabled: running(r),
        flags: None,
        subsystem: Subsystem::Analyzer,
        restart: true,
    });
    if !running(r) {
        return;
    }
    let q = |s: &str| toml::Value::String(s.to_string()).to_string();
    let mut s = header("#", &["octopus-analyzer: BPF filters are locked (BIOCLOCK) before it drops privileges"]);
    let _ =
        writeln!(s, "user = \"_octoflow\"\npcap_dir = \"{PCAP_DIR}\"\npfhelper = \"{}\"", crate::dns::PFHELPER_SOCKET);
    for a in &c.analyzer.rules {
        let ifname = if a.network == "wan" {
            r.wan.as_ref().map(|w| w.egress.clone()).unwrap_or_default()
        } else {
            r.net(&a.network).map(|(_, n)| n.ifname.clone()).unwrap_or_default()
        };
        let Ok(filter) = to_pcap(&a.fcap) else { continue };
        let _ = writeln!(
            s,
            "\n[[rules]]\nname = {}\ninterface = {}\nfcap = {}\nfilter = {}",
            q(&a.name),
            q(&ifname),
            q(&a.fcap),
            q(&filter)
        );
        if let Some(re) = &a.regex {
            let _ = writeln!(s, "regex = {}", q(re));
        }
        let action = if a.action == AnalyzerAction::Block { "block" } else { "log" };
        let _ = writeln!(s, "action = \"{action}\"\nblock_for = {}\npcap = {}", a.block_for, a.pcap);
    }
    g.file("/etc/octopus/analyzer.toml", s, Subsystem::Analyzer);
}
