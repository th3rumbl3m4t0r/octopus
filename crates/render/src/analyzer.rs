//! /etc/octopus/analyzer.toml (phase 6): each rule's FCAP expression,
//! already translated to a pcap filter, on its network's interface.

use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::fcap::to_pcap;
use octopus_config::schema::{AnalyzerAction, Ipv6Mode};

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
    let list = |v: &[String]| v.iter().map(|x| q(x)).collect::<Vec<_>>().join(", ");
    // never blocked, whatever a rule matches
    let _ = writeln!(s, "protected = [{}]", list(&crate::services::protected(r)));
    let ours: Vec<String> = r
        .internal_v4()
        .iter()
        .map(|p| p.to_string())
        .chain((c.ipv6.mode == Ipv6Mode::Pd).then(|| octopus_config::model::ula_prefix(c).to_string()))
        .collect();
    for a in &c.analyzer.rules {
        let Ok(mut filter) = to_pcap(&a.fcap) else { continue };
        // blocks only for sources that can be there: a network's own range,
        // or for the WAN anything but ours (bpf sees forged sources before pf)
        let (ifname, inside, outside) = if a.network == "wan" {
            (r.wan.as_ref().map(|w| w.egress.clone()).unwrap_or_default(), vec![], ours.clone())
        } else if let Some((_, n)) = r.net(&a.network) {
            let mut inside = vec![n.prefix.to_string()];
            inside.extend(n.v6.map(|v| v.ula.trunc().to_string()));
            // a tier sharing its interface: only its own traffic
            if let Some(p) = n.src {
                let own6 = r.v6_owner(&n.ifname).is_some_and(|o| o.name == n.name);
                filter = format!("(net {p}{}) and ({filter})", if own6 { " or ip6" } else { "" });
            }
            (n.ifname.clone(), inside, vec![])
        } else {
            continue;
        };
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
        let _ = writeln!(s, "inside = [{}]\noutside = [{}]", list(&inside), list(&outside));
    }
    g.file("/etc/octopus/analyzer.toml", s, Subsystem::Analyzer);
}
