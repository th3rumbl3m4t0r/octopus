//! The router.toml schema. Every struct denies unknown fields so a typo is a
//! compile error instead of a silently ignored setting.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub system: System,
    /// Physical ports by role. Roles are bound to MAC addresses; the OpenBSD
    /// names (`igc0`, `vio0`, ...) are resolved at build time.
    #[serde(default)]
    pub interfaces: BTreeMap<String, Interface>,
    pub wan: Option<Wan>,
    /// The house ports: one bridge for every tier that names no port of its
    /// own. Any device in any port; the tier comes from its MAC (DHCP) or,
    /// for Wi-Fi, from the VLAN its access point tags it with.
    pub lan: Option<Lan>,
    /// Address tiers (`[[networks]]` in older files): each a range with the
    /// router in it, its devices chosen by MAC, cable or Wi-Fi VLAN.
    #[serde(default, rename = "tiers", alias = "networks")]
    pub networks: Vec<Network>,
    #[serde(default)]
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub tables: Vec<Table>,
    #[serde(default)]
    pub forwards: Vec<Forward>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub links: Vec<Link>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default)]
    pub ntp: Ntp,
    #[serde(default)]
    pub ssh: Ssh,
    #[serde(default)]
    pub logging: Logging,
    #[serde(default)]
    pub web: Web,
    #[serde(default)]
    pub ipv6: Ipv6,
    pub traffic: Option<Traffic>,
    pub wireguard: Option<WireGuard>,
    /// Internal reverse-proxy sites served by nginx (phase 2).
    #[serde(default)]
    pub vhosts: Vec<Vhost>,
    /// The servers networks' egress proxy (phase 5).
    pub proxy: Option<Proxy>,
    /// Passive analysis (phase 6): standing rules, off unless enabled.
    #[serde(default)]
    pub analyzer: Analyzer,
    /// Wi-Fi on OpenWrt access points that octopus configures.
    pub wifi: Option<Wifi>,
}

/// Wi-Fi: the networks (SSIDs) and the access points that broadcast them.
/// The access points run OpenWrt and are set up over SSH with the router's
/// key (docs/operations.md: assimilating an access point); `apply` pushes
/// their settings, and rollback pushes the previous ones.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Wifi {
    /// Regulatory domain (two letters, e.g. `CZ`): which channels and how
    /// much power are legal. Default: from `system.timezone`
    /// (Europe/Prague: CZ).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(default)]
    pub networks: Vec<WifiNetwork>,
    #[serde(default)]
    pub aps: Vec<AccessPoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WifiNetwork {
    pub ssid: String,
    /// The tier its clients join. One that isn't the access point's own
    /// tier reaches it as a VLAN, so it needs a `vlan`.
    #[serde(rename = "tier", alias = "network")]
    pub network: String,
    #[serde(default = "default_wifi_security")]
    pub security: WifiSecurity,
    /// `secret:<key>` reference to the passphrase (8 to 63 characters);
    /// the web UI sets it without ever showing it.
    pub password: Option<String>,
    /// Bands it is on.
    #[serde(default = "default_bands")]
    pub bands: Vec<Band>,
    #[serde(default)]
    pub hidden: bool,
    /// Clients can't reach each other. Default: on for guest networks.
    pub isolate: Option<bool>,
    /// Only on these access points (default: all of them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aps: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WifiSecurity {
    /// WPA2-PSK and WPA3-SAE together: every device, the newer ones safer.
    Wpa2Wpa3,
    /// WPA3-SAE only.
    Wpa3,
    /// WPA2-PSK only, for old devices.
    Wpa2,
    /// No password (guests with a portal elsewhere, or none).
    Open,
}

fn default_wifi_security() -> WifiSecurity {
    WifiSecurity::Wpa2Wpa3
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
pub enum Band {
    #[serde(rename = "2g")]
    G2,
    #[serde(rename = "5g")]
    G5,
}

impl Band {
    pub fn name(self) -> &'static str {
        match self {
            Band::G2 => "2g",
            Band::G5 => "5g",
        }
    }
}

fn default_bands() -> Vec<Band> {
    vec![Band::G2, Band::G5]
}

/// An OpenWrt access point.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessPoint {
    pub name: String,
    /// Its [[hosts]] entry: the address octopus reaches it on (a DHCP
    /// reservation by its mac) and the network its port is in.
    pub host: String,
    /// `auto` or a channel number.
    #[serde(default = "auto_channel")]
    pub channel_2g: String,
    /// `auto` or a channel number.
    #[serde(default = "auto_channel")]
    pub channel_5g: String,
    pub description: Option<String>,
}

fn auto_channel() -> String {
    "auto".into()
}

impl Wifi {
    /// The regulatory domain: as set, else the time zone's country.
    pub fn country(&self, timezone: &str) -> Option<String> {
        if self.country.is_empty() { zone_country(timezone).map(str::to_string) } else { Some(self.country.clone()) }
    }
}

/// The country of a time zone, for the Wi-Fi regulatory domain (the zones
/// of one country only; anything else must be set).
pub fn zone_country(tz: &str) -> Option<&'static str> {
    const ZONES: &[(&str, &str)] = &[
        ("Europe/Prague", "CZ"),
        ("Europe/Bratislava", "SK"),
        ("Europe/Vienna", "AT"),
        ("Europe/Berlin", "DE"),
        ("Europe/Warsaw", "PL"),
        ("Europe/Budapest", "HU"),
        ("Europe/Paris", "FR"),
        ("Europe/London", "GB"),
        ("Europe/Amsterdam", "NL"),
        ("Europe/Brussels", "BE"),
        ("Europe/Luxembourg", "LU"),
        ("Europe/Zurich", "CH"),
        ("Europe/Rome", "IT"),
        ("Europe/Madrid", "ES"),
        ("Europe/Lisbon", "PT"),
        ("Europe/Dublin", "IE"),
        ("Europe/Copenhagen", "DK"),
        ("Europe/Stockholm", "SE"),
        ("Europe/Oslo", "NO"),
        ("Europe/Helsinki", "FI"),
        ("Europe/Tallinn", "EE"),
        ("Europe/Riga", "LV"),
        ("Europe/Vilnius", "LT"),
        ("Europe/Ljubljana", "SI"),
        ("Europe/Zagreb", "HR"),
        ("Europe/Belgrade", "RS"),
        ("Europe/Bucharest", "RO"),
        ("Europe/Sofia", "BG"),
        ("Europe/Athens", "GR"),
        ("Europe/Kyiv", "UA"),
        ("Europe/Kiev", "UA"),
        ("Europe/Istanbul", "TR"),
        ("America/New_York", "US"),
        ("America/Chicago", "US"),
        ("America/Denver", "US"),
        ("America/Los_Angeles", "US"),
        ("America/Toronto", "CA"),
        ("America/Vancouver", "CA"),
        ("Asia/Tokyo", "JP"),
        ("Australia/Sydney", "AU"),
    ];
    ZONES.iter().find(|(z, _)| *z == tz).map(|(_, c)| *c)
}

impl WifiNetwork {
    /// Isolated clients: as set, else on for guest networks.
    pub fn isolated(&self, kind: Option<Kind>) -> bool {
        self.isolate.unwrap_or(kind == Some(Kind::Guest))
    }

    /// Broadcast by this access point?
    pub fn on(&self, ap: &str) -> bool {
        self.aps.is_empty() || self.aps.iter().any(|a| a == ap)
    }
}

/// octopus-analyzer's standing rules: FCAP filter, payload regex, pcaps,
/// optional block through the pf helper's lab_block table. The web UI's ad
/// hoc captures don't need any of this.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Analyzer {
    /// Run octopus-analyzer with the rules below (off: the rules are kept,
    /// nothing runs).
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<AnalyzerRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerRule {
    pub name: String,
    /// A network (its interface) or "wan".
    pub network: String,
    /// Arbor-style FCAP expression (packet fields only).
    pub fcap: String,
    /// Regular expression on the payload, if any.
    pub regex: Option<String>,
    #[serde(default = "default_analyzer_action")]
    pub action: AnalyzerAction,
    /// Seconds a blocked source stays in lab_block.
    #[serde(default = "default_block_for")]
    pub block_for: u32,
    /// Keep matching packets in ring-buffered pcap files.
    #[serde(default = "yes")]
    pub pcap: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AnalyzerAction {
    Log,
    Block,
}

fn default_analyzer_action() -> AnalyzerAction {
    AnalyzerAction::Log
}
fn default_block_for() -> u32 {
    3600
}

/// octopus-proxy on the router: servers' outbound 80/443 is diverted to it,
/// origins' certificates are verified, and only listed hosts pass.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    #[serde(default)]
    pub allow: Vec<ProxyAllow>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyAllow {
    pub network: String,
    /// Host names; `*.example.com` for every name under it.
    pub hosts: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct System {
    pub hostname: String,
    /// Internal DNS zone, for example `home.arpa`.
    pub domain: String,
    pub openbsd_release: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// pf state table limit.
    #[serde(default = "default_states")]
    pub max_states: u32,
    /// pf table entry limit (the pfSense import carries large allowlists).
    #[serde(default = "default_table_entries")]
    pub max_table_entries: u32,
}

fn default_timezone() -> String {
    "UTC".into()
}
fn default_states() -> u32 {
    100_000
}
fn default_table_entries() -> u32 {
    400_000
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub mac: String,
    /// Optional fixed name. Used only when the MAC can't be resolved, e.g.
    /// when compiling off the router; a mismatch with the MAC is an error.
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Wan {
    /// Role in `[interfaces]`.
    pub interface: String,
    pub vlan: Option<u16>,
    /// 802.1p priority for frames on the WAN VLAN (`txprio`).
    pub vlan_prio: Option<u8>,
    /// Exactly one of `pppoe`, `dhcp = true` and `static`.
    pub pppoe: Option<Pppoe>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dhcp: bool,
    #[serde(rename = "static")]
    pub static_: Option<StaticWan>,
    #[serde(default = "default_wan_mtu")]
    pub mtu: u16,
    /// TCP MSS clamp; defaults to mtu - 40.
    pub mss: Option<u16>,
    /// Answer ICMP echo on the WAN address.
    #[serde(default)]
    pub allow_ping: bool,
}

fn default_wan_mtu() -> u16 {
    1500
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Pppoe {
    /// `secret:<key>` reference.
    pub user: String,
    /// `secret:<key>` reference.
    pub password: String,
    #[serde(default = "default_pppoe_auth")]
    pub auth: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticWan {
    #[schemars(with = "String")]
    pub address: Ipv4Net,
    pub gateway: Ipv4Addr,
}

/// The WAN mode, from whichever of the three fields is set.
#[derive(Debug, Clone)]
pub enum WanMode {
    Pppoe { user: String, password: String, auth: String },
    Dhcp,
    Static { address: Ipv4Net, gateway: Ipv4Addr },
}

impl Wan {
    /// None unless exactly one mode is set (the checker reports that).
    pub fn mode(&self) -> Option<WanMode> {
        match (&self.pppoe, self.dhcp, &self.static_) {
            (Some(p), false, None) => {
                Some(WanMode::Pppoe { user: p.user.clone(), password: p.password.clone(), auth: p.auth.clone() })
            }
            (None, true, None) => Some(WanMode::Dhcp),
            (None, false, Some(s)) => Some(WanMode::Static { address: s.address, gateway: s.gateway }),
            _ => None,
        }
    }
}

fn default_pppoe_auth() -> String {
    "chap".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Router and infrastructure management: full access, the only place sshd listens.
    Mgmt,
    /// Personal devices: internet plus router services.
    Lan,
    /// Servers: router services, octopus-proxy for 80/443 and declared links only.
    Servers,
    /// Guests: the internet plus DNS, DHCP and NTP from the router; nothing
    /// internal, not even the vhosts. Wi-Fi isolates guest clients too.
    Guest,
    /// Everything allowed; the router managed only where [[rules]] allow it.
    /// The policy is the rules (tiers).
    Open,
}

fn default_kind() -> Kind {
    Kind::Open
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Mgmt => "mgmt",
            Kind::Lan => "lan",
            Kind::Servers => "servers",
            Kind::Guest => "guest",
            Kind::Open => "open",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Bulk,
    Default,
    Streaming,
    Realtime,
}

impl Class {
    pub const ALL: [Class; 4] = [Class::Bulk, Class::Default, Class::Streaming, Class::Realtime];

    pub fn name(self) -> &'static str {
        match self {
            Class::Bulk => "bulk",
            Class::Default => "default",
            Class::Streaming => "streaming",
            Class::Realtime => "realtime",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Lan {
    /// Roles in `[interfaces]`.
    pub ports: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub name: String,
    /// Role in `[interfaces]`, for a tier on a port of its own; or `bridge`;
    /// or neither: the tier is on the house ports (`[lan]`), untagged or as
    /// its `vlan` on every one of them.
    pub interface: Option<String>,
    /// Roles bridged into one layer-2 network (veb(4); the router's address
    /// is on a vport(4)). For several ports without VLANs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridge: Vec<String>,
    /// Tag on `interface`, or on every port of `bridge` (a network sharing
    /// the ports of an untagged bridge, e.g. guests on the same access
    /// points); untagged when absent.
    pub vlan: Option<u16>,
    /// Router address and prefix, e.g. `192.168.1.1/24`.
    #[schemars(with = "String")]
    pub address: Ipv4Net,
    /// MAC addresses and prefixes (`bc:24:11` for Proxmox) whose devices
    /// get their address from this tier on the house ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macs: Vec<String>,
    /// Every other device on a cable (the house ports, untagged) gets its
    /// address here.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub wired: bool,
    /// `open` (tiers): everything allowed, the router managed only where
    /// [[rules]] allow it; the policy is the rules. `mgmt`, `lan`, `servers`,
    /// `guest`: the older fixed policies.
    #[serde(default = "default_kind")]
    pub kind: Kind,
    pub class: Option<Class>,
    pub description: Option<String>,
    pub dhcp: Option<Dhcp>,
    /// IPv6 on this network when [ipv6] is on (default true).
    pub ipv6: Option<bool>,
    /// Which /64 of the delegated prefix (and of the ULA) this network gets.
    /// Defaults to its position in the file; set it to keep addresses
    /// stable when networks are added or removed.
    pub ipv6_slot: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dhcp {
    /// One range; `ranges` for several.
    pub range: Option<[Ipv4Addr; 2]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<[Ipv4Addr; 2]>,
    #[serde(default = "default_lease")]
    pub lease_time: u32,
    #[serde(default = "default_max_lease")]
    pub max_lease_time: u32,
}

impl Dhcp {
    pub fn all_ranges(&self) -> Vec<[Ipv4Addr; 2]> {
        self.range.iter().copied().chain(self.ranges.iter().copied()).collect()
    }
}

fn default_lease() -> u32 {
    7200
}
fn default_max_lease() -> u32 {
    86400
}

/// A known device: DNS name in the internal zone, PTR, and a DHCP
/// reservation when `mac` is set.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub name: String,
    /// Its tier: from `ip` (the tier whose range holds it) when absent.
    #[serde(rename = "tier", alias = "network", skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Table {
    pub name: String,
    #[schemars(with = "Vec<String>")]
    pub entries: Vec<ipnet::IpNet>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Any,
    Tcp,
    Udp,
    #[serde(rename = "tcp/udp")]
    TcpUdp,
    Icmp,
    Gre,
    Esp,
}

impl Proto {
    pub fn has_ports(self) -> bool {
        matches!(self, Proto::Tcp | Proto::Udp | Proto::TcpUdp)
    }
}

/// A WAN port forward. The only way to open an inbound path to an internal host (INV-2).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub name: String,
    pub proto: Proto,
    pub port: Ports,
    /// Source restriction: `any`, a table name, an address or a prefix.
    #[serde(default = "any")]
    pub from: String,
    pub to: Ipv4Addr,
    pub to_port: Option<u16>,
    /// NAT reflection: internal clients reaching the WAN address get redirected too.
    #[serde(default)]
    pub reflect: bool,
    #[serde(default)]
    pub log: bool,
}

fn any() -> String {
    "any".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pass,
    Block,
    Reject,
}

/// An explicit filter rule on traffic entering from `network`. Rules are
/// first-match in file order and come before the network's kind policy.
/// `from` and `to`: `any`, `self`, `internal` (every internal network),
/// `internet` (everything else), a network, host or table (`net:`, `host:`,
/// `table:` when a name is ambiguous), an address or a prefix.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Where the traffic comes in: a network, `all` (every internal
    /// network) or `wan` (from the internet; block and reject only, the way
    /// in is a forward).
    pub network: String,
    pub action: Action,
    #[serde(default = "any")]
    pub from: String,
    #[serde(default = "any")]
    pub to: String,
    #[serde(default = "proto_any")]
    pub proto: Proto,
    pub port: Option<Ports>,
    #[serde(default)]
    pub log: bool,
    pub description: Option<String>,
}

fn proto_any() -> Proto {
    Proto::Any
}

/// A direct egress exception for a `servers` network (INV-3).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub network: String,
    pub to: String,
    pub proto: Proto,
    pub port: Option<Ports>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Prefix or `default`.
    pub to: String,
    pub via: Ipv4Addr,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    #[serde(default = "default_engine")]
    pub engine: DnsEngine,
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<Upstream>,
    #[serde(default = "default_cache")]
    pub cache_size: u32,
    /// Names outside the internal zone answered locally (split horizon):
    /// each becomes a one-name primary zone.
    #[serde(default)]
    pub records: Vec<DnsRecord>,
    /// Other upstreams for listed clients (octopus-dns). Each view has its
    /// own cache and never falls back to another view's upstreams.
    #[serde(default)]
    pub views: Vec<DnsView>,
    /// Block DoH/DoT to well-known public resolvers, so clients can't go
    /// around the router's DNS (and their view).
    #[serde(default = "yes")]
    pub block_public_resolvers: bool,
    /// Names answered with an address of ours no matter what the internet
    /// says (blackholing, or pointing a name at an internal host).
    #[serde(default)]
    pub overrides: Vec<DnsOverride>,
    /// Where names an upstream refuses (Cloudflare security answers 0.0.0.0)
    /// resolve instead, e.g. an internal host that logs who asked (octopus-dns).
    pub sinkhole: Option<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsOverride {
    pub name: String,
    pub ip: IpAddr,
    /// Every name below it too.
    #[serde(default = "yes")]
    pub subdomains: bool,
    pub description: Option<String>,
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            engine: default_engine(),
            upstreams: default_upstreams(),
            cache_size: default_cache(),
            records: vec![],
            views: vec![],
            block_public_resolvers: true,
            overrides: vec![],
            sinkhole: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsView {
    pub name: String,
    pub upstreams: Vec<Upstream>,
    /// Hosts, addresses, prefixes, networks or tables. Clients are told
    /// apart by their IPv4 source address.
    pub clients: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DnsEngine {
    /// Phase A: the stock hickory-dns binary.
    Hickory,
    /// Phase B: octopus-dns, hickory-server with logging and classification.
    OctopusDns,
}

fn default_engine() -> DnsEngine {
    DnsEngine::Hickory
}
fn default_cache() -> u32 {
    50_000
}
fn yes() -> bool {
    true
}

fn default_upstreams() -> Vec<Upstream> {
    vec![
        Upstream { ip: "1.1.1.1".parse().unwrap(), tls_name: "cloudflare-dns.com".into() },
        Upstream { ip: "9.9.9.9".parse().unwrap(), tls_name: "dns.quad9.net".into() },
    ]
}

/// A DNS-over-TLS upstream. Plaintext upstreams don't exist in the schema.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub ip: IpAddr,
    pub tls_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsRecord {
    pub name: String,
    pub ip: IpAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ntp {
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default = "default_constraints")]
    pub constraints: Vec<String>,
    /// Serve time to the internal networks.
    #[serde(default = "yes")]
    pub serve: bool,
}

impl Default for Ntp {
    fn default() -> Self {
        Ntp { servers: vec!["pool.ntp.org".into()], constraints: default_constraints(), serve: true }
    }
}

fn default_constraints() -> Vec<String> {
    vec!["https://9.9.9.9".into(), "https://www.google.com".into()]
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub password_auth: bool,
    #[serde(default = "default_root_login")]
    pub root_login: String,
}

impl Default for Ssh {
    fn default() -> Self {
        Ssh { port: default_ssh_port(), password_auth: false, root_login: default_root_login() }
    }
}

fn default_ssh_port() -> u16 {
    22
}
fn default_root_login() -> String {
    "prohibit-password".into()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Logging {
    /// `udp://host[:port]`, `tcp://host[:port]` or `tls://host[:port]`.
    #[serde(default)]
    pub remote: Vec<String>,
    /// CA file that signed the TLS log server's certificate (syslogd -C).
    pub tls_ca: Option<String>,
    /// Client certificate and key for log servers that require one (-c, -k).
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Send pf's log (blocked packets, logged rules) to syslog as
    /// `filterlog`, so it reaches the remote log server too.
    #[serde(default)]
    pub pf: bool,
    /// IPFIX collector `host:port` for pflow(4).
    pub pflow: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Web {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_web_port")]
    pub port: u16,
    /// Its certificate: `services`, a leaf from the services root (once the
    /// root is set up; `octopus pki renew` keeps it current), or
    /// `self-signed`, the one install.site made, never touched (for a lab
    /// whose addresses the root doesn't cover).
    #[serde(default)]
    pub certificate: WebCertificate,
}

impl Default for Web {
    fn default() -> Self {
        Web { enabled: true, port: default_web_port(), certificate: WebCertificate::Services }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WebCertificate {
    /// A leaf from the services root, renewed daily.
    #[default]
    Services,
    /// The self-signed certificate from the install stays.
    SelfSigned,
}

fn default_web_port() -> u16 {
    8443
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ipv6 {
    #[serde(default = "default_v6_mode")]
    pub mode: Ipv6Mode,
    /// Prefix length asked for on the WAN; each network takes a /64 slot.
    #[serde(default = "default_v6_request")]
    pub request: u8,
    /// Unique local prefix (/48) for stable internal addresses (DNS, NTP);
    /// derived from the hostname when absent.
    #[schemars(with = "Option<String>")]
    pub ula: Option<ipnet::Ipv6Net>,
    /// Announce the router as DNS server in router advertisements (RDNSS).
    /// Off by default: clients keep asking over IPv4, where the DNS views
    /// can tell them apart.
    #[serde(default)]
    pub advertise_dns: bool,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Ipv6 { mode: Ipv6Mode::Off, request: default_v6_request(), ula: None, advertise_dns: false }
    }
}

fn default_v6_request() -> u8 {
    60
}

fn default_v6_mode() -> Ipv6Mode {
    Ipv6Mode::Off
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Mode {
    /// Blocked completely.
    Off,
    /// Prefix delegation on the WAN, router advertisements on the networks.
    Pd,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Traffic {
    /// Upload root rate, e.g. `22M` (about 90 % of the measured line).
    pub upload: String,
    /// Download root rate, e.g. `90M`.
    pub download: String,
    #[serde(default)]
    pub destinations: Vec<Destination>,
    #[serde(default)]
    pub ports: Vec<ClassPorts>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub class: Class,
    /// Suffix match.
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassPorts {
    pub class: Class,
    pub proto: Proto,
    pub port: Ports,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireGuard {
    pub listen_port: u16,
    /// Router tunnel address and prefix.
    #[schemars(with = "String")]
    pub address: Ipv4Net,
    /// `secret:<key>` reference.
    pub private_key: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    pub public_key: String,
    pub address: Ipv4Addr,
    /// `mgmt` or `lan`.
    pub policy: Kind,
    pub preshared_key: Option<String>,
}

/// An HTTPS site on nginx, proxied to `upstream`. Internal sites get a
/// certificate from the services intermediate; public ones (`public`,
/// `hostnames` outside the internal zone) are on the WAN too, with a
/// Let's Encrypt certificate (acme-client) or the `cert`/`key` given.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vhost {
    /// A label in the internal zone (`omada`) or a name inside it. With
    /// `hostnames` set, only the site's name in this file.
    pub name: String,
    /// The names served, when not just `name`: e.g. `app.example.com` and
    /// `git.example.com` behind Cloudflare. Inside the internal zone they
    /// share one services leaf; outside it they need `public` or `cert`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// Serve `hostnames` on the internet too: nginx on the WAN, pf opens
    /// tcp 80 and 443 there (INV-2), internal clients get the router's
    /// address for these names (split horizon).
    #[serde(default)]
    pub public: bool,
    /// Certificate (full chain) and key files on the router for the names
    /// outside the internal zone, e.g. a Cloudflare origin certificate.
    /// Without them a public site gets Let's Encrypt through acme-client.
    pub cert: Option<String>,
    pub key: Option<String>,
    /// Who may connect over the WAN: `cloudflare` (Cloudflare's published
    /// ranges; nginx then logs and forwards the visitor's address), tables,
    /// addresses or prefixes. Empty: anyone. pf applies the union of all
    /// public sites' lists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_from: Vec<String>,
    /// `http://ip:port` or `https://ip:port`.
    pub upstream: String,
    /// Check an https upstream's certificate (against `upstream_ca`, or the
    /// system store).
    #[serde(default = "yes")]
    pub verify_upstream: bool,
    /// CA file on the router for the upstream's certificate.
    pub upstream_ca: Option<String>,
    /// The name to verify (and send as SNI) when the upstream is an address:
    /// nginx checks DNS names only, never IP SANs.
    pub upstream_name: Option<String>,
    #[serde(default)]
    pub websocket: bool,
    pub description: Option<String>,
}

impl Vhost {
    pub fn fqdn(&self, domain: &str) -> String {
        if self.name.contains('.') { self.name.clone() } else { format!("{}.{domain}", self.name) }
    }

    /// Every name the site answers to.
    pub fn names(&self, domain: &str) -> Vec<String> {
        if self.hostnames.is_empty() {
            vec![self.fqdn(domain)]
        } else {
            self.hostnames.iter().map(|h| h.trim_end_matches('.').to_ascii_lowercase()).collect()
        }
    }

    /// (names in the internal zone, names outside it)
    pub fn split_names(&self, domain: &str) -> (Vec<String>, Vec<String>) {
        self.names(domain).into_iter().partition(|n| n == domain || n.ends_with(&format!(".{domain}")))
    }

    /// The outside names get their certificate from Let's Encrypt.
    pub fn acme(&self, domain: &str) -> bool {
        self.public && self.cert.is_none() && !self.split_names(domain).1.is_empty()
    }
}

/// Cloudflare's published ranges (https://www.cloudflare.com/ips/), for
/// `allow_from = ["cloudflare"]`.
pub const CLOUDFLARE: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// One port, a range `a-b`, or a comma list of both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ports(pub Vec<(u16, u16)>);

impl Ports {
    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|&(a, b)| a <= port && port <= b)
    }
}

impl fmt::Display for Ports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> =
            self.0.iter().map(|&(a, b)| if a == b { a.to_string() } else { format!("{a}-{b}") }).collect();
        f.write_str(&parts.join(","))
    }
}

impl std::str::FromStr for Ports {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let mut out = vec![];
        for part in s.split(',').map(str::trim) {
            let (a, b) = match part.split_once(['-', ':']) {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (part, part),
            };
            let a: u16 = a.parse().map_err(|_| format!("bad port {part:?}"))?;
            let b: u16 = b.parse().map_err(|_| format!("bad port {part:?}"))?;
            if a == 0 || a > b {
                return Err(format!("bad port range {part:?}"));
            }
            out.push((a, b));
        }
        Ok(Ports(out))
    }
}

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u16),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => format!("{n}").parse().map_err(serde::de::Error::custom),
            Raw::S(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

impl JsonSchema for Ports {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Ports".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": ["integer", "string"],
            "description": "A port, a range `a-b`, or a comma list of both.",
            "x-ports": true
        })
    }
}

impl Serialize for Ports {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [(a, b)] if a == b => s.serialize_u16(*a),
            _ => s.serialize_str(&self.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_country_from_the_time_zone() {
        let w = Wifi { country: String::new(), networks: vec![], aps: vec![] };
        assert_eq!(w.country("Europe/Prague").as_deref(), Some("CZ"));
        assert_eq!(w.country("UTC"), None);
        let set = Wifi { country: "DE".into(), ..w };
        assert_eq!(set.country("Europe/Prague").as_deref(), Some("DE"));
    }
}
