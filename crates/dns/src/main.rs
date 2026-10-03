//! octopus-dns: the router's DNS service, phase B (design 11.3).
//!
//! hickory-server's Catalog does the work (file-backed primary zones, a
//! DNS-over-TLS forwarder for everything else); this wraps it to add:
//!
//! 1. one JSON log record per query (syslog, facility local5);
//! 2. destination classification: when a name matches a [[classes]] suffix,
//!    its A/AAAA answers go to octopus-pfhelper's cls_* table *before* the
//!    answer is released, so the client's first connection is classified;
//! 3. retention: classified addresses stay for max(TTL, min_retention) and
//!    each table is rewritten with `replace` every minute;
//! 4. NXDOMAIN for the DoH canary (use-application-dns.net).
//!
//! It binds port 53 as root, then drops to _octodns and pledges.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_server::Server;
use hickory_server::net::NetError;
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{Message, ResponseCode};
use hickory_server::proto::rr::{LowerName, Name, RData, Record};
use hickory_server::proto::serialize::binary::BinEncoder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::file::{FileConfig, FileZoneHandler};
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::zone_handler::{
    AxfrPolicy, Catalog, MessageResponse, MessageResponseBuilder, ZoneHandler, ZoneType,
};
use ipnet::IpNet;
use serde::Deserialize;

mod helper;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: Vec<IpAddr>,
    #[serde(default = "default_port")]
    port: u16,
    allow: Vec<IpNet>,
    zone_dir: PathBuf,
    zones: Vec<String>,
    #[serde(default)]
    nxdomain: Vec<String>,
    user: String,
    pfhelper: Option<String>,
    #[serde(default = "default_retention")]
    min_retention: u64,
    #[serde(default)]
    networks: Vec<NetName>,
    #[serde(default)]
    classes: Vec<ClassConf>,
    forward: ForwardConfig,
    /// Other upstreams for listed clients; own cache; no fallback.
    #[serde(default)]
    views: Vec<ViewConf>,
    /// octopus-collector's DNS port: every answer goes there too (phase 6).
    collector: Option<SocketAddr>,
    /// Where an upstream's refusal (0.0.0.0) points instead.
    sinkhole: Option<std::net::Ipv4Addr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewConf {
    name: String,
    clients: Vec<IpNet>,
    forward: ForwardConfig,
}

struct View {
    name: String,
    clients: Vec<IpNet>,
    catalog: Catalog,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetName {
    name: String,
    prefix: IpNet,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassConf {
    name: String,
    table: String,
    domains: Vec<String>,
}

fn default_port() -> u16 {
    53
}
fn default_retention() -> u64 {
    3600
}

#[derive(Clone)]
struct Class {
    name: String,
    table: String,
    /// lowercase, no trailing dot
    suffixes: Vec<String>,
}

struct Handler {
    /// the default view
    catalog: Catalog,
    views: Vec<View>,
    nxdomain: Vec<LowerName>,
    classes: Vec<Class>,
    nets: Vec<(String, IpNet)>,
    helper: Option<Arc<helper::Helper>>,
    /// (address, class index) -> expiry
    retained: Retained,
    min_retention: Duration,
    collector: Option<(std::net::UdpSocket, SocketAddr)>,
    sinkhole: Option<std::net::Ipv4Addr>,
}

/// An upstream's refusal: Cloudflare's security resolver answers 0.0.0.0 / ::.
/// With a sinkhole, A records point there and AAAA records go (NODATA).
/// Returns whether the answer was a refusal.
fn sinkhole(msg: &mut Message, to: Option<std::net::Ipv4Addr>) -> bool {
    let refused = msg.answers.iter().any(|r| match &r.data {
        RData::A(a) => a.0.is_unspecified(),
        RData::AAAA(a) => a.0.is_unspecified(),
        _ => false,
    });
    if refused && let Some(to) = to {
        msg.answers.retain(|r| !matches!(&r.data, RData::AAAA(a) if a.0.is_unspecified()));
        for r in msg.answers.iter_mut() {
            if let RData::A(a) = &mut r.data
                && a.0.is_unspecified()
            {
                a.0 = to;
            }
        }
    }
    refused
}

/// Captures the catalog's response so it can be inspected before release.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Option<Vec<u8>>>>);

#[async_trait::async_trait]
impl ResponseHandler for Capture {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut bytes = Vec::with_capacity(512);
        let mut enc = BinEncoder::new(&mut bytes);
        enc.set_max_size(u16::MAX);
        let info = response.destructive_emit(&mut enc)?;
        *self.0.lock().unwrap() = Some(bytes);
        Ok(info)
    }
}

fn suffix_match(name: &str, suffix: &str) -> bool {
    name == suffix || name.strip_suffix(suffix).is_some_and(|p| p.ends_with('.'))
}

impl Handler {
    fn class_of(&self, qname: &str) -> Option<usize> {
        // the most specific (longest) suffix wins
        self.classes
            .iter()
            .enumerate()
            .flat_map(|(i, c)| c.suffixes.iter().filter(|s| suffix_match(qname, s)).map(move |s| (s.len(), i)))
            .max()
            .map(|(_, i)| i)
    }

    /// The view for a client: the first whose clients contain it, else default.
    fn view_of(&self, ip: IpAddr) -> (&str, &Catalog) {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.views
            .iter()
            .find(|v| v.clients.iter().any(|c| c.contains(&ip)))
            .map(|v| (v.name.as_str(), &v.catalog))
            .unwrap_or(("default", &self.catalog))
    }

    fn net_of(&self, ip: IpAddr) -> &str {
        self.nets.iter().find(|(_, p)| p.contains(&ip)).map(|(n, _)| n.as_str()).unwrap_or("-")
    }

    async fn classify(&self, class: usize, msg: &Message) -> Vec<String> {
        let mut addrs = vec![];
        let mut ttl = 0u32;
        for r in &msg.answers {
            match &r.data {
                RData::A(a) => addrs.push(IpAddr::V4(a.0)),
                RData::AAAA(a) => addrs.push(IpAddr::V6(a.0)),
                _ => continue,
            }
            ttl = ttl.max(r.ttl);
        }
        if addrs.is_empty() {
            return vec![];
        }
        let keep = Duration::from_secs(ttl as u64).max(self.min_retention);
        let expiry = Instant::now() + keep;
        {
            let mut m = self.retained.lock().unwrap();
            for a in &addrs {
                m.insert((*a, class), expiry);
            }
        }
        let list: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
        if let Some(h) = &self.helper {
            // bounded wait: classification must not stall resolution
            if let Err(e) = h.request(&self.classes[class].table, "add", &list, Duration::from_millis(300)).await {
                warn(&format!("pfhelper add {}: {e}", self.classes[class].table));
            }
        }
        list
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let start = Instant::now();
        let src = request.src();
        let (view, catalog) = self.view_of(src.ip());
        let Ok(info) = request.request_info() else {
            return catalog.handle_request::<R, T>(request, response_handle).await;
        };
        let qname = info.query.name().to_string().trim_end_matches('.').to_ascii_lowercase();
        let qtype = info.query.query_type().to_string();
        let edns = request.edns.as_ref();

        // DoH canary: NXDOMAIN, so Firefox keeps using us (INV-4)
        if self.nxdomain.iter().any(|n| n.zone_of(info.query.name())) {
            let resp = MessageResponseBuilder::new(&request.queries, edns)
                .error_msg(&request.metadata, ResponseCode::NXDomain);
            let r = response_handle.send_response(resp).await;
            log_query(src, self.net_of(src.ip()), view, &qname, &qtype, "NXDomain", &[], start, None);
            return r.unwrap_or_else(|_| servfail(request));
        }

        let capture = Capture::default();
        let fallback = catalog.handle_request::<Capture, T>(request, capture.clone()).await;
        let Some(bytes) = capture.0.lock().unwrap().take() else { return fallback };
        let msg = match Message::from_vec(&bytes) {
            Ok(m) => m,
            Err(e) => {
                warn(&format!("cannot re-read a response for {qname}: {e}"));
                let resp = MessageResponseBuilder::new(&request.queries, edns)
                    .error_msg(&request.metadata, ResponseCode::ServFail);
                return response_handle.send_response(resp).await.unwrap_or_else(|_| servfail(request));
            }
        };

        let mut msg = msg;
        let refused = sinkhole(&mut msg, self.sinkhole);
        // a refused name is never classified into a pf table
        let class = if refused { None } else { self.class_of(&qname) };
        if let Some(c) = class {
            self.classify(c, &msg).await;
        }

        let answers: Vec<String> = msg
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0.to_string()),
                RData::AAAA(a) => Some(a.0.to_string()),
                RData::CNAME(c) => Some(format!("CNAME {}", c.0)),
                _ => None,
            })
            .collect();
        if let Some((sock, to)) = &self.collector {
            let addrs: Vec<String> = msg
                .answers
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(a) => Some(a.0.to_string()),
                    RData::AAAA(a) => Some(a.0.to_string()),
                    _ => None,
                })
                .collect();
            if !addrs.is_empty() {
                // fire and forget: flows lose a label, resolution never waits
                let m = serde_json::json!({"c": src.ip().to_string(), "q": qname, "a": addrs}).to_string();
                let _ = sock.send_to(m.as_bytes(), to);
            }
        }
        let rcode = format!("{:?}", msg.metadata.response_code);
        let resp = MessageResponseBuilder::new(&request.queries, msg.edns.as_ref().or(edns)).build(
            msg.metadata,
            msg.answers.iter(),
            msg.authorities.iter(),
            std::iter::empty(),
            msg.additionals.iter(),
        );
        let r = response_handle.send_response(resp).await;
        log_query(
            src,
            self.net_of(src.ip()),
            view,
            &qname,
            &qtype,
            &rcode,
            &answers,
            start,
            if refused { Some("blocked") } else { class.map(|c| self.classes[c].name.as_str()) },
        );
        r.unwrap_or_else(|_| servfail(request))
    }
}

fn servfail(request: &Request) -> ResponseInfo {
    use hickory_server::proto::op::{Header, HeaderCounts, MessageType, Metadata};
    let mut metadata = Metadata::new(request.metadata.id, MessageType::Response, request.metadata.op_code);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header { metadata, counts: HeaderCounts::default() })
}

// ---- logging: JSON lines to syslog local5 (forwarded with everything else)

#[allow(clippy::too_many_arguments)]
fn log_query(
    src: SocketAddr,
    net: &str,
    view: &str,
    qname: &str,
    qtype: &str,
    rcode: &str,
    answers: &[String],
    start: Instant,
    class: Option<&str>,
) {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    let v = serde_json::json!({
        "ts": (ts * 1000.0).round() / 1000.0,
        "client": src.ip().to_string(),
        "net": net,
        "view": view,
        "qname": qname,
        "qtype": qtype,
        "rcode": rcode,
        "answers": answers,
        "ms": (start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
        "class": class,
    });
    syslog(libc::LOG_LOCAL5 | libc::LOG_INFO, &v.to_string());
}

fn warn(msg: &str) {
    syslog(libc::LOG_DAEMON | libc::LOG_WARNING, msg);
}

fn syslog(prio: libc::c_int, msg: &str) {
    if let Ok(m) = std::ffi::CString::new(msg.replace('\0', "")) {
        unsafe { libc::syslog(prio, c"%s".as_ptr(), m.as_ptr()) };
    }
}

// ---- setup

/// The local zones, loaded once and shared by every view's catalog.
type Zones = Vec<(LowerName, Arc<dyn ZoneHandler>)>;

fn zones(cfg: &Config) -> Result<Zones, String> {
    let mut v = vec![];
    for z in &cfg.zones {
        let name = Name::parse(z, Some(&Name::root())).map_err(|e| format!("zone {z}: {e}"))?;
        let fc = FileConfig { zone_path: PathBuf::from(format!("{z}.zone")) };
        let h = FileZoneHandler::try_from_config(
            name.clone(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
            Some(&cfg.zone_dir),
            &fc,
        )
        .map_err(|e| format!("zone {z}: {e}"))?;
        v.push((LowerName::new(&name), Arc::new(h) as Arc<dyn ZoneHandler>));
    }
    Ok(v)
}

/// A catalog: the local zones plus a forwarder with exactly these upstreams
/// (and its own cache), so a view never answers from another's.
fn catalog(zones: &[(LowerName, Arc<dyn ZoneHandler>)], forward: &ForwardConfig) -> Result<Catalog, String> {
    let mut catalog = Catalog::new();
    for (n, h) in zones {
        catalog.upsert(n.clone(), vec![h.clone()]);
    }
    let fwd = ForwardZoneHandler::builder_tokio(forward.clone())
        .with_origin(Name::root())
        .build()
        .map_err(|e| format!("forwarder: {e}"))?;
    catalog.upsert(LowerName::new(&Name::root()), vec![Arc::new(fwd) as Arc<dyn ZoneHandler>]);
    Ok(catalog)
}

fn ids(user: &str) -> Result<(u32, u32), String> {
    let text = std::fs::read_to_string("/etc/passwd").map_err(|e| e.to_string())?;
    text.lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 3 && f[0] == user).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
        })
        .ok_or_else(|| format!("no user {user}"))
}

fn drop_privileges(user: &str, unveil: &[(&str, &str)]) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let (uid, gid) = ids(user)?;
    unsafe {
        let groups = [gid];
        if libc::setgroups(1, groups.as_ptr() as *const _) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            return Err(format!("cannot drop to {user}"));
        }
    }
    sandbox(unveil)
}

#[cfg(target_os = "openbsd")]
fn sandbox(paths: &[(&str, &str)]) -> Result<(), String> {
    use std::ffi::CString;
    unsafe {
        for (p, perm) in paths {
            let (cp, cperm) = (CString::new(*p).unwrap(), CString::new(*perm).unwrap());
            if libc::unveil(cp.as_ptr(), cperm.as_ptr()) != 0 {
                return Err(format!("unveil {p}"));
            }
        }
        if libc::unveil(std::ptr::null(), std::ptr::null()) != 0 {
            return Err("unveil lock".into());
        }
        // rpath: the TLS verifier reads /etc/ssl/cert.pem on first use
        if libc::pledge(c"stdio rpath inet unix".as_ptr(), std::ptr::null()) != 0 {
            return Err("pledge".into());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
fn sandbox(_: &[(&str, &str)]) -> Result<(), String> {
    Ok(())
}

type Retained = Arc<Mutex<HashMap<(IpAddr, usize), Instant>>>;

/// Every minute: forget expired addresses and rewrite each class table.
/// The first pass (at start) empties tables left over from a previous run.
async fn retention(helper: Arc<helper::Helper>, classes: Vec<Class>, retained: Retained) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let now = Instant::now();
        let mut sets: Vec<Vec<String>> = vec![vec![]; classes.len()];
        {
            let mut m = retained.lock().unwrap();
            m.retain(|_, exp| *exp > now);
            for (ip, c) in m.keys() {
                sets[*c].push(ip.to_string());
            }
        }
        for (c, set) in classes.iter().zip(sets) {
            let h = &helper;
            if let Err(e) = h.request(&c.table, "replace", &set, Duration::from_secs(5)).await {
                warn(&format!("pfhelper replace {}: {e}", c.table));
            }
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut conf, mut validate, mut zonedir) = ("/etc/octopus/dns/octopus-dns.toml".to_string(), false, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => conf = args.next().expect("-c needs a file"),
            "-z" => zonedir = Some(PathBuf::from(args.next().expect("-z needs a directory"))),
            "--validate" => validate = true,
            _ => {
                eprintln!("usage: octopus-dns [-c octopus-dns.toml] [-z zonedir] [--validate]");
                std::process::exit(2);
            }
        }
    }
    unsafe { libc::openlog(c"octopus-dns".as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, libc::LOG_DAEMON) };
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
    if let Err(e) = rt.block_on(run(&conf, zonedir, validate)) {
        eprintln!("octopus-dns: {e}");
        warn(&format!("fatal: {e}"));
        std::process::exit(1);
    }
}

async fn run(conf: &str, zonedir: Option<PathBuf>, validate: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(conf).map_err(|e| format!("{conf}: {e}"))?;
    let mut cfg: Config = toml::from_str(&text).map_err(|e| format!("{conf}: {e}"))?;
    if let Some(z) = zonedir {
        cfg.zone_dir = z;
    }
    let zs = zones(&cfg)?;
    let default = catalog(&zs, &cfg.forward)?;
    let mut views = vec![];
    for v in &cfg.views {
        if v.forward.name_servers.is_empty() {
            return Err(format!("view {}: no upstreams", v.name));
        }
        views.push(View { name: v.name.clone(), clients: v.clients.clone(), catalog: catalog(&zs, &v.forward)? });
    }
    if validate {
        println!("{conf}: ok ({} zones, {} classes, {} views)", cfg.zones.len(), cfg.classes.len(), views.len());
        return Ok(());
    }

    let classes: Vec<Class> = cfg
        .classes
        .iter()
        .map(|c| Class {
            name: c.name.clone(),
            table: c.table.clone(),
            suffixes: c.domains.iter().map(|d| d.trim_end_matches('.').to_ascii_lowercase()).collect(),
        })
        .collect();
    let helper = cfg.pfhelper.as_ref().map(|p| Arc::new(helper::Helper::new(p)));
    let retained: Retained = Arc::new(Mutex::new(HashMap::new()));
    if let Some(h) = &helper
        && !classes.is_empty()
    {
        tokio::spawn(retention(h.clone(), classes.clone(), retained.clone()));
    }
    let mut server = Server::with_access(
        Handler {
            catalog: default,
            views,
            nxdomain: cfg
                .nxdomain
                .iter()
                .filter_map(|n| Name::parse(n, Some(&Name::root())).ok())
                .map(|n| LowerName::new(&n))
                .collect(),
            classes,
            nets: cfg.networks.iter().map(|n| (n.name.clone(), n.prefix)).collect(),
            helper,
            retained,
            min_retention: Duration::from_secs(cfg.min_retention),
            sinkhole: cfg.sinkhole,
            collector: match cfg.collector {
                Some(to) => {
                    let s = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("collector socket: {e}"))?;
                    s.set_nonblocking(true).map_err(|e| e.to_string())?;
                    Some((s, to))
                }
                None => None,
            },
        },
        [],
        cfg.allow.clone(),
    );
    for ip in &cfg.listen {
        let addr = SocketAddr::new(*ip, cfg.port);
        let udp = tokio::net::UdpSocket::bind(addr).await.map_err(|e| format!("udp {addr}: {e}"))?;
        server.register_socket(udp);
        let tcp = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("tcp {addr}: {e}"))?;
        server.register_listener(tcp, Duration::from_secs(5), 32);
    }
    let mut unveil = vec![("/etc/ssl", "r")];
    if let Some(p) = &cfg.pfhelper {
        unveil.push((p.as_str(), "rw"));
    }
    drop_privileges(&cfg.user, &unveil)?;
    warn(&format!(
        "listening on {} addresses port {}; {} zones; {} classes; views: default{}",
        cfg.listen.len(),
        cfg.port,
        cfg.zones.len(),
        cfg.classes.len(),
        cfg.views.iter().map(|v| format!(", {} ({} clients)", v.name, v.clients.len())).collect::<String>()
    ));
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        r = server.block_until_done() => r.map_err(|e| e.to_string()),
        _ = term.recv() => {
            let _ = server.shutdown_gracefully().await;
            Ok(())
        }
    }
}
