//! octopus-proxy: the servers networks' only way to the web (design 13).
//!
//! pf diverts a servers network's outbound 443 and 80 here. For HTTPS:
//!
//!  1. read the client's TLS ClientHello and take its SNI; no SNI, or a name
//!     not on the network's allowlist: close, log
//!  2. connect to the original destination with that SNI and verify the real
//!     certificate (rustls/webpki against /etc/ssl/cert.pem); expired, wrong
//!     name, self-signed, unknown root: close, log
//!  3. present a leaf for the name, minted by the signer process with the
//!     interception root (which only servers trust)
//!  4. relay HTTP/1.1 requests whose Host is the same allowed name; anything
//!     else gets 403 (no domain fronting)
//!
//! Plain HTTP: the Host of each request must be allowed, and the proxy
//! connects to that name (resolved by the router, internet addresses only),
//! never to wherever the client pointed: one name per connection.
//! Both: no CONNECT or upgrades, one Host, the target sent on in origin
//! form; timeouts on every step; a cap on connections, per client too.
//! Every decision is logged as a JSON line (syslog local3,
//! /var/log/octopus-proxy).
//!
//! relayd was the design's choice; its TLS inspection connects upstream
//! without SNI, so it fails on SNI-hosted sites and can't check the name.
//! Runs unprivileged and pledged; the key lives only in the signer.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

mod allow;
mod signer;

const CA_BUNDLE: &str = "/etc/ssl/cert.pem";
/// Connections at once, all clients and one client.
const MAX_CONNS: usize = 1024;
const MAX_PER_CLIENT: u32 = 64;
/// TLS handshakes, upstream connects, an upstream's response head.
const STEP: Duration = Duration::from_secs(10);
const RESPONSE: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    user: String,
    ca_cert: String,
    ca_key: String,
    #[serde(default)]
    listeners: Vec<ListenConf>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ListenConf {
    /// the servers network
    name: String,
    https: SocketAddr,
    http: SocketAddr,
    allow: Vec<String>,
}

struct Ctx {
    signer: signer::Signer,
    upstream: Arc<rustls::ClientConfig>,
    active: AtomicUsize,
    per_client: std::sync::Mutex<HashMap<IpAddr, u32>>,
}

/// A connection's place under the caps; given back when it ends.
struct Admitted(Arc<Ctx>, IpAddr);

impl Ctx {
    fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<Admitted> {
        let mut m = self.per_client.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(ip).or_insert(0);
        if *n >= MAX_PER_CLIENT || self.active.load(Ordering::SeqCst) >= MAX_CONNS {
            return None;
        }
        *n += 1;
        self.active.fetch_add(1, Ordering::SeqCst);
        Some(Admitted(self.clone(), ip))
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        let mut m = self.0.per_client.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

fn syslog(prio: libc::c_int, msg: &str) {
    if let Ok(m) = std::ffi::CString::new(msg.replace('\0', "")) {
        unsafe { libc::syslog(prio, c"%s".as_ptr(), m.as_ptr()) };
    }
}

/// One JSON line per decision.
fn event(
    net: &str,
    client: SocketAddr,
    dst: SocketAddr,
    host: &str,
    action: &str,
    why: &str,
    extra: serde_json::Value,
) {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut v = serde_json::json!({
        "ts": ts, "net": net, "client": client.ip().to_string(), "dst": dst.to_string(),
        "host": host, "action": action, "why": why,
    });
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    syslog(libc::LOG_LOCAL3 | libc::LOG_INFO, &v.to_string());
}

/// A request as it may go on: no CONNECT, no protocol upgrade, one Host,
/// and a target that names no other host; sent on in origin form (path and
/// query), so the origin has nothing but the checked name to go by.
/// Returns the host.
fn sanitize(req: &mut Request<Incoming>) -> Result<String, &'static str> {
    use hyper::header::HOST;
    if req.method() == hyper::Method::CONNECT {
        return Err("CONNECT is not relayed");
    }
    if req.headers().contains_key(hyper::header::UPGRADE) {
        return Err("protocol upgrades are not relayed");
    }
    let mut hosts = req.headers().get_all(HOST).iter();
    let host = hosts.next().map(|h| h.to_str().map(str::to_string).map_err(|_| "a Host that isn't text"));
    if hosts.next().is_some() {
        return Err("more than one Host");
    }
    let authority = req.uri().authority().map(|a| a.to_string());
    let host = match (host.transpose()?, authority) {
        (Some(h), Some(a)) if allow::normalize(&h) != allow::normalize(&a) => {
            return Err("the target names another host than Host");
        }
        (Some(h), _) => h,
        (None, Some(a)) => a,
        (None, None) => return Err("no Host"),
    };
    if req.uri().authority().is_some() || req.uri().scheme().is_some() {
        let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        *req.uri_mut() = pq.parse().map_err(|_| "a bad target")?;
    }
    if !req.headers().contains_key(HOST) {
        let v = hyper::header::HeaderValue::from_str(&host).map_err(|_| "a bad host")?;
        req.headers_mut().insert(HOST, v);
    }
    Ok(host)
}

fn forbidden(msg: &str) -> Response<http_body::Full> {
    let mut r = Response::new(http_body::Full::new(format!("octopus-proxy: {msg}\n")));
    *r.status_mut() = StatusCode::FORBIDDEN;
    r
}

/// A minimal full-body type for our own replies, next to proxied bodies.
mod http_body {
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use hyper::body::{Body, Bytes, Frame, Incoming};

    pub struct Full(Option<Bytes>);

    impl Full {
        pub fn new(s: String) -> Full {
            Full(Some(Bytes::from(s)))
        }
    }

    impl Body for Full {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.0.take().map(|b| Ok(Frame::data(b))))
        }
    }

    /// Either a proxied body or one of ours.
    pub enum Either {
        Proxied(Incoming),
        Ours(Full),
    }

    impl Body for Either {
        type Data = Bytes;
        type Error = hyper::Error;
        fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
            match self.get_mut() {
                Either::Proxied(b) => Pin::new(b).poll_frame(cx),
                Either::Ours(b) => match Pin::new(b).poll_frame(cx) {
                    Poll::Ready(Some(Ok(f))) => Poll::Ready(Some(Ok(f))),
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Ready(Some(Err(e))) => match e {},
                    Poll::Pending => Poll::Pending,
                },
            }
        }
    }
}

type Reply = Response<http_body::Either>;

/// Logs one request: host, method, path, status.
type ReqLog = Arc<dyn Fn(&str, &str, &str, u16) + Send + Sync>;

fn ours(r: Response<http_body::Full>) -> Reply {
    r.map(http_body::Either::Ours)
}

type Sender = hyper::client::conn::http1::SendRequest<Incoming>;

/// Where a connection's requests go: a fixed upstream (HTTPS: the verified
/// origin for the SNI), or one made for the first request's name (HTTP).
enum Upstream {
    Fixed(Sender),
    ByName { port: u16, conn: Option<(String, Sender)> },
}

/// Connect to `host` (as the router resolves it), internet addresses only.
async fn connect_name(host: &str, port: u16) -> Result<TcpStream, String> {
    let name = allow::normalize(host);
    let addrs = tokio::time::timeout(STEP, tokio::net::lookup_host((name.as_str(), port)))
        .await
        .map_err(|_| "no answer from DNS".to_string())?
        .map_err(|e| format!("{name}: {e}"))?;
    let mut last = format!("{name}: no address on the internet");
    for a in addrs.filter(|a| allow::global(a.ip())) {
        match tokio::time::timeout(STEP, TcpStream::connect(a)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = format!("{a}: {e}"),
            Err(_) => last = format!("{a}: timed out"),
        }
    }
    Err(last)
}

async fn handshake<U>(io: U) -> Result<Sender, String>
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = tokio::time::timeout(STEP, hyper::client::conn::http1::handshake(TokioIo::new(io)))
        .await
        .map_err(|_| "upstream handshake timed out".to_string())?
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    Ok(sender)
}

fn status(code: StatusCode, msg: &str) -> Reply {
    let mut r = forbidden(msg);
    *r.status_mut() = code;
    ours(r)
}

/// Relay requests on `client`, each sanitized and its Host checked against `ok`.
async fn relay_http<C>(client: C, upstream: Upstream, ok: impl Fn(&str) -> bool + Send + Sync + 'static, log: ReqLog)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let upstream = Arc::new(tokio::sync::Mutex::new(upstream));
    let ok = Arc::new(ok);
    let svc = service_fn(move |mut req: Request<Incoming>| {
        let upstream = upstream.clone();
        let ok = ok.clone();
        let log = log.clone();
        async move {
            let (method, path) = (req.method().to_string(), req.uri().path().to_string());
            let host = match sanitize(&mut req) {
                Ok(h) => h,
                Err(e) => {
                    log("", &method, &path, 400);
                    return Ok::<Reply, hyper::Error>(status(StatusCode::BAD_REQUEST, e));
                }
            };
            if !ok(&host) {
                log(&host, &method, &path, 403);
                return Ok(status(StatusCode::FORBIDDEN, &format!("{} is not allowed", allow::normalize(&host))));
            }
            let mut up = upstream.lock().await;
            let sender = match &mut *up {
                Upstream::Fixed(s) => s,
                Upstream::ByName { port, conn } => {
                    match conn {
                        Some((h, _)) if allow::normalize(h) != allow::normalize(&host) => {
                            log(&host, &method, &path, 403);
                            return Ok(status(StatusCode::FORBIDDEN, "one host per connection"));
                        }
                        Some(_) => {}
                        None => match connect_name(&host, *port).await {
                            Ok(s) => match handshake(s).await {
                                Ok(sender) => *conn = Some((host.clone(), sender)),
                                Err(e) => {
                                    log(&host, &method, &path, 502);
                                    return Ok(status(StatusCode::BAD_GATEWAY, &format!("upstream: {e}")));
                                }
                            },
                            Err(e) => {
                                log(&host, &method, &path, 502);
                                return Ok(status(StatusCode::BAD_GATEWAY, &format!("upstream: {e}")));
                            }
                        },
                    }
                    &mut conn.as_mut().unwrap().1
                }
            };
            match tokio::time::timeout(RESPONSE, sender.send_request(req)).await {
                Ok(Ok(r)) => {
                    log(&host, &method, &path, r.status().as_u16());
                    Ok(r.map(http_body::Either::Proxied))
                }
                Ok(Err(e)) => {
                    log(&host, &method, &path, 502);
                    Ok(status(StatusCode::BAD_GATEWAY, &format!("upstream: {e}")))
                }
                Err(_) => {
                    log(&host, &method, &path, 504);
                    Ok(status(StatusCode::GATEWAY_TIMEOUT, "upstream: no answer"))
                }
            }
        }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(client), svc)
        .await;
}

/// A connection that wasn't diverted (to the proxy's own address, or over
/// loopback) has no destination of its own: connecting to it would be the
/// proxy connecting to itself.
fn not_diverted(dst: SocketAddr, l: &ListenConf) -> bool {
    dst.ip().is_loopback() || dst == l.https || dst == l.http
}

async fn https(conn: TcpStream, ctx: Arc<Ctx>, l: Arc<ListenConf>) {
    let (Ok(peer), Ok(dst)) = (conn.peer_addr(), conn.local_addr()) else { return };
    if not_diverted(dst, &l) {
        return;
    }
    let Some(_slot) = ctx.admit(peer.ip()) else {
        return event(&l.name, peer, dst, "", "block", "too many connections", serde_json::json!({}));
    };
    // divert-to keeps the original destination as our local address
    let start = match tokio::time::timeout(
        Duration::from_secs(10),
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), conn),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return event(&l.name, peer, dst, "", "block", "no TLS hello", serde_json::json!({})),
    };
    let Some(sni) = start.client_hello().server_name().map(allow::normalize) else {
        return event(&l.name, peer, dst, "", "block", "no SNI", serde_json::json!({}));
    };
    if !allow::matches(&l.allow, &sni) {
        return event(&l.name, peer, dst, &sni, "block", "not on the allowlist", serde_json::json!({}));
    }
    let t0 = Instant::now();
    let up = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(dst)).await {
        Ok(Ok(s)) => s,
        _ => return event(&l.name, peer, dst, &sni, "block", "upstream unreachable", serde_json::json!({})),
    };
    let Ok(name) = ServerName::try_from(sni.clone()) else { return };
    let up = match tokio::time::timeout(STEP, TlsConnector::from(ctx.upstream.clone()).connect(name, up)).await {
        Err(_) => {
            return event(&l.name, peer, dst, &sni, "block", "upstream handshake timed out", serde_json::json!({}));
        }
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            // the origin's certificate failed verification: the server never gets in
            return event(
                &l.name,
                peer,
                dst,
                &sni,
                "block",
                &format!("upstream certificate: {e}"),
                serde_json::json!({}),
            );
        }
    };
    let leaf = match ctx.signer.leaf(&sni).await {
        Ok(k) => k,
        Err(e) => return event(&l.name, peer, dst, &sni, "block", &format!("signer: {e}"), serde_json::json!({})),
    };
    let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocols")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(leaf)));
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = match tokio::time::timeout(STEP, start.into_stream(Arc::new(sc))).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return event(&l.name, peer, dst, &sni, "block", &format!("client handshake: {e}"), serde_json::json!({}));
        }
        Err(_) => return event(&l.name, peer, dst, &sni, "block", "client handshake timed out", serde_json::json!({})),
    };
    event(&l.name, peer, dst, &sni, "pass", "tls", serde_json::json!({"ms": t0.elapsed().as_millis() as u64}));
    let (net, allowl, sni2) = (l.name.clone(), l.allow.clone(), sni.clone());
    let log: ReqLog = Arc::new(move |host: &str, m: &str, p: &str, st: u16| {
        let action = if (400..500).contains(&st) { "block" } else { "pass" };
        event(&net, peer, dst, host, action, "request", serde_json::json!({"method": m, "path": p, "status": st}));
    });
    let sender = match handshake(up).await {
        Ok(s) => s,
        Err(e) => return event(&l.name, peer, dst, &sni, "block", &format!("upstream: {e}"), serde_json::json!({})),
    };
    // same name as the TLS session, and on the list: no domain fronting
    relay_http(tls, Upstream::Fixed(sender), move |h| allow::normalize(h) == sni2 && allow::matches(&allowl, h), log)
        .await;
}

async fn http(conn: TcpStream, ctx: Arc<Ctx>, l: Arc<ListenConf>) {
    let (Ok(peer), Ok(dst)) = (conn.peer_addr(), conn.local_addr()) else { return };
    if not_diverted(dst, &l) {
        return;
    }
    let Some(_slot) = ctx.admit(peer.ip()) else {
        return event(&l.name, peer, dst, "", "block", "too many connections", serde_json::json!({}));
    };
    let net = l.name.clone();
    let log: ReqLog = Arc::new(move |host: &str, m: &str, p: &str, st: u16| {
        let action = if (400..500).contains(&st) { "block" } else { "pass" };
        event(&net, peer, dst, host, action, "http request", serde_json::json!({"method": m, "path": p, "status": st}));
    });
    let a = l.allow.clone();
    // the name decides where it goes, not the address the client used
    relay_http(conn, Upstream::ByName { port: dst.port(), conn: None }, move |h| allow::matches(&a, h), log).await;
}

fn upstream_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(CA_BUNDLE).map_err(|e| format!("{CA_BUNDLE}: {e}"))? {
        let c = c.map_err(|e| format!("{CA_BUNDLE}: {e}"))?;
        let _ = roots.add(c);
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
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

fn drop_to(user: &str, promises: &std::ffi::CStr, readable: &[&std::ffi::CStr]) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        let (uid, gid) = ids(user)?;
        unsafe {
            let g = [gid];
            if libc::setgroups(1, g.as_ptr() as *const _) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(format!("cannot drop to {user}"));
            }
        }
    }
    #[cfg(target_os = "openbsd")]
    unsafe {
        for p in readable {
            if libc::unveil(p.as_ptr(), c"r".as_ptr()) != 0 {
                return Err("unveil".into());
            }
        }
        if libc::unveil(std::ptr::null(), std::ptr::null()) != 0
            || libc::pledge(promises.as_ptr(), std::ptr::null()) != 0
        {
            return Err("pledge".into());
        }
    }
    let _ = (promises, readable);
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut conf, mut validate) = ("/etc/octopus/proxy.toml".to_string(), false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => conf = args.next().expect("-c needs a file"),
            "--validate" => validate = true,
            _ => {
                eprintln!("usage: octopus-proxy [-c proxy.toml] [--validate]");
                std::process::exit(2);
            }
        }
    }
    unsafe { libc::openlog(c"octopus-proxy".as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, libc::LOG_DAEMON) };
    if let Err(e) = run(&conf, validate) {
        eprintln!("octopus-proxy: {e}");
        syslog(libc::LOG_DAEMON | libc::LOG_ERR, &format!("fatal: {e}"));
        std::process::exit(1);
    }
}

fn run(conf: &str, validate: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(conf).map_err(|e| format!("{conf}: {e}"))?;
    let cfg: Config = toml::from_str(&text).map_err(|e| format!("{conf}: {e}"))?;
    let upstream = Arc::new(upstream_config()?);
    for l in &cfg.listeners {
        for h in &l.allow {
            let bare = h.strip_prefix("*.").unwrap_or(h);
            if bare.is_empty() || bare.contains(['*', '/', ' ']) {
                return Err(format!("listener {}: bad allow entry {h:?}", l.name));
            }
        }
    }
    if validate {
        if !std::path::Path::new(&cfg.ca_cert).exists() {
            println!(
                "{conf}: ok (the interception root {} doesn't exist yet: octopus pki intercept-init)",
                cfg.ca_cert
            );
        } else {
            println!("{conf}: ok ({} listeners)", cfg.listeners.len());
        }
        return Ok(());
    }
    let ca = octopus_pki::Ca {
        cert_pem: std::fs::read_to_string(&cfg.ca_cert).map_err(|e| format!("{}: {e}", cfg.ca_cert))?,
        key_pem: std::fs::read_to_string(&cfg.ca_key).map_err(|e| format!("{}: {e}", cfg.ca_key))?,
    };
    let allowed: Vec<String> = cfg.listeners.iter().flat_map(|l| l.allow.clone()).collect();
    // room for the connection caps: two descriptors each
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }

    // the signer gets the key; this process forgets it
    let (ours, theirs) = StdUnixStream::pair().map_err(|e| e.to_string())?;
    match unsafe { libc::fork() } {
        -1 => return Err("fork failed".into()),
        0 => {
            drop(ours);
            if let Err(e) = drop_to(&cfg.user, c"stdio", &[]) {
                syslog(libc::LOG_DAEMON | libc::LOG_ERR, &format!("signer: {e}"));
                std::process::exit(1);
            }
            signer::run(theirs, ca, allowed);
        }
        _ => {
            drop(theirs);
            drop(ca);
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let mut socks = vec![];
        for l in &cfg.listeners {
            let l = Arc::new(l.clone());
            let s = TcpListener::bind(l.https).await.map_err(|e| format!("{}: {e}", l.https))?;
            let p = TcpListener::bind(l.http).await.map_err(|e| format!("{}: {e}", l.http))?;
            socks.push((l, s, p));
        }
        let ctx = Arc::new(Ctx {
            signer: signer::Signer::new(ours).map_err(|e| e.to_string())?,
            upstream,
            active: AtomicUsize::new(0),
            per_client: Default::default(),
        });
        // dns: plain HTTP goes to the name, resolved by the router
        drop_to(&cfg.user, c"stdio inet dns", &[c"/etc/resolv.conf", c"/etc/hosts"])?;
        syslog(libc::LOG_DAEMON | libc::LOG_NOTICE, &format!("listening for {} servers network(s)", socks.len()));
        let mut tasks = vec![];
        for (l, s, p) in socks {
            let (ctx2, l2) = (ctx.clone(), l.clone());
            let ctx = ctx.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    if let Ok((c, _)) = s.accept().await {
                        tokio::spawn(https(c, ctx2.clone(), l2.clone()));
                    }
                }
            }));
            tasks.push(tokio::spawn(async move {
                loop {
                    if let Ok((c, _)) = p.accept().await {
                        tokio::spawn(http(c, ctx.clone(), l.clone()));
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
        Ok::<(), String>(())
    })
}
