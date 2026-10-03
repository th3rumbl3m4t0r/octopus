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
//! Plain HTTP: the Host of each request must be allowed. Every decision is
//! logged as a JSON line (syslog local3, /var/log/octopus-proxy).
//!
//! relayd was the design's choice; its TLS inspection connects upstream
//! without SNI, so it fails on SNI-hosted sites and can't check the name.
//! Runs unprivileged and pledged; the key lives only in the signer.

use std::net::SocketAddr;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
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

fn host_of(req: &Request<Incoming>) -> String {
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_default()
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

/// Relay requests on `client` to `upstream`, each Host checked against `ok`.
async fn relay_http<C, U>(client: C, upstream: U, ok: impl Fn(&str) -> bool + Send + Sync + 'static, log: ReqLog)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok((sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await else { return };
    tokio::spawn(conn);
    let sender = Arc::new(tokio::sync::Mutex::new(sender));
    let ok = Arc::new(ok);
    let svc = service_fn(move |req: Request<Incoming>| {
        let sender = sender.clone();
        let ok = ok.clone();
        let log = log.clone();
        async move {
            let host = host_of(&req);
            let (method, path) = (req.method().to_string(), req.uri().path().to_string());
            if !ok(&host) {
                log(&host, &method, &path, 403);
                return Ok::<Reply, hyper::Error>(ours(forbidden(&format!(
                    "{} is not allowed",
                    allow::normalize(&host)
                ))));
            }
            let resp = sender.lock().await.send_request(req).await;
            match resp {
                Ok(r) => {
                    log(&host, &method, &path, r.status().as_u16());
                    Ok(r.map(http_body::Either::Proxied))
                }
                Err(e) => {
                    log(&host, &method, &path, 502);
                    let mut r = forbidden(&format!("upstream: {e}"));
                    *r.status_mut() = StatusCode::BAD_GATEWAY;
                    Ok(ours(r))
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

async fn https(conn: TcpStream, ctx: Arc<Ctx>, l: Arc<ListenConf>) {
    let (Ok(peer), Ok(dst)) = (conn.peer_addr(), conn.local_addr()) else { return };
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
    let up = match TlsConnector::from(ctx.upstream.clone()).connect(name, up).await {
        Ok(t) => t,
        Err(e) => {
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
    let tls = match start.into_stream(Arc::new(sc)).await {
        Ok(t) => t,
        Err(e) => {
            return event(&l.name, peer, dst, &sni, "block", &format!("client handshake: {e}"), serde_json::json!({}));
        }
    };
    event(&l.name, peer, dst, &sni, "pass", "tls", serde_json::json!({"ms": t0.elapsed().as_millis() as u64}));
    let (net, allowl, sni2) = (l.name.clone(), l.allow.clone(), sni.clone());
    let log: ReqLog = Arc::new(move |host: &str, m: &str, p: &str, st: u16| {
        let action = if st == 403 { "block" } else { "pass" };
        event(&net, peer, dst, host, action, "request", serde_json::json!({"method": m, "path": p, "status": st}));
    });
    // same name as the TLS session, and on the list: no domain fronting
    relay_http(tls, up, move |h| allow::normalize(h) == sni2 && allow::matches(&allowl, h), log).await;
}

async fn http(conn: TcpStream, l: Arc<ListenConf>) {
    let (Ok(peer), Ok(dst)) = (conn.peer_addr(), conn.local_addr()) else { return };
    let up = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(dst)).await {
        Ok(Ok(s)) => s,
        _ => return event(&l.name, peer, dst, "", "block", "upstream unreachable", serde_json::json!({})),
    };
    let net = l.name.clone();
    let log: ReqLog = Arc::new(move |host: &str, m: &str, p: &str, st: u16| {
        let action = if st == 403 { "block" } else { "pass" };
        event(&net, peer, dst, host, action, "http request", serde_json::json!({"method": m, "path": p, "status": st}));
    });
    let a = l.allow.clone();
    relay_http(conn, up, move |h| allow::matches(&a, h), log).await;
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

fn drop_to(user: &str, promises: &std::ffi::CStr) -> Result<(), String> {
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
        if libc::unveil(std::ptr::null(), std::ptr::null()) != 0
            || libc::pledge(promises.as_ptr(), std::ptr::null()) != 0
        {
            return Err("pledge".into());
        }
    }
    let _ = promises;
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

    // the signer gets the key; this process forgets it
    let (ours, theirs) = StdUnixStream::pair().map_err(|e| e.to_string())?;
    match unsafe { libc::fork() } {
        -1 => return Err("fork failed".into()),
        0 => {
            drop(ours);
            if let Err(e) = drop_to(&cfg.user, c"stdio") {
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
        let ctx = Arc::new(Ctx { signer: signer::Signer::new(ours).map_err(|e| e.to_string())?, upstream });
        drop_to(&cfg.user, c"stdio inet")?;
        syslog(libc::LOG_DAEMON | libc::LOG_NOTICE, &format!("listening for {} servers network(s)", socks.len()));
        let mut tasks = vec![];
        for (l, s, p) in socks {
            let (ctx2, l2) = (ctx.clone(), l.clone());
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
                        tokio::spawn(http(c, l.clone()));
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
