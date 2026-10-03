//! octopus-web: the router's web UI. Runs as _octoweb, serves HTTPS on the
//! management addresses only (INV-1), and never holds root or secrets:
//! everything privileged goes through `doas` rules that allow exactly
//!
//!   octopus status --json | diff --staged | apply --staged | confirm | rollback
//!
//! Config edits are checked in-process (placeholder secrets) and staged in
//! /var/octopus/staged/ for `octopus apply --staged` to rebuild from scratch.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

mod auth;
mod edit;
mod firewall;
mod pages;
mod traffic;
mod tree;

const CONF: &str = "/etc/octopus/web.toml";
const ROUTER_TOML: &str = "/etc/octopus/router.toml";
const STAGED_DIR: &str = "/var/octopus/staged";
const OCTOPUS: &str = "/usr/local/sbin/octopus";
const ANALYZER: &str = "/usr/local/sbin/octopus-analyzer";
const CAPTURE: &str = "/var/octopus/staged/capture.json";
const DOAS: &str = "/usr/bin/doas";

const X11_CSS: &str = include_str!("../assets/x11.css");
const X11_JS: &str = include_str!("../assets/x11.js");
const OCTO_CSS: &str = include_str!("../assets/octopus.css");
const OCTO_JS: &str = include_str!("../assets/octopus.js");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Conf {
    listen: Vec<String>,
    hostname: String,
    cert: String,
    key: String,
    users: String,
}

struct App {
    host: String,
    /// the addresses we listen on: requests from them come through our nginx
    own: Vec<std::net::IpAddr>,
    auth: auth::Auth,
    status: Mutex<Option<(Instant, Value)>>,
    /// one privileged action at a time
    action: tokio::sync::Mutex<()>,
    /// one capture at a time (they hold a bpf device for up to 30 s)
    capture: tokio::sync::Mutex<()>,
    traffic: Arc<traffic::Traffic>,
    dev: bool,
}

type Shared = Arc<App>;

fn hdr(h: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn session_user(app: &App, h: &HeaderMap) -> Option<String> {
    auth::cookie(hdr(h, header::COOKIE)).and_then(|t| app.auth.user(&t))
}

/// The client's address: X-Real-IP when the request came through the
/// router's own nginx (a vhost), else the peer. Only the login lockout uses it.
fn client_ip(h: &HeaderMap, peer: SocketAddr, own: &[std::net::IpAddr]) -> std::net::IpAddr {
    let via_self = peer.ip().is_loopback() || own.contains(&peer.ip());
    if via_self && let Some(ip) = hdr(h, header::HeaderName::from_static("x-real-ip")).and_then(|s| s.parse().ok()) {
        return ip;
    }
    peer.ip()
}

async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    // no HSTS: management is internal, and with HSTS set a browser refuses to
    // click through the self-signed certificate an install starts with
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// Pages need a session (else to /login); /api needs a session and, for
/// anything but GET, the X-Octopus header, which our own page script sets
/// and a form on another site can't (no Origin checks: management is
/// internal, and browsers send odd Origins through proxies and privacy settings).
async fn guard(State(app): State<Shared>, req: axum::extract::Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let public = matches!(path.as_str(), "/login" | "/x11.css" | "/x11.js" | "/octopus.css" | "/nav.js");
    if public {
        return next.run(req).await;
    }
    let user = session_user(&app, req.headers());
    if path.starts_with("/api/") {
        if user.is_none() {
            return (StatusCode::UNAUTHORIZED, axum::Json(json!({"error": "not logged in"}))).into_response();
        }
        if req.method() != Method::GET && req.headers().get("x-octopus").is_none() {
            return (StatusCode::FORBIDDEN, axum::Json(json!({"error": "missing X-Octopus header"}))).into_response();
        }
    } else if user.is_none() {
        return Redirect::to("/login").into_response();
    }
    let mut req = req;
    req.extensions_mut().insert(UserName(user.unwrap_or_default()));
    next.run(req).await
}

#[derive(Clone)]
struct UserName(String);

fn asset(ct: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "max-age=3600")], body).into_response()
}

// ---- pages

async fn login_page(State(app): State<Shared>) -> Html<String> {
    Html(pages::login(&app.host, None))
}

#[derive(Deserialize)]
struct LoginForm {
    user: String,
    password: String,
}

async fn login_post(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    let app2 = app.clone();
    let ip = client_ip(&headers, peer, &app.own);
    let res = tokio::task::spawn_blocking(move || app2.auth.login(ip, &f.user, &f.password)).await;
    match res {
        Ok(Ok(token)) => {
            let c = format!("{}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=43200", auth::COOKIE);
            ([(header::SET_COOKIE, c)], Redirect::to("/status")).into_response()
        }
        Ok(Err(msg)) => (StatusCode::UNAUTHORIZED, Html(pages::login(&app.host, Some(msg)))).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn logout(State(app): State<Shared>, h: HeaderMap) -> Response {
    if let Some(t) = auth::cookie(hdr(&h, header::COOKIE)) {
        app.auth.logout(&t);
    }
    let c = format!("{}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0", auth::COOKIE);
    ([(header::SET_COOKIE, c)], Redirect::to("/login")).into_response()
}

fn user_of(req: &axum::http::Extensions) -> String {
    req.get::<UserName>().map(|u| u.0.clone()).unwrap_or_default()
}

async fn page(State(app): State<Shared>, req: axum::extract::Request) -> Response {
    let user = user_of(req.extensions());
    let h = &app.host;
    let html = match req.uri().path() {
        "/" => return Redirect::to("/status").into_response(),
        "/status" => pages::status(h, &user),
        "/firewall" => pages::firewall(h, &user),
        "/generations" => pages::generations(h, &user),
        "/dns" => pages::dns(h, &user),
        "/flows" => pages::flows(h, &user),
        "/proxy" => pages::proxy(h, &user),
        "/analyzer" => pages::analyzer(h, &user),
        "/dhcp" => pages::dhcp(h, &user),
        "/vhosts" => pages::vhosts(h, &user),
        "/wifi" => pages::wifi(h, &user),
        "/settings" => pages::settings(h, &user),
        "/config" => pages::config(h, &user, &std::fs::read_to_string(ROUTER_TOML).unwrap_or_default()),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    Html(html).into_response()
}

// ---- privileged actions through doas

async fn octopus(app: &App, args: &[&str]) -> (bool, String) {
    let mut cmd = if app.dev {
        let mut c = tokio::process::Command::new(std::env::var("OCTOPUS_BIN").unwrap_or_else(|_| "octopus".into()));
        c.args(args);
        c
    } else {
        let mut c = tokio::process::Command::new(DOAS);
        c.arg("-n").arg(OCTOPUS).args(args);
        c
    };
    cmd.stdin(std::process::Stdio::null()).kill_on_drop(false);
    match tokio::time::timeout(Duration::from_secs(180), cmd.output()).await {
        Err(_) => (false, "timed out after 180 s".into()),
        Ok(Err(e)) => (false, format!("cannot run octopus: {e}")),
        Ok(Ok(o)) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s += &String::from_utf8_lossy(&o.stderr);
            (o.status.success(), s)
        }
    }
}

async fn api_status(State(app): State<Shared>) -> Response {
    if let Some((t, v)) = app.status.lock().unwrap().as_ref()
        && t.elapsed() < Duration::from_secs(2)
    {
        return axum::Json(v.clone()).into_response();
    }
    let (ok, out) = octopus(&app, &["status", "--json"]).await;
    if !ok {
        return (StatusCode::BAD_GATEWAY, axum::Json(json!({"error": out.trim()}))).into_response();
    }
    match serde_json::from_str::<Value>(&out) {
        Ok(v) => {
            *app.status.lock().unwrap() = Some((Instant::now(), v.clone()));
            axum::Json(v).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, axum::Json(json!({"error": format!("status: {e}")}))).into_response(),
    }
}

async fn api_config() -> Response {
    let toml = std::fs::read_to_string(ROUTER_TOML).unwrap_or_default();
    let summary = edit::summary(&toml);
    let doc = tree::doc_json(&toml).unwrap_or(Value::Null);
    axum::Json(json!({"toml": toml, "summary": summary, "doc": doc})).into_response()
}

/// router.toml's schema (JSON Schema from the Rust types: doc comments,
/// defaults, choices): the settings page builds its forms from it.
async fn api_schema() -> Response {
    static SCHEMA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let s =
        SCHEMA.get_or_init(|| serde_json::to_value(schemars::schema_for!(octopus_config::Config)).unwrap_or_default());
    axum::Json(s.clone()).into_response()
}

#[derive(Deserialize)]
struct EditBody {
    toml: String,
    edit: edit::Edit,
}

/// Apply one structured edit to the text the page holds (not the file: a
/// page can stack several edits before one diff/apply).
async fn api_edit(axum::Json(b): axum::Json<EditBody>) -> Response {
    let out = tokio::task::spawn_blocking(move || {
        let text = edit::apply(&b.toml, &b.edit)?;
        let (ok, diagnostics, _) = check_text(&text);
        let doc = tree::doc_json(&text).unwrap_or(Value::Null);
        Ok::<_, String>(
            json!({"ok": ok, "toml": text, "summary": edit::summary(&text), "doc": doc, "diagnostics": diagnostics}),
        )
    })
    .await;
    match out {
        Ok(Ok(v)) => axum::Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The filter policy as a table (source, destination, action): of the
/// running config (GET), or of the page's working copy (POST {toml}).
async fn api_policy(body: Option<axum::Json<ConfigBody>>) -> Response {
    let rows = tokio::task::spawn_blocking(move || {
        let text = match body {
            Some(b) => b.0.toml,
            None => std::fs::read_to_string(ROUTER_TOML).map_err(|e| format!("{ROUTER_TOML}: {e}"))?,
        };
        let r = resolve_text(&text).map_err(|d| d.into_iter().map(|x| x.msg).collect::<Vec<_>>().join("; "))?;
        Ok::<_, String>(octopus_render::policy::rows(&r))
    })
    .await;
    match rows {
        Ok(Ok(rows)) => axum::Json(json!({"rows": rows})).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": e}))).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct TrafficQuery {
    #[serde(rename = "if")]
    ifname: Option<String>,
    range: Option<String>,
}

async fn api_traffic(State(app): State<Shared>, q: axum::extract::Query<TrafficQuery>) -> Response {
    let ifs = app.traffic.interfaces();
    let ifname = q.ifname.clone().filter(|i| ifs.contains(i)).or_else(|| ifs.first().cloned()).unwrap_or_default();
    let day = q.range.as_deref() == Some("24h");
    let points = app.traffic.points(&ifname, day);
    axum::Json(json!({"interfaces": ifs, "if": ifname, "range": if day { "24h" } else { "1h" }, "step": if day { 60 } else { 5 }, "points": points}))
        .into_response()
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CaptureBody {
    interface: String,
    #[serde(default)]
    fcap: String,
    #[serde(default)]
    pcre: String,
    seconds: u32,
    max_packets: u32,
}

/// A one-shot capture: staged as JSON for octopus-analyzer --oneshot, which
/// runs as root only long enough to open bpf, then as _octoflow.
async fn api_capture(State(app): State<Shared>, axum::Json(b): axum::Json<CaptureBody>) -> Response {
    if b.seconds == 0 || b.seconds > 30 || b.max_packets == 0 || b.max_packets > 500 {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "1-30 seconds, 1-500 packets"}))).into_response();
    }
    let Ok(_g) = app.capture.try_lock() else {
        return (StatusCode::CONFLICT, axum::Json(json!({"error": "a capture is already running"}))).into_response();
    };
    let req = serde_json::to_vec(&b).unwrap_or_default();
    let path = if app.dev {
        std::env::var("OCTOPUS_CAPTURE").unwrap_or_else(|_| "/tmp/capture.json".into())
    } else {
        CAPTURE.into()
    };
    if let Err(e) = std::fs::write(&path, req) {
        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": format!("stage: {e}")})))
            .into_response();
    }
    let mut cmd = if app.dev {
        tokio::process::Command::new(
            std::env::var("OCTOPUS_ANALYZER_BIN").unwrap_or_else(|_| "octopus-analyzer".into()),
        )
    } else {
        let mut c = tokio::process::Command::new(DOAS);
        c.arg("-n").arg(ANALYZER);
        c
    };
    cmd.arg("--oneshot").arg(&path).stdin(std::process::Stdio::null()).kill_on_drop(true);
    let r = tokio::time::timeout(Duration::from_secs(b.seconds as u64 + 15), cmd.output()).await;
    match r {
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, axum::Json(json!({"error": "capture did not finish"}))).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_GATEWAY, axum::Json(json!({"error": format!("cannot run the analyzer: {e}")})))
            .into_response(),
        Ok(Ok(o)) => match serde_json::from_slice::<Value>(&o.stdout) {
            Ok(v) if o.status.success() => axum::Json(v).into_response(),
            _ => {
                let msg = String::from_utf8_lossy(&o.stderr).trim().to_string();
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": if msg.is_empty() { "capture failed".into() } else { msg }})),
                )
                    .into_response()
            }
        },
    }
}

#[derive(Deserialize)]
struct ConfigBody {
    toml: String,
}

/// Parse and bind to this machine's interfaces (by MAC).
fn resolve_text(text: &str) -> Result<octopus_config::Router, Vec<octopus_config::Diag>> {
    let cfg = octopus_config::parse(text)
        .map_err(|e| vec![octopus_config::Diag { level: octopus_config::Level::Error, code: "E-TOML", msg: e }])?;
    let macs = std::process::Command::new("/sbin/ifconfig")
        .arg("-a")
        .output()
        .ok()
        .filter(|_| cfg!(target_os = "openbsd"))
        .map(|o| octopus_config::ifmap::parse_ifconfig(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();
    octopus_config::Router::resolve(cfg, &macs).map_err(|d| d.0)
}

/// Compile with placeholder secrets: diagnostics and the rendered paths.
fn check_text(text: &str) -> (bool, Vec<Value>, Vec<String>) {
    let diag = |level: &str, code: &str, msg: String| json!({"level": level, "code": code, "msg": msg});
    if text.len() > 1 << 20 {
        return (false, vec![diag("error", "E-SIZE", "larger than 1 MiB".into())], vec![]);
    }
    let r = match resolve_text(text) {
        Ok(r) => r,
        Err(d) => return (false, d.iter().map(|x| diag("error", x.code, x.msg.clone())).collect(), vec![]),
    };
    let d = octopus_config::check::check(&r, None);
    let list: Vec<Value> = d
        .0
        .iter()
        .map(|x| diag(if x.level == octopus_config::Level::Error { "error" } else { "warning" }, x.code, x.msg.clone()))
        .collect();
    if d.has_errors() {
        return (false, list, vec![]);
    }
    match octopus_render::render(&r, &octopus_render::SecretSource::Placeholder) {
        Ok(g) => (true, list, g.files.iter().map(|f| f.path.clone()).collect()),
        Err(e) => {
            let mut l = list;
            l.push(diag("error", "E-RENDER", e));
            (false, l, vec![])
        }
    }
}

async fn api_check(axum::Json(b): axum::Json<ConfigBody>) -> Response {
    let (ok, diagnostics, files) =
        tokio::task::spawn_blocking(move || check_text(&b.toml)).await.unwrap_or((false, vec![], vec![]));
    axum::Json(json!({"ok": ok, "diagnostics": diagnostics, "files": files})).into_response()
}

fn stage(text: &str, user: &str) -> Result<(), String> {
    let dir = std::path::Path::new(STAGED_DIR);
    let tmp = dir.join(".router.toml.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("stage: {e}"))?;
    std::fs::rename(&tmp, dir.join("router.toml")).map_err(|e| format!("stage: {e}"))?;
    std::fs::write(
        dir.join("actor"),
        user.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect::<String>(),
    )
    .map_err(|e| format!("stage: {e}"))
}

async fn staged_action(app: &App, req_user: &str, text: String, args: &[&str]) -> Response {
    let t2 = text.clone();
    let (ok, diagnostics, _) =
        tokio::task::spawn_blocking(move || check_text(&t2)).await.unwrap_or((false, vec![], vec![]));
    if !ok {
        return axum::Json(json!({"ok": false, "diagnostics": diagnostics, "output": "check failed", "diff": ""}))
            .into_response();
    }
    let _g = app.action.lock().await;
    if let Err(e) = stage(&text, req_user) {
        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": e}))).into_response();
    }
    let (ok, out) = octopus(app, args).await;
    *app.status.lock().unwrap() = None;
    axum::Json(json!({"ok": ok, "diagnostics": diagnostics, "output": out, "diff": out})).into_response()
}

async fn api_diff(State(app): State<Shared>, req: axum::extract::Request) -> Response {
    let user = user_of(req.extensions());
    let Ok(b) = body_json(req).await else { return StatusCode::BAD_REQUEST.into_response() };
    staged_action(&app, &user, b.toml, &["diff", "--staged"]).await
}

async fn api_apply(State(app): State<Shared>, req: axum::extract::Request) -> Response {
    let user = user_of(req.extensions());
    let Ok(b) = body_json(req).await else { return StatusCode::BAD_REQUEST.into_response() };
    staged_action(&app, &user, b.toml, &["apply", "--staged"]).await
}

async fn body_json(req: axum::extract::Request) -> Result<ConfigBody, ()> {
    let bytes = axum::body::to_bytes(req.into_body(), 2 << 20).await.map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

async fn api_simple(app: &App, args: &[&str]) -> Response {
    let _g = app.action.lock().await;
    let (ok, out) = octopus(app, args).await;
    *app.status.lock().unwrap() = None;
    axum::Json(json!({"ok": ok, "output": out.trim()})).into_response()
}

#[derive(Deserialize)]
struct SecretBody {
    key: String,
    value: String,
}

/// A Wi-Fi passphrase into secrets.toml: staged for `octopus secret
/// --staged` (wifi_* keys only), never read back, never logged.
async fn api_secret(State(app): State<Shared>, axum::Json(b): axum::Json<SecretBody>) -> Response {
    let dir =
        if app.dev { std::env::var("OCTOPUS_STAGED").unwrap_or_else(|_| "/tmp".into()) } else { STAGED_DIR.into() };
    let path = std::path::Path::new(&dir).join("secret.json");
    let body = json!({"key": b.key, "value": b.value}).to_string();
    let staged = {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::remove_file(&path);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(body.as_bytes()))
    };
    if let Err(e) = staged {
        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": format!("stage: {e}")})))
            .into_response();
    }
    let r = api_simple(&app, &["secret", "--staged"]).await;
    let _ = std::fs::remove_file(&path);
    r
}

#[derive(Deserialize)]
struct ReleaseBody {
    mac: String,
}

/// Lift the guard's block on a device (`octopus guard release --staged`).
async fn api_guard_release(State(app): State<Shared>, axum::Json(b): axum::Json<ReleaseBody>) -> Response {
    let dir =
        if app.dev { std::env::var("OCTOPUS_STAGED").unwrap_or_else(|_| "/tmp".into()) } else { STAGED_DIR.into() };
    let path = std::path::Path::new(&dir).join("guard.json");
    if let Err(e) = std::fs::write(&path, json!({"mac": b.mac}).to_string()) {
        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": format!("stage: {e}")})))
            .into_response();
    }
    let r = api_simple(&app, &["guard", "release", "--staged"]).await;
    let _ = std::fs::remove_file(&path);
    r
}

#[derive(Deserialize)]
struct PushBody {
    #[serde(default)]
    force: bool,
}

async fn api_ap_push(State(app): State<Shared>, axum::Json(b): axum::Json<PushBody>) -> Response {
    if b.force { api_simple(&app, &["ap", "push", "--force"]).await } else { api_simple(&app, &["ap", "push"]).await }
}

async fn api_confirm(State(app): State<Shared>) -> Response {
    api_simple(&app, &["confirm"]).await
}

async fn api_rollback(State(app): State<Shared>) -> Response {
    api_simple(&app, &["rollback"]).await
}

fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/status", get(page))
        .route("/firewall", get(page))
        .route("/dhcp", get(page))
        .route("/config", get(page))
        .route("/generations", get(page))
        .route("/dns", get(page))
        .route("/flows", get(page))
        .route("/proxy", get(page))
        .route("/analyzer", get(page))
        .route("/vhosts", get(page))
        .route("/wifi", get(page))
        .route("/settings", get(page))
        .route("/login", get(login_page).post(login_post))
        .route("/logout", post(logout))
        .route("/x11.css", get(|| async { asset("text/css", X11_CSS) }))
        .route("/x11.js", get(|| async { asset("text/javascript", X11_JS) }))
        .route("/octopus.css", get(|| async { asset("text/css", OCTO_CSS) }))
        .route("/octopus.js", get(|| async { asset("text/javascript", OCTO_JS) }))
        .route(
            "/nav.js",
            get(|| async { ([(header::CONTENT_TYPE, "text/javascript")], pages::nav_js()).into_response() }),
        )
        .route("/api/status", get(api_status))
        .route("/api/config", get(api_config))
        .route("/api/check", post(api_check))
        .route("/api/diff", post(api_diff))
        .route("/api/apply", post(api_apply))
        .route("/api/confirm", post(api_confirm))
        .route("/api/rollback", post(api_rollback))
        .route("/api/edit", post(api_edit))
        .route("/api/policy", get(api_policy).post(api_policy))
        .route("/api/schema", get(api_schema))
        .route("/api/secret", post(api_secret))
        .route("/api/ap-push", post(api_ap_push))
        .route("/api/guard-release", post(api_guard_release))
        .route("/api/traffic", get(api_traffic))
        .route("/api/capture", post(api_capture))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

fn tls(conf: &Conf) -> Result<TlsAcceptor, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&conf.cert)
        .map_err(|e| format!("{}: {e}", conf.cert))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", conf.cert))?;
    let key = PrivateKeyDer::from_pem_file(&conf.key).map_err(|e| format!("{}: {e}", conf.key))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("certificate: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

#[cfg(target_os = "openbsd")]
fn sandbox() -> Result<(), String> {
    use std::ffi::CString;
    let paths: [(&str, &str); 9] = [
        (DOAS, "x"),
        ("/sbin/ifconfig", "x"),
        ("/usr/bin/netstat", "x"),
        (ROUTER_TOML, "r"),
        (STAGED_DIR, "rwc"),
        ("/dev/null", "rw"),
        ("/etc/passwd", "r"),
        ("/etc/group", "r"),
        ("/etc/localtime", "r"),
    ];
    unsafe {
        for (p, perm) in paths {
            let p = CString::new(p).unwrap();
            let perm = CString::new(perm).unwrap();
            if libc::unveil(p.as_ptr(), perm.as_ptr()) != 0 {
                return Err(format!("unveil {p:?}"));
            }
        }
        if libc::unveil(std::ptr::null(), std::ptr::null()) != 0 {
            return Err("unveil lock".into());
        }
        if libc::pledge(c"stdio rpath wpath cpath inet proc exec".as_ptr(), std::ptr::null()) != 0 {
            return Err("pledge".into());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
fn sandbox() -> Result<(), String> {
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut conf_path = CONF.to_string();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-f" => conf_path = args.next().expect("-f needs a file"),
            "--hash" => {
                // read a password on stdin, print a bcrypt hash for the users file
                let mut pw = String::new();
                std::io::stdin().read_line(&mut pw).expect("stdin");
                println!("{}", bcrypt::hash(pw.trim_end_matches(['\n', '\r']), 10).expect("bcrypt"));
                return;
            }
            "--schema" => {
                // router.toml's JSON Schema, as /api/schema serves it
                println!(
                    "{}",
                    serde_json::to_string_pretty(&schemars::schema_for!(octopus_config::Config)).unwrap_or_default()
                );
                return;
            }
            _ => {
                eprintln!("usage: octopus-web [-f web.toml] | --hash < password | --schema");
                std::process::exit(2);
            }
        }
    }
    if let Err(e) = run(&conf_path) {
        eprintln!("octopus-web: {e}");
        std::process::exit(1);
    }
}

fn run(conf_path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(conf_path).map_err(|e| format!("{conf_path}: {e}"))?;
    let conf: Conf = toml::from_str(&text).map_err(|e| format!("{conf_path}: {e}"))?;
    let acceptor = tls(&conf)?;
    let auth = auth::Auth::load(&conf.users)?;
    let own: Vec<std::net::IpAddr> =
        conf.listen.iter().filter_map(|l| l.parse::<SocketAddr>().ok()).map(|a| a.ip()).collect();
    let state = Arc::new(App {
        host: conf.hostname.clone(),
        own,
        auth,
        status: Mutex::new(None),
        action: tokio::sync::Mutex::new(()),
        capture: tokio::sync::Mutex::new(()),
        traffic: Arc::new(traffic::Traffic::default()),
        dev: std::env::var_os("OCTOPUS_WEB_DEV").is_some(),
    });
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let mut listeners = vec![];
        for l in &conf.listen {
            let addr: SocketAddr = l.parse().map_err(|_| format!("listen {l:?}: not ip:port"))?;
            listeners.push(TcpListener::bind(addr).await.map_err(|e| format!("{addr}: {e}"))?);
        }
        sandbox()?;
        tokio::spawn(traffic::sampler(state.traffic.clone()));
        eprintln!("octopus-web: listening on {}", conf.listen.join(", "));
        let app = app(state);
        let mut tasks = vec![];
        for l in listeners {
            let app = app.clone();
            let acceptor = acceptor.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((tcp, peer)) = l.accept().await else { continue };
                    let acceptor = acceptor.clone();
                    let svc = app.clone().layer(axum::Extension(ConnectInfo(peer)));
                    tokio::spawn(async move {
                        let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
                        else {
                            return;
                        };
                        let svc = TowerToHyperService::new(svc);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .timer(hyper_util::rt::TokioTimer::new())
                            .header_read_timeout(Duration::from_secs(15))
                            .serve_connection(TokioIo::new(tls), svc)
                            .await;
                    });
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
        Ok::<(), String>(())
    })
}
