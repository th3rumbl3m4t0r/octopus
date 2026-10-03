//! Page shells in the x11 look. Data arrives from /api/status through
//! octopus.js; the server only renders the frame, the config text and names.

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

pub const PAGES: [(&str, &str); 12] = [
    // not "/": x11.js marks a link current when the path starts with it
    ("status", "/status"),
    ("firewall", "/firewall"),
    ("dns", "/dns"),
    ("dhcp", "/dhcp"),
    ("wifi", "/wifi"),
    ("reverse proxy", "/vhosts"),
    ("egress proxy", "/proxy"),
    ("flows", "/flows"),
    ("analyzer", "/analyzer"),
    ("settings", "/settings"),
    ("config", "/config"),
    ("generations", "/generations"),
];

fn head(title: &str, host: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\" class=\"theme-night\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{} · octopus · {}</title>\n<link rel=\"stylesheet\" href=\"/x11.css\">\n\
         <link rel=\"stylesheet\" href=\"/octopus.css\">\n<script src=\"/nav.js\"></script>\n\
         <script src=\"/x11.js\"></script>\n</head>\n",
        esc(title),
        esc(host)
    )
}

/// The nav list for x11.js (served as /nav.js so the CSP can stay strict).
pub fn nav_js() -> String {
    let items: Vec<String> = PAGES.iter().map(|(n, h)| format!("{{ name: '{n}', href: '{h}' }}")).collect();
    format!("window.X11_CONFIG = {{ nav: [{}] }};\n", items.join(", "))
}

fn topbar(host: &str, user: &str) -> String {
    format!(
        "<header id=\"topbar\"><div class=\"bar\">\n\
         <a class=\"brand\" href=\"/status\">octopus <small>// {}</small></a>\n\
         <nav data-x11-nav></nav>\n<span class=\"spacer\"></span>\n\
         <span class=\"dim\">{}</span>\n\
         <form method=\"post\" action=\"/logout\" class=\"row\"><button type=\"submit\">logout</button></form>\n\
         <span data-x11-controls></span>\n</div></header>\n\
         <div class=\"statusbar\" id=\"statusbar\"><span class=\"dim\">loading <span class=\"busy\"></span></span></div>\n",
        esc(host),
        esc(user)
    )
}

const PENDING: &str = "<section class=\"win pending span2\" id=\"pending\" hidden>\n\
    <div class=\"titlebar\"><span class=\"grip\">::</span>pending generation<span class=\"spacer\"></span></div>\n\
    <div class=\"body\"><div id=\"pending-text\"></div>\n\
    <div class=\"row\"><button class=\"primary\" id=\"btn-confirm\">confirm</button>\
    <button class=\"danger\" id=\"btn-rollback\">roll back now</button>\
    <span class=\"dim\">confirm only if you can still reach everything you need</span></div></div>\n</section>\n";

/// Edits made on any page, held in the browser until they go through diff /
/// apply like the config page.
const CHANGES: &str = "<section class=\"win changes span2\" id=\"changes\" hidden>\n\
    <div class=\"titlebar\"><span class=\"grip\">::</span>unapplied changes<span class=\"spacer\"></span>\
    <span class=\"dim\">to router.toml, nothing is live yet</span></div>\n\
    <div class=\"body\"><ul id=\"changes-list\"></ul><div id=\"changes-diag\"></div>\n\
    <div class=\"row\"><button id=\"btn-wdiff\">diff</button><button class=\"primary\" id=\"btn-wapply\">apply</button>\
    <button class=\"danger\" id=\"btn-wdiscard\">discard</button>\
    <span class=\"dim\">apply = the same check, apply and 60 s confirm as the config page</span></div>\n\
    <pre class=\"diff\" id=\"changes-out\" hidden></pre></div>\n</section>\n";

const TOAST: &str =
    "<div class=\"win toast\" id=\"toast\" hidden><div class=\"titlebar\"></div><div class=\"body\"></div></div>\n";

fn win(title: &str, extra: &str, body: &str, class: &str) -> String {
    format!(
        "<section class=\"win {class}\">\n<div class=\"titlebar\"><span class=\"grip\">::</span>{}<span class=\"spacer\"></span>{extra}</div>\n\
         <div class=\"body\">{body}</div>\n</section>\n",
        esc(title)
    )
}

fn page(name: &str, host: &str, user: &str, main_class: &str, content: &str) -> String {
    format!(
        "{}<body data-page=\"{name}\">\n{}<main class=\"{main_class}\">\n{PENDING}{CHANGES}{content}</main>\n{TOAST}\
         <footer class=\"statusbar\"><span>octopus {}</span><span class=\"spacer\"></span>\
         <span>OpenBSD router; the config compiler is not in the forwarding path</span></footer>\n\
         <script src=\"/octopus.js\"></script>\n</body>\n</html>\n",
        head(name, host),
        topbar(host, user),
        env!("CARGO_PKG_VERSION")
    )
}

pub fn status(host: &str, user: &str) -> String {
    let c = win("interfaces", "", "<table class=\"x11\" id=\"t-ifaces\"></table>", "span2")
        + &win(
            "traffic",
            "<select id=\"tr-if\" aria-label=\"interface\"></select>\
             <select id=\"tr-range\" aria-label=\"range\"><option value=\"1h\">1 hour</option><option value=\"24h\">24 hours</option></select>",
            "<div class=\"graph\" id=\"tr-graph\"></div><div class=\"axis dim\" id=\"tr-axis\"></div>\
             <div class=\"row\" id=\"tr-legend\"></div>",
            "span2",
        )
        + &win(
            "ipv6",
            "<span class=\"dim\" id=\"v6-summary\"></span>",
            "<table class=\"x11\" id=\"t-v6\"></table><pre id=\"v6-lease\" class=\"dim\"></pre>",
            "",
        )
        + &win("services", "", "<table class=\"x11\" id=\"t-services\"></table>", "")
        + &win("busiest rules", "<a href=\"/firewall\">all</a>", "<table class=\"x11\" id=\"t-top\"></table>", "")
        + &win("octopus events", "<span class=\"dim\">/var/log/daemon</span>", "<pre id=\"log\"></pre>", "span2");
    page("status", host, user, "", &c)
}

pub fn firewall(host: &str, user: &str) -> String {
    let c = win(
        "new rule",
        "<span class=\"dim\" id=\"fw-mode\">click a rule below to start from it</span>",
        "<div id=\"fw-new\"></div>",
        "span2",
    ) + &win(
        "overview",
        "<span class=\"dim\">router.toml with unapplied changes; counters from pfctl -sl</span>",
        "<table class=\"x11 pick\" id=\"t-policy\"></table>",
        "span2",
    ) + &win(
        "rule counters",
        "<span class=\"dim\">pfctl -sl</span>",
        "<table class=\"x11\" id=\"t-labels\"></table>",
        "",
    ) + &win(
        "pf tables",
        "<span class=\"dim\">named address lists the rules use (pfctl -sT)</span>",
        "<table class=\"x11\" id=\"t-tables\"></table>",
        "span2",
    ) + &win(
        "blocked devices",
        "<span class=\"dim\">used an address their tier keeps for listed devices; cut off from the router</span>",
        "<table class=\"x11\" id=\"t-guard\"></table>",
        "span2",
    ) + &win("queues", "<span class=\"dim\">pfctl -vsq</span>", "<pre id=\"queues\"></pre>", "span2");
    page("firewall", host, user, "", &c)
}

/// A list of router.toml entries with an editor (octopus.js builds it from
/// the schema): `path` is the list, e.g. `["hosts"]`.
fn list_editor(id: &str, path: &str) -> String {
    format!("<div class=\"lsted\" id=\"{id}\" data-path=\"{}\"></div>", esc(path))
}

pub fn dhcp(host: &str, user: &str) -> String {
    let c = win(
        "reservations",
        "<span class=\"dim\">[[hosts]] with a mac: always the same address</span>",
        &list_editor("le-hosts", "[\"hosts\"]"),
        "span2",
    ) + &win(
        "leases",
        "<span class=\"dim\">Kea's leases; reserve keeps a device on its address</span>",
        "<table class=\"x11\" id=\"t-leases\"></table>",
        "span2",
    );
    page("dhcp", host, user, "", &c)
}

pub fn dns(host: &str, user: &str) -> String {
    let views = "<div id=\"dns-setup\"></div><table class=\"x11\" id=\"t-dviews\"></table>\n\
         <form class=\"row\" id=\"f-view\"><input id=\"view-client\" list=\"dl-hosts\" placeholder=\"host, address or prefix\" required>\
         <select id=\"view-name\" aria-label=\"view\"></select><button type=\"submit\">add</button></form>\
         <datalist id=\"dl-hosts\"></datalist>";
    let sinkhole = "<div id=\"sink-now\"></div>\n\
         <form class=\"row\" id=\"f-sinkhole\"><input id=\"sink-ip\" placeholder=\"IPv4 address\" size=\"15\">\
         <button type=\"submit\">set</button><button type=\"button\" id=\"btn-sink-clear\">remove</button></form>\
         <div class=\"dim\">names the upstream blocks (Cloudflare security answers 0.0.0.0) resolve here instead, \
         logged as blocked; AAAA gets no answer</div>";
    let c = win("upstreams and views", "<span class=\"dim\">which resolver answers whom</span>", views, "")
        + &win("sinkhole", "<span class=\"dim\">dns.sinkhole</span>", sinkhole, "")
        + &win(
            "top names",
            "<span class=\"dim\">click a name to override it</span>",
            "<table class=\"x11 pick\" id=\"t-names\"></table>",
            "",
        )
        + &win("top clients", "", "<table class=\"x11\" id=\"t-clients\"></table>", "")
        + &win(
            "views",
            "<span class=\"dim\">which upstreams answered</span>",
            "<table class=\"x11\" id=\"t-views\"></table>",
            "",
        )
        + &win(
            "classified",
            "<span class=\"dim\">answers sent to cls_* tables</span>",
            "<table class=\"x11\" id=\"t-classes\"></table>",
            "",
        )
        + &win(
            "overrides",
            "<span class=\"dim\">a name (and its subdomains) answered with one address: blackholing, or an inside host</span>",
            &list_editor("le-overrides", "[\"dns\", \"overrides\"]"),
            "span2",
        )
        + &win(
            "recent queries",
            "<span class=\"dim\" id=\"dns-summary\"></span>",
            "<table class=\"x11 pick\" id=\"t-queries\"></table>",
            "span2",
        );
    page("dns", host, user, "", &c)
}

pub fn flows(host: &str, user: &str) -> String {
    let c = win(
        "recent flows",
        "<span class=\"dim\" id=\"flows-summary\"></span>",
        "<table class=\"x11\" id=\"t-flows\"></table>",
        "span2",
    ) + &win(
        "top names",
        "<span class=\"dim\">by bytes</span>",
        "<table class=\"x11\" id=\"t-fnames\"></table>",
        "",
    ) + &win(
        "top clients",
        "<span class=\"dim\">by bytes</span>",
        "<table class=\"x11\" id=\"t-fclients\"></table>",
        "",
    );
    page("flows", host, user, "", &c)
}

pub fn proxy(host: &str, user: &str) -> String {
    let c =
        win(
            "servers' web traffic",
            "<span class=\"dim\" id=\"proxy-summary\"></span>",
            "<table class=\"x11\" id=\"t-proxy\"></table>",
            "span2",
        ) + &win("hosts", "<span class=\"dim\">decisions</span>", "<table class=\"x11\" id=\"t-phosts\"></table>", "");
    page("proxy", host, user, "", &c)
}

pub fn analyzer(host: &str, user: &str) -> String {
    let adhoc = "<form class=\"row\" id=\"f-capture\"><select id=\"cap-if\" aria-label=\"interface\"></select>\
         <input id=\"cap-fcap\" class=\"grow\" placeholder=\"FCAP, e.g. proto tcp and dst port 80 (empty: every packet)\">\
         <input id=\"cap-pcre\" class=\"grow\" placeholder=\"PCRE on the payload, e.g. (?i)union\\s+select (empty: no regex)\">\
         <label class=\"row\">for <input id=\"cap-sec\" type=\"number\" min=\"1\" max=\"30\" value=\"10\" size=\"3\"> s</label>\
         <label class=\"row\">at most <input id=\"cap-max\" type=\"number\" min=\"1\" max=\"500\" value=\"100\" size=\"4\"> packets</label>\
         <button class=\"primary\" type=\"submit\" id=\"btn-capture\">capture</button>\
         <button type=\"button\" id=\"pkt-pcap\" disabled>download pcap</button></form>\
         <div class=\"dim\" id=\"cap-status\">matches the expressions on live traffic for a while and lists what matched; \
         nothing runs before or after, nothing is stored on the router</div>\
         <div class=\"dim\" id=\"pkt-summary\"></div>\
         <table class=\"x11 pick\" id=\"t-packets\"></table>\n<pre class=\"hex\" id=\"pkt-hex\"></pre>";
    let rules =
        "<div class=\"row\"><label class=\"row\"><input type=\"checkbox\" id=\"an-enabled\">run the standing rules \
         (octopus-analyzer, always on)</label><span class=\"dim\" id=\"an-state\"></span></div>"
            .to_string()
            + &list_editor("le-analyzer", "[\"analyzer\", \"rules\"]");
    let c = win("ad hoc", "<span class=\"dim\">FCAP + PCRE on demand</span>", adhoc, "span2")
        + &win(
            "standing rules",
            "<span class=\"dim\">[analyzer]: FCAP filter (locked BPF) and an optional PCRE, logged, kept in pcaps or blocked</span>",
            &rules,
            "span2",
        )
        + "<div class=\"running\" id=\"an-running\" hidden>"
        + &win(
            "matches",
            "<span class=\"dim\" id=\"an-summary\"></span>",
            "<table class=\"x11\" id=\"t-amatch\"></table>",
            "span2",
        )
        + &win(
            "lab_block",
            "<span class=\"dim\">sources blocked by block rules</span>",
            "<table class=\"x11\" id=\"t-ablock\"></table>",
            "",
        )
        + &win(
            "pcaps",
            "<span class=\"dim\">/var/octopus/pcap</span>",
            "<table class=\"x11\" id=\"t-pcaps\"></table>",
            "",
        )
        + "</div>";
    page("analyzer", host, user, "", &c)
}

pub fn vhosts(host: &str, user: &str) -> String {
    let help = "<div class=\"dim\">Each site is one or more host names proxied to one inside address. \
        Names in the internal zone get a certificate from the services root. For names on the internet \
        (behind Cloudflare, say) tick <b>public</b>: nginx answers on the WAN too, pf opens tcp 80 and 443 there, \
        and Let's Encrypt (acme-client) issues the certificate, or give the <b>cert</b> and <b>key</b> files of a \
        Cloudflare origin certificate. <b>allow_from = cloudflare</b> lets only Cloudflare in. \
        Point the names at the WAN address (proxied in Cloudflare, SSL mode Full (strict)); \
        inside, they resolve to the router.</div>";
    let c = win(
        "sites",
        "<span class=\"dim\">[[vhosts]], served by nginx</span>",
        &(list_editor("le-vhosts", "[\"vhosts\"]") + help),
        "span2",
    );
    page("vhosts", host, user, "", &c)
}

pub fn wifi(host: &str, user: &str) -> String {
    let aps = list_editor("le-aps", "[\"wifi\", \"aps\"]")
        + "<div class=\"row\"><button type=\"button\" id=\"btn-push\">push to the access points now</button>\
           <button type=\"button\" id=\"btn-push-force\">push everything again</button>\
           <span class=\"dim\">apply pushes what changed by itself; an access point that was away gets it here</span></div>";
    let adopt = "<div class=\"dim\">An access point joins in three steps: flash it with OpenWrt built by \
         <code>deploy/ap-image.sh</code> (plain OpenWrt plus this router's key below, an address by DHCP, nothing else), \
         give it a reservation on the dhcp page (its mac and the address it should have), and add it above. \
         Octopus then owns its Wi-Fi and network settings.</div>\
         <div>router's key for the access points: <code id=\"ap-key\" class=\"wrap\">…</code></div>";
    let c = win(
        "wifi networks",
        "<span class=\"dim\">SSIDs, each onto a tier; guests' clients are kept apart</span>",
        &("<div class=\"row\" id=\"wifi-country\"></div>".to_string()
            + &list_editor("le-ssids", "[\"wifi\", \"networks\"]")),
        "span2",
    ) + &win("access points", "<span class=\"dim\">OpenWrt, configured over SSH</span>", &aps, "span2")
        + &win("assimilating an access point", "", adopt, "span2");
    page("wifi", host, user, "", &c)
}

pub fn settings(host: &str, user: &str) -> String {
    let c = "<section class=\"win settings-nav\">\n<div class=\"titlebar\"><span class=\"grip\">::</span>router.toml</div>\n\
             <div class=\"body\" id=\"set-nav\"></div>\n</section>\n\
             <section class=\"win settings-main\">\n<div class=\"titlebar\"><span class=\"grip\">::</span><span id=\"set-title\">settings</span>\
             <span class=\"spacer\"></span><span class=\"dim\">changes collect above; diff and apply there</span></div>\n\
             <div class=\"body\" id=\"set-body\"></div>\n</section>\n";
    page("settings", host, user, "settings", c)
}

pub fn generations(host: &str, user: &str) -> String {
    let c = win(
        "generations",
        "<span class=\"dim\">/var/octopus/gen</span>",
        "<table class=\"x11\" id=\"t-gens\"></table>\
         <div class=\"dim\">roll back to a specific generation on the router: <code>octopus rollback N</code></div>",
        "",
    );
    page("generations", host, user, "wide", &c)
}

pub fn config(host: &str, user: &str, toml: &str) -> String {
    let editor = format!(
        "<textarea class=\"config\" id=\"config-text\" spellcheck=\"false\" autocomplete=\"off\">{}</textarea>\n\
         <div class=\"row\"><button id=\"btn-check\">check</button><button id=\"btn-diff\">diff</button>\
         <button class=\"primary\" id=\"btn-apply\">apply</button><button id=\"btn-reload\">reload</button>\
         <span class=\"dim\">apply = build, validate, apply, then 60 s to confirm or it rolls back</span></div>",
        esc(toml)
    );
    let c = win("router.toml", "<span class=\"dim\">/etc/octopus/router.toml</span>", &editor, "")
        + "<section class=\"win\">\n<div class=\"titlebar\"><span class=\"grip\">::</span><span id=\"out-title\">output</span></div>\n\
           <div class=\"body\" id=\"out\"><span class=\"dim\">check validates the file and the invariants; diff shows what would change on the router (files with secrets are hidden)</span></div>\n</section>\n";
    page("config", host, user, "", &c)
}

pub fn login(host: &str, error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"bad\">{}</div>", esc(e))).unwrap_or_default();
    format!(
        "{}<body data-page=\"login\">\n<main class=\"wide\"><section class=\"win login\">\n\
         <div class=\"titlebar\"><span class=\"grip\">::</span>octopus // {}</div>\n<div class=\"body\">\n\
         <pre class=\"art\">   ___\n  (o o)\n /(   )\\\n  /|||\\\n</pre>\n\
         <form method=\"post\" action=\"/login\">\n<label class=\"lbl\" for=\"u\">user</label>\
         <input id=\"u\" name=\"user\" autocomplete=\"username\" autofocus>\n\
         <label class=\"lbl\" for=\"p\">password</label><input id=\"p\" name=\"password\" type=\"password\" autocomplete=\"current-password\">\n\
         {err}<div class=\"row\"><button class=\"primary\" type=\"submit\">login</button></div>\n</form>\n</div></section></main>\n</body>\n</html>\n",
        head("login", host),
        esc(host)
    )
}
