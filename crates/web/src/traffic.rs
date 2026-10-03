//! Interface traffic for the status page's graphs. Every 5 s the web UI
//! reads the byte counters (`netstat -ibn` needs no privileges) and keeps
//! the rates in memory: an hour at 5 s, a day at 1 min. A restart starts
//! the graphs over; nothing is written to disk.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FINE: usize = 720;
const COARSE: usize = 1440;
const SKIP: [&str; 5] = ["lo", "enc", "pflog", "pflow", "pfsync"];

/// (unix seconds, received bits/s, sent bits/s)
pub type Point = (u64, u64, u64);

#[derive(Default)]
struct If {
    last: Option<(Instant, u64, u64)>,
    fine: VecDeque<Point>,
    coarse: VecDeque<Point>,
    acc: (u64, u64, u32),
}

#[derive(Default)]
pub struct Traffic {
    ifs: Mutex<BTreeMap<String, If>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The link line of each interface: Name Mtu <Link> Address Ibytes Obytes.
pub fn parse_netstat(text: &str) -> Vec<(String, u64, u64)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = vec![];
    for l in text.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 5 || !f[2].starts_with("<Link") || !seen.insert(f[0].to_string()) {
            continue;
        }
        let name = f[0].trim_end_matches('*');
        let stem: String = name.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
        if SKIP.contains(&stem.as_str()) {
            continue;
        }
        let n = f.len();
        if let (Ok(i), Ok(o)) = (f[n - 2].parse(), f[n - 1].parse()) {
            out.push((name.to_string(), i, o));
        }
    }
    out
}

impl Traffic {
    pub fn record(&self, counters: Vec<(String, u64, u64)>) {
        let t = Instant::now();
        let ts = now();
        let mut ifs = self.ifs.lock().unwrap();
        for (name, rx, tx) in counters {
            let e = ifs.entry(name).or_default();
            if let Some((t0, rx0, tx0)) = e.last {
                let dt = t.duration_since(t0).as_secs_f64().max(0.001);
                // a counter that went backwards (interface recreated) starts over
                if rx >= rx0 && tx >= tx0 {
                    let p = (ts, ((rx - rx0) as f64 * 8.0 / dt) as u64, ((tx - tx0) as f64 * 8.0 / dt) as u64);
                    e.fine.push_back(p);
                    if e.fine.len() > FINE {
                        e.fine.pop_front();
                    }
                    e.acc = (e.acc.0 + p.1, e.acc.1 + p.2, e.acc.2 + 1);
                    if e.acc.2 == 12 {
                        e.coarse.push_back((ts, e.acc.0 / 12, e.acc.1 / 12));
                        if e.coarse.len() > COARSE {
                            e.coarse.pop_front();
                        }
                        e.acc = (0, 0, 0);
                    }
                }
            }
            e.last = Some((t, rx, tx));
        }
    }

    pub fn interfaces(&self) -> Vec<String> {
        self.ifs.lock().unwrap().keys().cloned().collect()
    }

    pub fn points(&self, ifname: &str, day: bool) -> Vec<Point> {
        let ifs = self.ifs.lock().unwrap();
        ifs.get(ifname)
            .map(|e| if day { e.coarse.iter().copied().collect() } else { e.fine.iter().copied().collect() })
            .unwrap_or_default()
    }
}

/// Sample forever (OpenBSD's netstat; elsewhere this finds nothing).
pub async fn sampler(t: std::sync::Arc<Traffic>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        if let Ok(o) = tokio::process::Command::new("/usr/bin/netstat")
            .arg("-ibn")
            .stdin(std::process::Stdio::null())
            .output()
            .await
        {
            t.record(parse_netstat(&String::from_utf8_lossy(&o.stdout)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates() {
        let text = "Name    Mtu   Network     Address              Ibytes       Obytes\n\
                    vio0    1500  <Link>      02:00:5e:10:00:21    1000         2000\n\
                    vio0    1500  192.168.1/2 192.168.1.41         1000         2000\n\
                    lo0     32768 <Link>                           5            5\n";
        let c = parse_netstat(text);
        assert_eq!(c, vec![("vio0".to_string(), 1000, 2000)]);
        let t = Traffic::default();
        t.record(c);
        std::thread::sleep(Duration::from_millis(100));
        t.record(vec![("vio0".into(), 2000, 2000)]);
        let p = t.points("vio0", false);
        assert_eq!(p.len(), 1);
        assert!(p[0].1 > 0 && p[0].2 == 0);
    }
}
