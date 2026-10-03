// The web UI on a running router (the lab): traffic graph, firewall
// overview, a DNS edit diffed through doas and then discarded (nothing is
// applied), and one-shot captures of UDP probes this script sends.
//   node lab-ui.js https://192.168.1.41:8443 USER PASSWORD_FILE
// npm install playwright && npx playwright install chromium-headless-shell
const { chromium } = require('playwright');
const dgram = require('dgram');
const fs = require('fs');
const [B, USER, PWFILE] = process.argv.slice(2);
const HOST = new URL(B).hostname;
const ok = (c, m) => { console.log((c ? 'ok   ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
function probes(ms, payload) {
  const s = dgram.createSocket('udp4');
  const t = setInterval(() => s.send(Buffer.from(payload), 9999, HOST), 200);
  return new Promise(r => setTimeout(() => { clearInterval(t); s.close(); r(); }, ms));
}
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 900 } });
  const errs = [];
  p.on('pageerror', e => errs.push('pageerror: ' + e.message));
  p.on('console', m => { if ((m.type() === 'error' && !/status of (400|409)/.test(m.text())) || /Content.Security/i.test(m.text())) errs.push('console: ' + m.text()); });
  p.on('dialog', d => d.accept());
  await p.goto(B + '/login');
  await p.fill('#u', USER); await p.fill('#p', fs.readFileSync(PWFILE, 'utf8').trim());
  await Promise.all([p.waitForNavigation(), p.click('button[type=submit]')]);

  await p.selectOption('#tr-if', 'vio0').catch(() => {});
  await p.waitForTimeout(1000);
  await p.selectOption('#tr-if', 'vio0').catch(() => {});
  await p.waitForTimeout(1000);
  const g = await p.evaluate(() => ({ opts: [...document.querySelectorAll('#tr-if option')].map(o => o.value).join(' '),
    d: document.querySelector('#tr-graph path.rx') && document.querySelector('#tr-graph path.rx').getAttribute('d').split('L').length,
    legend: document.getElementById('tr-legend').textContent }));
  console.log('     ' + JSON.stringify(g));
  ok(/vio0/.test(g.opts) && !/lo0|pflog/.test(g.opts) && g.d > 1, 'traffic from the real netstat');

  await p.goto(B + '/firewall'); await p.waitForTimeout(2500);
  const fw = await p.evaluate(() => [...document.querySelectorAll('#t-policy tr')].map(r => [...r.children].map(c => c.textContent).join(' | ')));
  console.log('     ' + fw.filter(r => / \| \d+ \| /.test(r)).slice(0, 5).join('\n     '));
  ok(fw.length > 10 && fw.some(r => / \| [1-9]\d* \| /.test(r)), 'policy rows with live counters');
  const labels = await p.$$eval('#t-labels tr td:first-child', t => t.map(x => x.textContent));
  ok(labels.length > 5 && !labels.includes('ID'), 'no "ID" pseudo-label');

  await p.goto(B + '/dns'); await p.waitForTimeout(1500);
  await p.click('#le-overrides > .row button.primary'); await p.waitForTimeout(300);
  await p.fill('#le-overrides .editor .form > label:text-is("name") + .fld input', 'ads.example.com');
  await p.fill('#le-overrides .editor .form > label:text-is("ip") + .fld input', '192.168.1.250');
  await p.click('#le-overrides .editor button.primary'); await p.waitForTimeout(1500);
  await p.click('#btn-wdiff'); await p.waitForTimeout(4000);
  const diff = await p.$eval('#changes-out', e => e.textContent);
  console.log('     ' + diff.split('\n').filter(l => /^[+-]/.test(l)).slice(0, 12).join('\n     '));
  ok(/ads\.example\.com/.test(diff), 'real diff (octopus diff --staged through doas) shows the override zone');
  await p.click('#btn-wdiscard'); await p.waitForTimeout(1500);
  ok(await p.$eval('#changes', e => e.hidden), 'discarded, nothing applied');

  await p.goto(B + '/analyzer'); await p.waitForTimeout(1500);
  await p.selectOption('#cap-if', 'vio0');
  await p.fill('#cap-fcap', 'proto udp and dst port 9999'); await p.fill('#cap-pcre', 'octo(?=pus)'); await p.fill('#cap-sec', '4');
  let t0 = Date.now();
  await Promise.all([p.click('#btn-capture'), probes(3000, 'hello octopus / not an octagon')]);
  await p.waitForFunction(() => !document.getElementById('btn-capture').disabled, null, { timeout: 30000 });
  console.log('     capture took ' + (Date.now() - t0) + ' ms: ' + await p.$eval('#pkt-summary', e => e.textContent) + ' | ' + await p.$eval('#cap-status', e => e.textContent));
  const n = await p.$$eval('#t-packets tr[data-i]', r => r.length);
  ok(n >= 5, n + ' real packets captured through bpf');
  const marked = await p.$$eval('#pkt-hex span.m', s => s.slice(1).map(x => x.textContent).join(''));
  ok(marked === '6f63746focto', 'PCRE2 lookahead match marked: ' + marked);
  console.log('     ' + (await p.$eval('#pkt-hex', e => e.textContent)).split('\n').slice(0, 5).join('\n     '));
  // a real download: the link is navigated, not fetched (connect-src 'self' would refuse a blob: fetch)
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#pkt-pcap')]);
  const file = fs.readFileSync(await dl.path());
  const magic = [...file.subarray(0, 4)].map(x => x.toString(16)).join(' ') + ', ' + file.length + ' bytes, ' + dl.suggestedFilename();
  ok(/a1 b2 c3 d4|d4 c3 b2 a1/.test(magic), 'pcap download is a pcap (' + magic + ')');

  // catastrophic pattern: the match limit skips the packet, the capture still ends on time
  await p.fill('#cap-pcre', '(a+)+$'); await p.fill('#cap-sec', '3');
  t0 = Date.now();
  await Promise.all([p.click('#btn-capture'), probes(2500, 'a'.repeat(40) + '!')]);
  await p.waitForFunction(() => !document.getElementById('btn-capture').disabled, null, { timeout: 30000 });
  const took = Date.now() - t0;
  ok(took < 8000, '(a+)+$ capture ended after ' + took + ' ms: ' + await p.$eval('#pkt-summary', e => e.textContent));

  // one capture at a time
  const codes = await p.evaluate(() => {
    const req = () => fetch('/api/capture', { method: 'POST', headers: { 'X-Octopus': '1', 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: 'vio0', fcap: '', pcre: '', seconds: 2, max_packets: 5 }) }).then(r => r.status);
    return Promise.all([req(), req()]);
  });
  ok(codes.sort().join() === '200,409', 'second concurrent capture refused: ' + codes);
  const bad = await p.evaluate(() => fetch('/api/capture', { method: 'POST', headers: { 'X-Octopus': '1', 'Content-Type': 'application/json' },
    body: JSON.stringify({ interface: 'vio0; id', fcap: '', pcre: '', seconds: 2, max_packets: 5 }) }).then(r => r.json()));
  ok(/not an interface name/.test(bad.error || ''), 'bad interface refused by the analyzer: ' + bad.error);

  // the standing rules: off, and the switch is an unapplied change like any other
  ok(!(await p.$eval('#an-enabled', e => e.checked)) && await p.$eval('#an-running', e => e.hidden), 'standing rules off: ' + await p.$eval('#an-state', e => e.textContent));
  await p.click('#an-enabled'); await p.waitForTimeout(1500);
  ok((await p.$$eval('#changes-list li', l => l.map(x => x.textContent))).join() === 'run the standing analyzer rules', 'switching them on is an unapplied change');
  await p.click('#btn-wdiscard'); await p.waitForTimeout(1500);
  ok(!(await p.$eval('#an-enabled', e => e.checked)), 'discarded: off again');

  ok(!errs.length, 'no page errors or CSP violations' + (errs.length ? ':\n  ' + errs.join('\n  ') : ''));
  await b.close();
})();
