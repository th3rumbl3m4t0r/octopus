// Every page and feature of the web UI, in one browser session the way a
// person would use it (tests/web-ui/run.sh starts the server; it starts
// from examples/lab.toml with a stateful fake octopus).
//   node suite.js URL USER PASSWORD_FILE [area ...]
const { chromium } = require('playwright');
const fs = require('fs');
const [B, USER, PWFILE, ...only] = process.argv.slice(2);

let failed = 0, passed = 0, area = '';
const errs = [];
function ok(c, m) {
  if (c) passed++; else failed++;
  console.log((c ? 'ok   ' : 'FAIL ') + area.padEnd(10) + m);
}
const wait = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, acceptDownloads: true });
  const p = await ctx.newPage();
  p.on('pageerror', e => errs.push(area + ' pageerror: ' + e.message));
  p.on('console', m => {
    // refusals (400, the wrong login's 401) are part of the tests
    if ((m.type() === 'error' && !/status of 40[01]/.test(m.text())) || /Content.Security/i.test(m.text())) errs.push(area + ' console: ' + m.text());
  });
  p.on('dialog', d => d.accept());

  const go = async (page, ms = 1500) => { await p.goto(B + '/' + page); await p.waitForTimeout(ms); };
  const text = sel => p.$eval(sel, e => e.textContent);
  const toast = () => text('#toast');
  const changes = () => p.$$eval('#changes-list li', l => l.map(x => x.textContent));
  const rows = sel => p.$$eval(sel + ' tr[data-i]', r => r.map(x => x.textContent));
  // a field of a list editor's open form (the first: top level before nested)
  const field = async (ed, label) => p.$(`${ed} .editor .form > label:text-is("${label}") + .fld :is(input, textarea, select)`);
  const fill = async (ed, values) => {
    for (const [k, v] of Object.entries(values)) {
      const f = await field(ed, k);
      if (!f) throw new Error('no field ' + k);
      const tag = await f.evaluate(e => e.tagName + (e.type === 'checkbox' ? ':cb' : ''));
      if (tag === 'INPUT:cb') { if (v) await f.check(); else await f.uncheck(); } else if (tag === 'SELECT') await f.selectOption(String(v)); else await f.fill(String(v));
    }
  };
  const addEntry = async (ed, values) => {
    await p.click(`${ed} > .row button.primary`); await p.waitForTimeout(300);
    await fill(ed, values);
    await p.click(`${ed} .editor > .row button.primary`); await p.waitForTimeout(1500);
  };
  const discard = async () => {
    if (!(await p.$eval('#changes', e => e.hidden))) { await p.click('#btn-wdiscard'); await p.waitForTimeout(1500); }
    ok(await p.$eval('#changes', e => e.hidden), 'discarded, nothing pending');
  };
  const applyAndConfirm = async () => {
    await p.click('#btn-wapply');
    await p.waitForSelector('#pending:not([hidden])', { timeout: 30000 });
    ok(true, 'applied: ' + (await text('#pending-text')).slice(0, 60));
    ok(await p.$eval('#changes', e => e.hidden), 'the changes window is empty after apply');
    await p.click('#btn-confirm'); await p.waitForTimeout(2000);
    ok(await p.$eval('#pending', e => e.hidden), 'confirmed');
  };
  const run = async (name, fn) => {
    if (only.length && !only.includes(name)) return;
    area = name;
    const before = errs.length;
    try { await fn(); } catch (e) { ok(false, 'threw: ' + e.message.split('\n')[0]); }
    ok(errs.length === before, 'no page errors or CSP violations' + (errs.length > before ? ': ' + errs.slice(before).join(' | ') : ''));
  };

  await run('login', async () => {
    await p.goto(B + '/login');
    await p.fill('#u', USER); await p.fill('#p', 'wrong');
    await Promise.all([p.waitForNavigation(), p.click('button[type=submit]')]);
    ok(/\/login/.test(p.url()) && /bad|invalid|wrong|unknown/i.test(await text('body')), 'a wrong password is refused');
    await p.fill('#u', USER); await p.fill('#p', fs.readFileSync(PWFILE, 'utf8').trim());
    await Promise.all([p.waitForNavigation(), p.click('button[type=submit]')]);
    ok(/\/status/.test(p.url()), 'logged in');
    const nav = await p.$$eval('#topbar nav a', a => a.map(x => x.textContent));
    ok(nav.length === 12, 'navigation: ' + nav.join(', '));
  });

  await run('pages', async () => {
    for (const pg of ['status', 'firewall', 'dns', 'dhcp', 'wifi', 'vhosts', 'proxy', 'flows', 'analyzer', 'settings', 'config', 'generations']) {
      const r = await p.goto(B + '/' + pg); await p.waitForTimeout(1200);
      ok(r.status() === 200 && !(await text('#statusbar')).includes('status:'), pg + ' loads with live status');
    }
  });

  await run('firewall', async () => {
    await go('firewall');
    ok((await rows('#t-policy')).length > 10, 'overview rows');
    ok(/what it is/.test(await text('#t-tables')) && /every internal network/.test(await text('#t-tables')), 'pf tables explained');
    await p.click('#t-policy tr[data-i]:has-text("dd (10.51.2.0/24)"):has-text("anything, the internet too")');
    const pre = await p.evaluate(() => [document.getElementById('fw-type').value, document.getElementById('fw-src').value, document.getElementById('fw-dst').value]);
    ok(pre.join() === 'allow,net:dd,any', 'a row starts the new-rule box: ' + pre);
    await p.selectOption('#fw-type', 'deny'); await p.selectOption('#fw-dst', 'internet'); await p.selectOption('#fw-proto', 'tcp'); await p.fill('#fw-port', '25'); await p.fill('#fw-desc', 'no smtp');
    await p.click('#fw-save'); await p.waitForTimeout(1500);
    ok((await rows('#t-policy')).some(r => /tcp 25deny ✎no smtp/.test(r)), 'deny rule in the overview');
    await p.click('#t-policy tr[data-i]:has-text("no smtp")'); await p.waitForTimeout(300);
    ok(/editing rules 7/.test(await text('#fw-mode')), 'clicking it edits it');
    await p.fill('#fw-port', '25,465'); await p.click('#fw-save'); await p.waitForTimeout(1500);
    ok((await rows('#t-policy')).some(r => /tcp 25,465deny/.test(r)), 'edited in place');
    await p.click('#t-policy tr[data-i]:has-text("no smtp")'); await p.waitForTimeout(300);
    await p.click('#fw-del'); await p.waitForTimeout(1500);
    ok(!(await rows('#t-policy')).some(r => /no smtp/.test(r)), 'deleted');
    await p.selectOption('#fw-type', 'nat'); await p.selectOption('#fw-src', 'internet'); await p.selectOption('#fw-dst', 'host:testbox');
    await p.fill('#fw-port', '8443'); await p.fill('#fw-toport', '443'); await p.click('#fw-save'); await p.waitForTimeout(1500);
    ok((await changes()).some(c => /nat internet → host:testbox 8443/.test(c)), 'nat rule added');
    await p.selectOption('#fw-type', 'allow'); await p.selectOption('#fw-src', 'internet'); await p.click('#fw-save'); await p.waitForTimeout(800);
    ok(/choose nat/.test(await toast()), 'allow from the internet points to nat');
    await p.selectOption('#fw-type', 'allow'); await p.selectOption('#fw-src', ''); await p.fill('#fw-src-ip', '10.30.0.100');
    await p.selectOption('#fw-dst', 'internet'); await p.selectOption('#fw-proto', 'tcp'); await p.fill('#fw-port', '22'); await p.click('#fw-save'); await p.waitForTimeout(1500);
    ok((await changes()).some(c => /allow 10\.30\.0\.100 → internet/.test(c)), 'a typed address as source (a servers host: a link)');
    // the guard's blocked devices, released by a button
    ok((await rows('#t-guard')).length === 0 && /02:00:00:00:77:66/.test(await text('#t-guard')), 'blocked devices listed');
    await p.click('#t-guard button[data-release]'); await p.waitForTimeout(2500);
    ok(/released/.test(await toast()) && !/02:00:00:00:77:66/.test(await text('#t-guard')), 'released');
    ok((await rows('#t-policy')).some(r => /guests: nothing else inside/.test(r)), 'the guests\' rules are ordinary rules');
    await discard();
  });

  await run('dns', async () => {
    await go('dns');
    const wins = await p.$$eval('main > section.win:not([hidden]) .titlebar', t => t.map(x => x.textContent));
    ok(/overrides/.test(wins[wins.length - 2]) && /recent queries/.test(wins[wins.length - 1]), 'overrides above recent queries, queries last');
    await p.click('#t-queries a[data-qname]'); await p.waitForTimeout(400);
    ok(await p.$eval('#le-overrides .editor', e => !e.hidden), 'a query name opens a new override');
    await fill('#le-overrides', { ip: '192.168.1.250' });
    await p.click('#le-overrides .editor > .row button.primary'); await p.waitForTimeout(1500);
    await addEntry('#le-overrides', { name: 'tracker.example.net', ip: '0.0.0.0', subdomains: false });
    ok((await rows('#le-overrides')).length === 2, 'two overrides: ' + (await rows('#le-overrides')).join(' | '));
    await p.click('#le-overrides tr[data-i="1"]'); await p.waitForTimeout(300);
    await fill('#le-overrides', { ip: '192.168.1.251' }); await p.click('#le-overrides .editor > .row button.primary'); await p.waitForTimeout(1500);
    ok((await rows('#le-overrides'))[1].includes('192.168.1.251'), 'override edited');
    await p.click('#le-overrides tr[data-i="0"] button[data-rm]'); await p.waitForTimeout(1500);
    ok((await rows('#le-overrides')).length === 1, 'override removed');
    await p.fill('#view-client', 'buildvm'); await p.selectOption('#view-name', 'unfiltered'); await p.click('#f-view button[type=submit]'); await p.waitForTimeout(1500);
    ok(/buildvm/.test(await text('#t-dviews')), 'host into the 1.1.1.1 view');
    await p.click('#t-dviews .chip:has-text("buildvm") button.x'); await p.waitForTimeout(1500);
    ok(!/buildvm/.test(await text('#t-dviews')), 'and out again');
    await p.fill('#sink-ip', '192.168.1.250'); await p.click('#f-sinkhole button[type=submit]'); await p.waitForTimeout(1500);
    ok(/192\.168\.1\.250/.test(await text('#sink-now')), 'sinkhole set');
    await p.click('#btn-sink-clear'); await p.waitForTimeout(1500);
    ok(/not set/.test(await text('#sink-now')), 'sinkhole removed');
    await p.click('#btn-wdiff'); await p.waitForTimeout(1500);
    ok(/tracker\.example\.net/.test(await text('#changes-out')), 'diff shows the change');
    await discard();
  });

  await run('dhcp', async () => {
    await go('dhcp');
    await p.click('#t-leases button[data-reserve]'); await p.waitForTimeout(400);
    const pre = await p.$$eval('#le-hosts .editor .form :is(input, select)', i => i.map(x => x.value));
    ok(pre[0] === 'phone-of-guest' && pre[1] === '' && pre[3] === '02:00:00:00:77:01', 'reserve fills in the lease, the tier from the address: ' + pre.slice(0, 4));
    await p.click('#le-hosts .editor > .row button.primary'); await p.waitForTimeout(1500);
    ok((await rows('#le-hosts')).some(r => /phone-of-guest.*mgmt/.test(r)), 'reservation added, in the tier of its address');
    await p.click('#le-hosts tr[data-i]:has-text("phone-of-guest")'); await p.waitForTimeout(300);
    await fill('#le-hosts', { description: 'the guest phone' }); await p.click('#le-hosts .editor > .row button.primary'); await p.waitForTimeout(1500);
    ok((await rows('#le-hosts')).some(r => /the guest phone/.test(r)), 'reservation edited');
    await p.click('#le-hosts tr[data-i]:has-text("phone-of-guest") button[data-rm]'); await p.waitForTimeout(1500);
    ok(!(await rows('#le-hosts')).some(r => /phone-of-guest/.test(r)), 'reservation removed');
    await discard();
  });

  await run('wifi', async () => {
    // the access point's reservation (its tier from its address)
    await go('settings#tiers');
    ok((await rows('#set-body')).length === 6, 'settings lists the tiers: ' + (await rows('#set-body')).map(r => r.split(/\d/)[0]).join(' '));
    await go('dhcp');
    await addEntry('#le-hosts', { name: 'ap-hall', ip: '192.168.1.250', mac: '02:00:00:00:99:50' });
    ok((await rows('#le-hosts')).some(r => /ap-hall/.test(r)), 'the access point reservation');

    await go('wifi', 2500);
    const add = '#le-ssids > .row button.primary';
    ok(await p.$eval(add, e => !e.disabled), '+ add ready: the country comes from the time zone');
    ok(/CZ from the time zone Europe\/Prague/.test(await text('#wifi-country')), 'and the page says so');
    await p.click(add); await p.waitForTimeout(300);
    const labels = await p.$$eval('#le-ssids .editor .form > label', l => l.map(x => x.textContent));
    ok(labels.filter(l => l === 'password').length === 1, 'one password field');
    await fill('#le-ssids', { ssid: 'home', tier: 'wifi', password: 'correct horse battery' });
    await p.click('#le-ssids .editor > .row button.primary'); await p.waitForTimeout(2000);
    await addEntry('#le-ssids', { ssid: 'guests', tier: 'guest', password: 'welcome guests', bands: '' });
    let s = await rows('#le-ssids');
    ok(s.length === 2 && s.every(r => /set/.test(r)), 'two SSIDs, passwords stored: ' + s.join(' | '));
    ok(/guests.*yes/.test(s[1]), 'the guest one isolated (its tier is kept from inside by a rule)');
    ok(!/country/.test(await text('#changes-diag')), 'no country needed');
    // the network field: the router's networks, or a new one made right here
    await p.click(add); await p.waitForTimeout(300);
    const opts = await p.$$eval('#le-ssids .editor select[data-key="wifi.networks.tier"] option', o => o.map(x => x.value));
    ok(opts.includes('wifi') && opts.includes('guest') && opts.includes('__new'), 'tier: a dropdown of the tiers and "new tier…": ' + opts.join(' '));
    await fill('#le-ssids', { ssid: 'Yer a Wi-Fi Harry', tier: '__new', password: 'expecto patronum' });
    ok(await p.$eval('#le-ssids .editor .newnet', e => !e.hidden), 'new tier: its fields appear');
    await p.fill('#le-ssids .editor .newnet input:not([type=number])', 'harry');
    await p.fill('#le-ssids .editor .newnet label:text-is("router address") + .fld input', '192.168.6.1/23');
    await p.selectOption('#le-ssids .editor .newnet select', 'guest');
    await p.click('#le-ssids .editor > .row button.primary'); await p.waitForTimeout(2500);
    const ch = await changes();
    ok(ch.some(c => /add tier harry \(192\.168\.6\.1\/23, vlan 5, guests\)/.test(c)) && ch.some(c => /add wifi.networks Yer a Wi-Fi Harry/.test(c)), 'tier and SSID added: ' + ch.slice(-2).join(' | '));
    ok((await rows('#le-ssids')).some(r => /Yer a Wi-Fi Harry.*harry.*guests.*vlan 5.*set.*yes/.test(r)), 'the SSID on it, password stored, guests isolated');
    const doc = await p.evaluate(() => JSON.parse(sessionStorage.getItem('octopus.work')).doc);
    const net = doc.tiers.filter(n => n.name === 'harry')[0];
    ok(net && net.vlan === 5 && !net.interface && !net.kind && net.dhcp.range.join('-') === '192.168.6.10-192.168.7.254', 'on the house ports, open, DHCP for the rest: ' + JSON.stringify(net));
    ok(doc.rules.filter(r => r.from === 'net:harry').length === 3, 'with the guests\' three rules');
    ok(!/error/.test(await text('#changes-diag')), 'no errors: ' + (await text('#changes-diag')).slice(0, 200));
    await p.click(add); await p.waitForTimeout(300);
    await fill('#le-ssids', { ssid: 'short', tier: 'wifi', password: 'short' });
    await p.click('#le-ssids .editor > .row button.primary'); await p.waitForTimeout(1500);
    ok(/8 to 63/.test(await toast()) && (await rows('#le-ssids')).length === 3, 'a short password is refused, nothing added');
    await p.click('#le-ssids .editor > .row button:text-is("cancel")');
    await addEntry('#le-aps', { name: 'hall', host: 'ap-hall', channel_5g: 36 });
    ok((await rows('#le-aps')).some(r => /hall.*192\.168\.1\.250/.test(r)), 'access point added');
    const diag = await text('#changes-diag');
    ok(!/error/.test(diag), 'no errors: ' + diag.replace(/warning/g, '\n   warning'));
    await applyAndConfirm();
    await p.waitForTimeout(5500);
    ok((await rows('#le-aps')).some(r => /applied/.test(r)), 'apply pushed the access point');
    await p.click('#btn-push'); await p.waitForTimeout(2500);
    ok(/pushed/.test(await toast()), 'push now');
    // editing: an empty password keeps the stored one
    await p.click('#le-ssids tr[data-i]:has-text("home")'); await p.waitForTimeout(300);
    ok(/leave empty/.test(await p.$eval('#le-ssids .editor input[type=password]', e => e.placeholder)), 'stored password: empty keeps it');
    await fill('#le-ssids', { security: 'wpa3' });
    await p.click('#le-ssids .editor > .row button.primary'); await p.waitForTimeout(1500);
    s = await rows('#le-ssids');
    ok(/wpa3/.test(s[0]) && /set/.test(s[0]), 'security changed, password still set');
    await p.click('#le-ssids tr[data-i]:has-text("guests") button[data-rm]'); await p.waitForTimeout(1500);
    ok((await rows('#le-ssids')).length === 2, 'SSID removed');
    await discard();
  });

  await run('country', async () => {
    await go('settings#system');
    await p.fill('#set-body .form > label:text-is("timezone") + .fld input', 'UTC');
    await p.click('#set-body > .row button.primary'); await p.waitForTimeout(1500);
    await go('wifi', 2000);
    ok(await p.$eval('#le-ssids > .row button.primary', e => e.disabled), 'time zone UTC: + add waits for the country');
    ok(/set the country first/.test(await text('#wifi-country')), 'the page asks for it');
    await p.fill('#wifi-country input', 'cz'); await p.click('#wifi-country button'); await p.waitForTimeout(1500);
    ok(await p.$eval('#le-ssids > .row button.primary', e => !e.disabled), 'country set: + add ready');
    await discard();
  });

  await run('vhosts', async () => {
    await go('vhosts');
    await addEntry('#le-vhosts', { name: 'blog', hostnames: 'blog.example.com\nwww.example.com', public: true, allow_from: 'cloudflare', upstream: 'http://10.30.0.100:8080' });
    let v = await rows('#le-vhosts');
    ok(v.some(r => /blog\.example\.com, www\.example\.com.*public.*Let's Encrypt/.test(r)), 'public site: ' + v.join(' | '));
    await addEntry('#le-vhosts', { name: 'nas', upstream: 'http://10.30.0.100:5000' });
    ok((await rows('#le-vhosts')).some(r => /nas\.lab\.home\.arpa.*inside only.*services root/.test(r)), 'internal site');
    await p.click('#le-vhosts tr[data-i]:has-text("blog")'); await p.waitForTimeout(300);
    await fill('#le-vhosts', { cert: '/etc/ssl/origin.pem', key: '/etc/ssl/private/origin.key' });
    await p.click('#le-vhosts .editor > .row button.primary'); await p.waitForTimeout(1500);
    ok((await rows('#le-vhosts')).some(r => /blog.*origin\.pem/.test(r)), 'own certificate instead');
    ok(!/error/.test(await text('#changes-diag')), 'no errors');
    await discard();
  });

  await run('analyzer', async () => {
    await go('analyzer');
    ok(!(await p.$eval('#an-enabled', e => e.checked)) && await p.$eval('#an-running', e => e.hidden), 'standing rules off by default');
    await p.fill('#cap-pcre', 'evil'); await p.fill('#cap-sec', '2'); await p.click('#btn-capture'); await p.waitForTimeout(2500);
    ok((await rows('#t-packets')).length === 1 && /evil/.test(await text('#pkt-hex')), 'ad hoc capture with a PCRE');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#pkt-pcap')]);
    ok(/\.pcap$/.test(dl.suggestedFilename()), 'download pcap: ' + dl.suggestedFilename());
    await p.click('#an-enabled'); await p.waitForTimeout(1500);
    ok(/run the standing analyzer rules/.test((await changes()).join()), 'switching the rules on is a change');
    await addEntry('#le-analyzer', { name: 'sqli', network: 'dd', fcap: 'proto tcp and dst port 80', regex: '(?i)union\\s+select' });
    ok((await rows('#le-analyzer')).some(r => /sqli.*union/.test(r)), 'rule with a PCRE added');
    await discard();
  });

  await run('settings', async () => {
    await go('settings');
    const secs = await p.$$eval('#set-nav a', a => a.map(x => x.dataset.sec));
    ok(secs.length === 23 && secs.includes('lan') && secs.includes('tiers'), 'sections: ' + secs.join(' '));
    for (const s of secs) {
      await p.click(`#set-nav a[data-sec="${s}"]`); await p.waitForTimeout(250);
      const has = await p.$eval('#set-body', e => !!e.querySelector('.form, table'));
      if (!has) ok(false, `[${s}] shows nothing`);
    }
    ok(true, 'every section opens');
    await p.click('#set-nav a[data-sec="ntp"]'); await p.waitForTimeout(300);
    await p.fill('#set-body .form > label:text-is("servers") + .fld textarea', 'ntp.nic.cz\npool.ntp.org');
    await p.click('#set-body > .row button.primary'); await p.waitForTimeout(1500);
    ok((await changes()).includes('change [ntp]'), 'a section saved');
    await p.click('#set-nav a[data-sec="routes"]'); await p.waitForTimeout(300);
    await p.click('#set-body .lsted > .row button.primary'); await p.waitForTimeout(300);
    await fill('#set-body', { to: '172.20.0.0/16', via: '192.168.1.254' }); await p.click('#set-body .editor > .row button.primary'); await p.waitForTimeout(1500);
    await p.click('#set-body tr[data-i="1"] button[data-mv="-1"]'); await p.waitForTimeout(1500);
    ok(/172\.20\.0\.0/.test((await rows('#set-body'))[0]), 'a list entry added and moved up');
    await p.click('#set-nav a[data-sec="interfaces"]'); await p.waitForTimeout(300);
    await p.click('#set-body tr[data-i]:has-text("porta")'); await p.waitForTimeout(300);
    await p.fill('#set-body .editor .form input', 'port_a'); await p.click('#set-body .editor > .row button.primary'); await p.waitForTimeout(1500);
    ok((await rows('#set-body')).some(r => /port_a/.test(r)), 'a role renamed (and the check says what uses it): ' + (await text('#changes-diag')).slice(0, 80));
    await p.click('#set-nav a[data-sec="traffic"]'); await p.waitForTimeout(300);
    await p.click('#set-body > .row button.danger'); await p.waitForTimeout(1500);
    ok((await changes()).includes('remove [traffic]'), 'an optional section removed');
    await discard();
  });

  await run('config', async () => {
    await go('config');
    await p.click('#btn-check'); await p.waitForTimeout(1500);
    ok(/files would be rendered/.test(await text('#out')), 'check');
    await p.$eval('#config-text', e => { e.value += '\n# added on the config page\n'; });
    await p.click('#btn-diff'); await p.waitForTimeout(1500);
    ok(/\+# added on the config page/.test(await text('#out')), 'diff');
    await p.click('#btn-apply'); await p.waitForSelector('#pending:not([hidden])', { timeout: 30000 });
    ok(true, 'applied');
    await p.click('#btn-rollback'); await p.waitForTimeout(2000);
    ok(await p.$eval('#pending', e => e.hidden), 'rolled back');
    await p.click('#btn-reload'); await p.waitForTimeout(1000);
    ok(!/added on the config page/.test(await p.$eval('#config-text', e => e.value)), 'router.toml as before');
  });

  await run('workcopy', async () => {
    await go('dns');
    await addEntry('#le-overrides', { name: 'kept.example.com', ip: '192.168.1.250' });
    await p.reload(); await p.waitForTimeout(1500);
    ok((await changes()).some(c => /kept\.example\.com/.test(c)), 'unapplied changes survive a reload');
    await go('firewall');
    ok(!(await p.$eval('#changes', e => e.hidden)), 'and follow to other pages');
    // an apply from elsewhere (another tab, the config page) drops them
    await go('config');
    await p.$eval('#config-text', e => { e.value = e.value.replace(/# added.*\n/, '') + '\n# elsewhere\n'; });
    await p.click('#btn-apply'); await p.waitForSelector('#pending:not([hidden])', { timeout: 30000 });
    await p.click('#btn-confirm'); await p.waitForTimeout(2000);
    await go('dns');
    ok(await p.$eval('#changes', e => e.hidden), 'dropped when router.toml changed underneath');
  });

  await run('status', async () => {
    await go('status', 11000);
    await p.reload(); await p.waitForTimeout(2000);
    ok((await p.$eval('#tr-graph path.rx', e => e.getAttribute('d'))).startsWith('M'), 'traffic graph');
    ok((await p.$$eval('#tr-if option', o => o.length)) >= 2, 'interface choice');
    await p.selectOption('#tr-range', '24h'); await p.waitForTimeout(800);
    ok(/a point every minute/.test(await text('#tr-legend')), '24 h range');
    ok((await p.$$eval('#t-ifaces tr', r => r.length)) > 3, 'interfaces');
  });

  await run('generations', async () => {
    await go('generations');
    ok((await p.$$eval('#t-gens tr', r => r.length)) >= 4 && /web:admin/.test(await text('#t-gens')), 'generations with the web applies');
  });

  await run('layout', async () => {
    for (const width of [1400, 760]) {
      await p.setViewportSize({ width, height: 900 });
      for (const pg of ['status', 'firewall', 'dns', 'dhcp', 'wifi', 'vhosts', 'analyzer', 'settings', 'config']) {
        await go(pg, 900);
        const sw = await p.evaluate(() => document.documentElement.scrollWidth);
        if (sw > width) ok(false, `${pg} at ${width}px scrolls sideways (${sw})`);
      }
      const bad = await p.$$eval('#topbar nav a', a => a.filter(x => { const r = x.getBoundingClientRect(); return document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2) !== x; }).map(x => x.textContent));
      ok(!bad.length, `top bar clickable at ${width}px` + (bad.length ? ': ' + bad : ''));
    }
    ok(true, 'no page scrolls sideways at 1400 or 760 px');
    await p.setViewportSize({ width: 1400, height: 1000 });
  });

  await run('logout', async () => {
    await go('status', 500);
    await Promise.all([p.waitForNavigation(), p.click('#topbar form button')]);
    await go('dns', 500);
    ok(/\/login/.test(p.url()), 'logged out: pages ask for a login');
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  await b.close();
  process.exit(failed ? 1 : 0);
})();
