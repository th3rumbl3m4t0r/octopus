// Edits through the web UI on the lab (examples/lab.toml, tiers), then apply and
// confirm through it: a firewall deny and an allow from internal ranges, a DNS override, two
// public sites (own certificate, Let's Encrypt), an analyzer rule with a PCRE,
// a DHCP reservation and an [ntp] change. Check the router afterwards
// (pfctl -sr, dig, curl --resolve, dhcpd.conf; see docs/operations.md).
//   node lab-edit.js https://192.168.1.41:8443 USER PASSWORD_FILE
// The site with its own certificate wants /etc/ssl/labtest.pem and
// /etc/ssl/private/labtest.key on the router.
const { chromium } = require('playwright');
const fs = require('fs');
const [B, USER, PWFILE] = process.argv.slice(2);
const ok = (c, m) => { console.log((c ? 'ok   ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 } });
  const errs = [];
  p.on('pageerror', e => errs.push('pageerror: ' + e.message));
  p.on('console', m => { if ((m.type() === 'error' && !/status of 400/.test(m.text())) || /Content.Security/i.test(m.text())) errs.push('console: ' + m.text()); });
  p.on('dialog', d => d.accept());
  await p.goto(B + '/login');
  await p.fill('#u', USER); await p.fill('#p', fs.readFileSync(PWFILE, 'utf8').trim());
  await Promise.all([p.waitForNavigation(), p.click('button[type=submit]')]);
  const changes = () => p.$$eval('#changes-list li', l => l.map(x => x.textContent));
  // a field of the open list editor, by its label
  const field = (ed, name) => p.$(`#${ed} .editor .form > label:text-is("${name}") + .fld :is(input, textarea, select)`);
  const add = async (page, ed, values) => {
    await p.goto(B + '/' + page); await p.waitForTimeout(1500);
    await p.click(`#${ed} > .row button.primary`); await p.waitForTimeout(300);
    for (const [k, v] of Object.entries(values)) {
      const f = await field(ed, k);
      if (v === true) await f.check(); else if ((await f.evaluate(e => e.tagName)) === 'SELECT') await f.selectOption(v); else await f.fill(v);
    }
    await p.click(`#${ed} .editor button.primary`); await p.waitForTimeout(1500);
  };

  await p.goto(B + '/firewall'); await p.waitForTimeout(1500);
  await p.selectOption('#fw-type', 'deny'); await p.selectOption('#fw-src', 'net:dd'); await p.selectOption('#fw-dst', 'internet');
  await p.selectOption('#fw-proto', 'tcp'); await p.fill('#fw-port', '25'); await p.fill('#fw-desc', 'lab test: no smtp out');
  await p.click('#fw-save'); await p.waitForTimeout(1500);
  await p.selectOption('#fw-type', 'allow'); await p.selectOption('#fw-src', 'internal'); await p.selectOption('#fw-dst', 'host:buildvm');
  await p.selectOption('#fw-proto', 'tcp'); await p.fill('#fw-port', '8006'); await p.fill('#fw-desc', 'lab test: proxmox from inside');
  await p.click('#fw-save'); await p.waitForTimeout(1500);

  await add('dns', 'le-overrides', { name: 'labtest.example.net', ip: '192.168.1.250' });
  await add('vhosts', 'le-vhosts', { name: 'labtest', hostnames: 'labtest.example.com\nlabtest2.example.com', public: true,
    cert: '/etc/ssl/labtest.pem', key: '/etc/ssl/private/labtest.key', upstream: 'http://192.168.1.31:80' });
  await add('vhosts', 'le-vhosts', { name: 'acmetest', hostnames: 'acmetest.example.com', public: true, allow_from: 'cloudflare', upstream: 'http://192.168.1.31:80' });
  await add('analyzer', 'le-analyzer', { name: 'labtest_sqli', network: 'dd', fcap: 'proto tcp and dst port 80', regex: '(?i)union\\s+select(?=\\s)' });
  await add('dhcp', 'le-hosts', { name: 'labres', ip: '10.51.2.77', mac: '02:00:00:00:99:77' });
  await p.goto(B + '/settings#ntp'); await p.waitForTimeout(1500);
  await p.fill('#set-body .form > label:text-is("servers") + .fld textarea', 'ntp.nic.cz\ntime.cloudflare.com\npool.ntp.org');
  await p.click('#set-body > .row button.primary'); await p.waitForTimeout(1500);

  const c = await changes();
  console.log('     ' + c.join('\n     '));
  ok(c.length === 8, '8 changes collected');
  const diag = await p.$eval('#changes-diag', e => e.textContent);
  console.log('     diagnostics: ' + diag);
  ok(!/error/.test(diag), 'no errors');

  await p.click('#btn-wapply');
  await p.waitForFunction(() => !document.getElementById('pending').hidden || !document.getElementById('changes-out').hidden, null, { timeout: 200000 });
  if (await p.$eval('#pending', e => e.hidden)) {
    ok(false, 'apply failed:\n' + await p.$eval('#changes-out', e => e.textContent));
    await b.close();
    return;
  }
  console.log('     ' + await p.$eval('#pending-text', e => e.textContent));
  ok(await p.$eval('#changes', e => e.hidden), 'applied: the changes window is empty');
  await p.click('#btn-confirm'); await p.waitForTimeout(3000);
  console.log('     ' + await p.$eval('#toast', e => e.textContent));
  ok(await p.$eval('#pending', e => e.hidden), 'confirmed');
  ok(!errs.length, 'no page errors' + (errs.length ? ':\n  ' + errs.join('\n  ') : ''));
  await b.close();
})();
