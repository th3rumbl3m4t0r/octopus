// The wifi page on a router without [wifi] yet (the lab): the country from
// the time zone, an SSID whose password goes to the router write-only. Ends by
// discarding the config change (the stored password stays in secrets.toml
// as wifi_octoweb: remove it by hand).
//   node lab-wifi.js https://192.168.1.41:8443 USER PASSWORD_FILE
const { chromium } = require('playwright');
const fs = require('fs');
const [B, USER, PWFILE] = process.argv.slice(2);
const ok = (c, m) => { console.log((c ? 'ok   ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 } });
  const errs = [];
  const posted = [];
  p.on('pageerror', e => errs.push('pageerror: ' + e.message));
  p.on('console', m => { if ((m.type() === 'error' && !/status of 400/.test(m.text())) || /Content.Security/i.test(m.text())) errs.push('console: ' + m.text()); });
  p.on('request', r => { if (r.method() === 'POST') posted.push(r.url().replace(B, '') + ' ' + (r.postData() || '')); });
  p.on('dialog', d => d.accept());
  await p.goto(B + '/login');
  await p.fill('#u', USER); await p.fill('#p', fs.readFileSync(PWFILE, 'utf8').trim());
  await Promise.all([p.waitForNavigation(), p.click('button[type=submit]')]);

  await p.goto(B + '/wifi'); await p.waitForTimeout(2500);
  const add = '#le-ssids > .row button.primary';
  ok(await p.$eval(add, e => !e.disabled), '+ add ready: the country comes from the time zone');
  ok(/CZ from the time zone/.test(await p.$eval('#wifi-country', e => e.textContent)), 'and the page says so');

  await p.click(add); await p.waitForTimeout(300);
  const labels = await p.$$eval('#le-ssids .editor .form > label', l => l.map(x => x.textContent));
  ok(labels.filter(l => l === 'password').length === 1 && !labels.includes('passphrase'), 'one password field: ' + labels.join(', '));
  const f = n => p.$(`#le-ssids .editor .form > label:text-is("${n}") + .fld :is(input, select, textarea)`);
  await (await f('ssid')).fill('octoweb');
  await (await f('tier')).selectOption('wifi');
  await (await f('password')).fill('web passphrase 1');
  await p.click('#le-ssids .editor button.primary'); await p.waitForTimeout(2500);
  const sec = posted.filter(x => x.startsWith('/api/secret'));
  ok(sec.length === 1 && /"key":"wifi_octoweb"/.test(sec[0]), 'password sent to /api/secret as wifi_octoweb');
  const edits = posted.filter(x => x.startsWith('/api/edit')).pop() || '';
  ok(/"password":"secret:wifi_octoweb"/.test(edits) && !/web passphrase 1/.test(edits), 'router.toml gets the reference, not the password');
  const diag = await p.$eval('#changes-diag', e => e.textContent);
  ok(!/error/.test(diag), 'no errors: ' + diag);

  await p.reload(); await p.waitForTimeout(2500);
  const row = await p.$eval('#le-ssids tr[data-i]:has-text("octoweb")', r => r.textContent);
  ok(/set/.test(row) && !/missing/.test(row), 'after a reload the router says it is stored: ' + row);
  await p.click('#le-ssids tr[data-i]:has-text("octoweb")'); await p.waitForTimeout(300);
  ok(/leave empty to keep it/.test(await p.$eval('#le-ssids .editor input[type=password]', e => e.placeholder)), 'editing it: empty keeps the password');

  await p.click('#btn-wdiscard'); await p.waitForTimeout(1500);
  ok(await p.$eval('#changes', e => e.hidden), 'discarded');
  ok(!errs.length, 'no page errors' + (errs.length ? ':\n  ' + errs.join('\n  ') : ''));
  await b.close();
})();
