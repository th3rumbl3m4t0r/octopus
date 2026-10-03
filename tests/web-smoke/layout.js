// The top bar's real layout in Chromium (jsdom has no layout): every nav
// link and logout must be on top at its centre, the status bar below.
// npm install playwright && npx playwright install chromium-headless-shell
const { chromium } = require('playwright');
const fs = require('fs');
(async () => {
  // usage: node layout.js URL USER PASSWORD_FILE [WIDTH]
  const [url, user, pwfile, width] = process.argv.slice(2);
  const pw = fs.readFileSync(pwfile, 'utf8');
  const b = await chromium.launch();
  const p = await b.newPage({ ignoreHTTPSErrors: true, viewport: { width: Number(width || 1280), height: 800 } });
  await p.goto(url + '/login');
  await p.fill('#u', user); await p.fill('#p', pw);
  await Promise.all([p.waitForNavigation(), p.click('button[type=submit]')]);
  await p.waitForTimeout(800);
  const r = await p.evaluate(() => {
    const box = e => { const b = e.getBoundingClientRect(); return { top: Math.round(b.top), bottom: Math.round(b.bottom), h: Math.round(b.height) }; };
    const hdr = document.getElementById('topbar'), bar = hdr.querySelector('.bar');
    const links = [...hdr.querySelectorAll('nav a')].map(a => {
      const b = a.getBoundingClientRect();
      const hit = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
      return { name: a.textContent, h: Math.round(b.height), clickable: hit === a };
    });
    return { header: box(hdr), bar: box(bar), statusbar_top: Math.round(document.getElementById('statusbar').getBoundingClientRect().top), links,
             logout: (() => { const x = hdr.querySelector('form button'); const b = x.getBoundingClientRect(); return document.elementFromPoint(b.left + b.width/2, b.top + b.height/2) === x; })() };
  });
  console.log(JSON.stringify(r));
  const bad = r.links.filter(l => !l.clickable).map(l => l.name);
  if (bad.length || !r.logout || r.statusbar_top < r.header.bottom) { console.error('top bar broken: not clickable ' + bad.join(' ')); process.exitCode = 1; }
  await b.close();
})();
