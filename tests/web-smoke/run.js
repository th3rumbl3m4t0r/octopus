const { JSDOM, VirtualConsole } = require('jsdom');
const fs = require('fs');
const status = JSON.parse(fs.readFileSync('status.json'));
const scripts = ['nav.js', 'x11.js', 'octopus.js'].map(f => fs.readFileSync(f, 'utf8'));
let failures = 0;
for (const page of ['status', 'firewall', 'dns', 'flows', 'proxy', 'analyzer', 'dhcp', 'config', 'generations']) {
  const vc = new VirtualConsole();
  const errors = [];
  vc.on('jsdomError', e => errors.push(e.message));
  vc.on('error', e => errors.push(String(e)));
  let html = fs.readFileSync(`page-${page}.html`, 'utf8').replace(/<script src="[^"]*"><\/script>/g, '');
  const dom = new JSDOM(html, { runScripts: 'outside-only', virtualConsole: vc, url: 'https://192.168.1.41:8443/' + page });
  const w = dom.window;
  w.fetch = (url) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(url.includes('/api/status') ? status : {}) });
  w.localStorage.clear();
  try { scripts.forEach(s => w.eval(s)); w.document.dispatchEvent(new w.Event('DOMContentLoaded')); } catch (e) { errors.push('eval: ' + e.message); }
  setTimeout(() => {
    const d = w.document;
    const tables = [...d.querySelectorAll('table.x11[id]')].map(t => `${t.id}:${t.querySelectorAll('tr').length - 1}`);
    const nav = [...d.querySelectorAll('nav a')].map(a => a.textContent + (a.className === 'on' ? '*' : '')).join(',');
    const sb = d.getElementById('statusbar').textContent.replace(/\s+/g, ' ').slice(0, 110);
    console.log(`${page.padEnd(11)} errors=${errors.length} nav=[${nav}] rows=[${tables.join(' ')}]`);
    if (page === 'status') console.log(`            statusbar: ${sb}`);
    if (errors.length) { failures++; console.log('   ', errors.join('\n    ')); }
    w.close();
  }, 300);
}
setTimeout(() => process.exit(failures ? 1 : 0), 1500);
