/* octopus-web client: renders /api/status into the page's windows, drives
   check / diff / apply / confirm / rollback on the config page, the edits
   on the DNS and analyzer pages, traffic graphs and captures. Instant
   updates only: no fades, no smooth anything (x11-design rule 4). */
(function () {
  'use strict';
  var page = document.body.getAttribute('data-page');
  var last = null;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function $(id) { return document.getElementById(id); }
  function bytes(n) {
    n = Number(n) || 0;
    var u = ['B', 'K', 'M', 'G', 'T'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + u[i];
  }
  function dur(s) {
    s = Number(s) || 0;
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return (d ? d + 'd ' : '') + (d || h ? h + 'h ' : '') + m + 'm';
  }
  function when(t) {
    if (!t) return '';
    var d = new Date(t * 1000);
    return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  }

  var toastTimer;
  function toast(title, body, cls) {
    var el = $('toast');
    el.querySelector('.titlebar').textContent = title;
    el.querySelector('.titlebar').className = 'titlebar' + (cls ? ' ' + cls : '');
    el.querySelector('.body').textContent = body || '';
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.hidden = true; }, cls === 'bad' ? 8000 : 3000);
  }

  function api(method, path, body) {
    var opt = { method: method, headers: { 'X-Octopus': '1' }, credentials: 'same-origin' };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    return fetch(path, opt).then(function (r) {
      if (r.status === 401) { location.href = '/login'; throw new Error('session expired'); }
      return r.json().then(function (j) {
        if (!r.ok && j && j.error) throw new Error(j.error);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return j;
      });
    });
  }

  function table(id, head, rows) {
    var el = $(id);
    if (!el) return;
    var h = '<tr>' + head.map(function (c) {
      var num = c.charAt(0) === '#';
      return '<th' + (num ? ' class="num"' : '') + '>' + esc(num ? c.slice(1) : c) + '</th>';
    }).join('') + '</tr>';
    el.innerHTML = h + (rows.length ? rows.join('') : '<tr><td class="dim" colspan="' + head.length + '">none</td></tr>');
  }
  function td(v, cls) { return '<td' + (cls ? ' class="' + cls + '"' : '') + '>' + v + '</td>'; }

  function wanOf(s) {
    return (s.interfaces || []).filter(function (i) { return i.name.indexOf('pppoe') === 0 || i.description === 'wan'; })[0];
  }
  // a select's options, rebuilt only when the list changes (keeps the choice)
  function options(sel, list) {
    var key = list.map(function (o) { return o[0]; }).join(' ');
    if (sel.getAttribute('data-list') === key) return;
    var v = sel.value;
    sel.innerHTML = list.map(function (o) { return '<option value="' + esc(o[0]) + '">' + esc(o[1]) + '</option>'; }).join('');
    sel.setAttribute('data-list', key);
    if (list.some(function (o) { return o[0] === v; })) sel.value = v;
  }

  // ---- status bar, every page
  function statusbar(s) {
    var wan = wanOf(s);
    var parts = [];
    if (wan) {
      var up = wan.inet.length > 0 && wan.inet[0] !== '0.0.0.0';
      parts.push('<span class="' + (up ? 'ok' : 'bad') + '">&#9679; wan ' + esc(wan.name) + ' ' + esc(up ? wan.inet[0] : (wan.status || 'down')) + '</span>');
    }
    parts.push('<span>' + esc(s.pf.states) + ' states</span>');
    parts.push('<span>gen ' + esc(s.state.current) + (s.state.confirmed !== s.state.current ? ' (confirmed ' + esc(s.state.confirmed) + ')' : '') + '</span>');
    if (s.state.pending) {
      parts.push('<span class="count">&#9679; generation ' + esc(s.state.pending.gen) + ' rolls back in ' + esc(s.state.pending.remaining) + 's</span>');
    }
    var failed = (s.services || []).filter(function (x) { return x.enabled && !x.running; });
    if (failed.length) parts.push('<span class="bad">' + failed.map(function (x) { return esc(x.name); }).join(' ') + ' down</span>');
    parts.push('<span class="spacer"></span>');
    parts.push('<span>up ' + dur(s.uptime) + ' &middot; load ' + esc(s.load) + ' &middot; OpenBSD ' + esc(s.release) + '</span>');
    $('statusbar').innerHTML = parts.join('');
    var p = $('pending');
    if (p) {
      p.hidden = !s.state.pending;
      if (s.state.pending) {
        $('pending-text').textContent = 'generation ' + s.state.pending.gen + ' is live and rolls back to ' +
          s.state.pending.previous + ' in ' + s.state.pending.remaining + ' s unless confirmed.';
      }
    }
  }

  // ---- pages
  var render = {
    status: function (s) {
      table('t-ifaces', ['interface', 'description', 'state', 'address', '#in', '#out', '#errors'],
        (s.interfaces || []).map(function (i) {
          var st = i.up ? (i.status || 'up') : 'down';
          var good = i.up && !/no carrier|down|initial|PADI/i.test(st);
          return '<tr>' + td(esc(i.name)) + td(esc(i.description), 'dim') + td(esc(st), good ? 'ok' : 'warn') +
            td(esc(i.inet.join(' '))) + td(bytes(i.ibytes), 'num') + td(bytes(i.obytes), 'num') +
            td(i.ierrs + i.oerrs, (i.ierrs + i.oerrs) ? 'num warn' : 'num dim') + '</tr>';
        }));
      table('t-services', ['service', 'state'], (s.services || []).map(function (x) {
        var st = !x.enabled ? 'off' : (x.running ? 'running' : 'NOT RUNNING');
        return '<tr>' + td(esc(x.name)) + td(st, !x.enabled ? 'dim' : (x.running ? 'ok' : 'bad')) + '</tr>';
      }));
      var v6 = s.ipv6 || {};
      $('v6-summary').textContent = v6.enabled ? 'prefix delegation on ' + v6.wan : 'off (no [wan] or ipv6.mode = "off")';
      table('t-v6', ['interface', 'IPv6 addresses'], (s.interfaces || []).filter(function (i) { return (i.inet6 || []).length; }).map(function (i) {
        return '<tr>' + td(esc(i.name) + ' <span class="dim">' + esc(i.description) + '</span>') + td(esc(i.inet6.join(' '))) + '</tr>';
      }));
      $('v6-lease').textContent = v6.lease || '';
      var lg = $('log');
      if (lg) lg.textContent = (s.log || []).slice().reverse().join('\n') || 'no octopus events yet';
      var top = (s.pf.labels || []).slice().sort(function (a, b) { return b.bytes - a.bytes; }).slice(0, 8);
      table('t-top', ['rule', '#packets', '#bytes'], top.map(function (l) {
        return '<tr>' + td(esc(l.label)) + td(l.packets, 'num') + td(bytes(l.bytes), 'num') + '</tr>';
      }));
      if (!trIf && wanOf(s)) trIf = wanOf(s).name;
      traffic();
    },
    firewall: function (s) {
      policyTable(s);
      table('t-labels', ['rule label', '#evaluations', '#packets', '#bytes'], (s.pf.labels || []).map(function (l) {
        return '<tr>' + td(esc(l.label)) + td(l.evaluations, 'num') + td(l.packets, 'num') + td(bytes(l.bytes), 'num') + '</tr>';
      }));
      table('t-tables', ['table', '#entries', 'what it is'], (s.pf.tables || []).map(function (t) {
        return '<tr>' + td(esc(t.name)) + td(t.entries, 'num') + td(esc(tableNote(t.name)), 'dim') + '</tr>';
      }));
      $('queues').textContent = s.pf.queues || 'no queues (traffic shaping is not configured)';
      var gd = s.guard || {};
      table('t-guard', ['device (mac)', 'used', 'tier', 'since (UTC)', ''], Object.keys(gd).map(function (mac) {
        var b = gd[mac];
        return '<tr>' + td(esc(mac)) + td(esc(b.ip)) + td(esc(b.tier), 'dim') + td(esc(when(b.at)), 'dim') +
          td('<button type="button" data-release="' + esc(mac) + '">release</button>') + '</tr>';
      }));
    },
    dhcp: function (s) {
      var now = Date.now() / 1000;
      var reserved = {};
      (((work && work.doc) || {}).hosts || []).forEach(function (x) { if (x.mac) reserved[x.mac.toLowerCase()] = x.name; });
      table('t-leases', ['address', 'mac', 'hostname', 'ends (UTC)', ''], (s.leases || []).map(function (l) {
        var r = reserved[(l.mac || '').toLowerCase()];
        return '<tr>' + td(esc(l.ip)) + td(esc(l.mac), 'dim') + td(esc(l.hostname || '')) + td(esc(l.ends || ''), l.abandoned ? 'bad' : 'dim') +
          td(r ? '<span class="dim">reserved: ' + esc(r) + '</span>' : '<button type="button" data-reserve="1" data-ip="' + esc(l.ip) + '" data-mac="' + esc(l.mac) +
            '" data-host="' + esc(l.hostname || '') + '">reserve</button>') + '</tr>';
      }));
      void now;
    },
    dns: function (s) {
      var d = s.dns;
      if (!d) {
        $('dns-summary').textContent = 'no query log: phase B (engine = "octopus-dns") writes /var/log/octopus-dns';
        return;
      }
      $('dns-summary').textContent = d.queries + ' queries in the log tail, ' + d.errors + ' failed';
      table('t-queries', ['time (UTC)', 'client', 'net', 'view', 'name', 'type', 'result', 'answers', '#ms', 'class'],
        (d.recent || []).map(function (q) {
          var bad = q.rcode !== 'NoError' && q.rcode !== 'NXDomain';
          return '<tr>' + td(esc(when(q.ts).slice(11)), 'dim') + td(esc(q.client)) + td(esc(q.net), 'dim') +
            td(esc(q.view || 'default'), q.view && q.view !== 'default' ? 'warn' : 'dim') + td('<a href="#" data-qname="' + esc(q.qname) + '" title="override this name">' + esc(q.qname) + '</a>') + td(esc(q.qtype), 'dim') + td(esc(q.rcode), bad ? 'bad' : (q.rcode === 'NXDomain' ? 'warn' : '')) +
            td(esc((q.answers || []).join(' ')), 'dim') + td(q.ms, 'num') + td(esc(q['class'] || ''), q['class'] ? 'ok' : '') + '</tr>';
        }));
      var top = function (id, head, list) {
        table(id, [head, '#queries'], (list || []).map(function (x) {
          return '<tr>' + td(esc(x.name)) + td(x.count, 'num') + '</tr>';
        }));
      };
      table('t-names', ['name', '#queries'], (d.top_names || []).map(function (x) {
        return '<tr>' + td('<a href="#" data-qname="' + esc(x.name) + '" title="override this name">' + esc(x.name) + '</a>') + td(x.count, 'num') + '</tr>';
      }));
      top('t-clients', 'client', d.top_clients);
      top('t-classes', 'class', d.classes);
      top('t-views', 'view', d.views);
    },
    flows: function (s) {
      var f = s.flows;
      if (!f) { $('flows-summary').textContent = 'no flow log: set [logging] pflow = "127.0.0.1:2055"'; return; }
      $('flows-summary').textContent = f.flows + ' flows in the log tail, ' + f.labelled + ' with a name';
      table('t-flows', ['ended (UTC)', 'from', 'to', 'proto', 'name', '#packets', '#bytes'], (f.recent || []).map(function (x) {
        return '<tr>' + td(esc(when(x.end).slice(11)), 'dim') + td(esc(x.src) + '<span class="dim">:' + x.sport + '</span>') +
          td(esc(x.dst) + '<span class="dim">:' + x.dport + '</span>') + td(esc(x.proto), 'dim') +
          td(esc(x.name || ''), x.name ? '' : 'dim') + td(x.packets, 'num') + td(bytes(x.bytes), 'num') + '</tr>';
      }));
      var top = function (id, head, list) {
        table(id, [head, '#bytes'], (list || []).map(function (x) { return '<tr>' + td(esc(x.name)) + td(bytes(x.count), 'num') + '</tr>'; }));
      };
      top('t-fnames', 'name', f.top_names);
      top('t-fclients', 'client', f.top_clients);
    },
    proxy: function (s) {
      var p = s.proxy;
      if (!p) { $('proxy-summary').textContent = 'no proxy: [proxy] with a servers network'; return; }
      $('proxy-summary').textContent = p.events + ' decisions in the log tail, ' + p.blocked + ' blocked';
      table('t-proxy', ['time (UTC)', 'network', 'client', 'host', 'result', 'why / request'], (p.recent || []).map(function (x) {
        var what = x.method ? esc(x.method + ' ' + x.path + ' ' + x.status) : esc(x.why);
        return '<tr>' + td(esc(when(x.ts).slice(11)), 'dim') + td(esc(x.net), 'dim') + td(esc(x.client)) + td(esc(x.host)) +
          td(esc(x.action), x.action === 'block' ? 'bad' : 'ok') + td(what, 'dim') + '</tr>';
      }));
      table('t-phosts', ['host', '#decisions'], (p.top_hosts || []).map(function (x) { return '<tr>' + td(esc(x.name)) + td(x.count, 'num') + '</tr>'; }));
    },
    analyzer: function (s) {
      options($('cap-if'), (s.interfaces || []).filter(function (i) { return i.name.indexOf('lo') !== 0; }).map(function (i) {
        return [i.name, i.name + (i.description ? ' (' + i.description + ')' : '')];
      }));
      var a = s.analyzer;
      if (!a) { $('an-summary').textContent = 'octopus-analyzer has not run yet'; return; }
      $('an-summary').textContent = a.matches + ' matches in the log tail';
      table('t-amatch', ['time (UTC)', 'rule', 'from', 'to', 'proto', '#len', 'action'], (a.recent || []).filter(function (x) { return x.rule; }).map(function (x) {
        return '<tr>' + td(esc(when(x.ts).slice(11)), 'dim') + td(esc(x.rule)) + td(esc(x.src) + '<span class="dim">:' + x.sport + '</span>') +
          td(esc(x.dst) + '<span class="dim">:' + x.dport + '</span>') + td(esc(x.proto), 'dim') + td(x.len, 'num') +
          td(esc(x.action), x.action === 'block' ? 'bad' : '') + '</tr>';
      }));
      var lb = (s.pf.tables || []).filter(function (t) { return t.name === 'lab_block'; })[0];
      table('t-ablock', ['table', '#entries'], lb ? ['<tr>' + td('lab_block') + td(lb.entries, lb.entries ? 'num warn' : 'num') + '</tr>'] : []);
      table('t-pcaps', ['file', 'modified (UTC)', '#size'], (a.pcaps || []).map(function (p) {
        return '<tr>' + td(esc(p.name)) + td(esc(when(p.modified)), 'dim') + td(bytes(p.bytes), 'num') + '</tr>';
      }));
    },
    generations: function (s) {
      table('t-gens', ['#gen', 'created', 'source', 'by', '#files', 'state'], (s.generations || []).map(function (g) {
        var tags = [];
        if (g.gen === s.state.current) tags.push('<span class="ok">current</span>');
        if (g.gen === s.state.confirmed) tags.push('confirmed');
        if (s.state.pending && g.gen === s.state.pending.gen) tags.push('<span class="warn">pending</span>');
        if (g.gen === 0) tags.push('<span class="dim">pre-octopus baseline</span>');
        return '<tr>' + td(g.gen, 'num') + td(esc(when(g.created))) + td(esc(g.source)) + td(esc(g.user), 'dim') +
          td(g.files, 'num') + td(tags.join(' ')) + '</tr>';
      }));
    },
    config: function () {}
  };

  // ---- traffic graph (status page): /api/traffic, drawn as SVG paths
  var trIf = '', trRange = '1h';
  function rate(n) {
    n = Number(n) || 0;
    var u = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'], i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i ? n.toFixed(1) : n) + ' ' + u[i];
  }
  // top of the scale in 1, 2, 5 steps
  function niceMax(v) {
    var p = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1000))));
    return [1, 2, 5, 10].map(function (k) { return k * p; }).filter(function (x) { return x >= v; })[0];
  }
  function graph(d) {
    var W = 720, H = 160, day = d.range === '24h', span = day ? 86400 : 3600;
    var pts = d.points || [];
    // the router's clock, not the browser's
    var end = pts.length ? pts[pts.length - 1][0] : Date.now() / 1000;
    var max = niceMax(Math.max.apply(null, pts.map(function (p) { return Math.max(p[1], p[2]); }).concat([0])));
    function path(k) {
      var s = '', prev = null;
      pts.forEach(function (p) {
        var x = (W - (end - p[0]) / span * W).toFixed(1), y = (H - p[k] / max * H).toFixed(1);
        // a gap (the UI restarted, sampling stalled) breaks the line
        s += (prev === null || p[0] - prev > d.step * 3 ? 'M' : 'L') + x + ' ' + y;
        prev = p[0];
      });
      return s;
    }
    var grid = '';
    for (var i = 1; i < 4; i++) grid += '<line class="grid" x1="0" x2="' + W + '" y1="' + H * i / 4 + '" y2="' + H * i / 4 + '"/>';
    $('tr-graph').innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="traffic on ' +
      esc(d['if']) + '">' + grid + '<path class="rx" d="' + path(1) + '"/><path class="tx" d="' + path(2) + '"/></svg>';
    $('tr-axis').innerHTML = day ? '<span>-24 h</span><span>-12 h</span><span>now</span>' : '<span>-60 min</span><span>-30 min</span><span>now</span>';
    var lp = pts[pts.length - 1];
    $('tr-legend').innerHTML = '<span class="rx">&#9632; in ' + (lp ? rate(lp[1]) : '-') + '</span><span class="tx">&#9632; out ' +
      (lp ? rate(lp[2]) : '-') + '</span><span class="dim">scale 0 to ' + rate(max) + ', a point every ' + (day ? 'minute' : '5 s') +
      (pts.length ? '' : '; no samples yet (kept in memory since octopus-web started)') + '</span>';
    options($('tr-if'), (d.interfaces || []).map(function (n) { return [n, n]; }));
    $('tr-if').value = d['if'];
    trIf = d['if'];
  }
  function traffic() {
    return api('GET', '/api/traffic?if=' + encodeURIComponent(trIf) + '&range=' + trRange).then(graph).catch(function (e) {
      $('tr-legend').innerHTML = '<span class="bad">traffic: ' + esc(e.message) + '</span>';
    });
  }

  // ---- working copy of router.toml (every page). Edits stack up in the
  // browser, through /api/edit, and reach the router only by the same diff /
  // apply as the config page. Kept for the tab's session, and dropped if
  // router.toml changed underneath them. Pages redraw from it (workHooks).
  var work = null, WORK_KEY = 'octopus.work', workHooks = [];
  function fresh(r) { return { base: r.toml, toml: r.toml, summary: r.summary, doc: r.doc, diagnostics: [], edits: [] }; }
  function saveWork() { try { sessionStorage.setItem(WORK_KEY, JSON.stringify(work)); } catch (e) { /* private mode */ } }
  function loadWork() {
    return api('GET', '/api/config').then(function (r) {
      var saved = null;
      try { saved = JSON.parse(sessionStorage.getItem(WORK_KEY) || 'null'); } catch (e) { /* ignore */ }
      var had = saved && saved.edits && saved.edits.length;
      if (had && saved.base !== r.toml) toast('unapplied changes dropped', 'router.toml changed on the router after they were made', 'bad');
      work = had && saved.base === r.toml && saved.doc ? saved : fresh(r);
      saveWork();
      showWork();
    }).catch(function (e) { toast('router.toml', e.message, 'bad'); });
  }
  function edit(e, what) {
    if (!work) return Promise.resolve(false);
    return api('POST', '/api/edit', { toml: work.toml, edit: e }).then(function (r) {
      work.toml = r.toml; work.summary = r.summary; work.doc = r.doc; work.diagnostics = r.diagnostics; work.edits.push(what);
      saveWork();
      $('changes-out').hidden = true;
      showWork();
      if (!r.ok) toast('check failed', 'see unapplied changes at the top', 'bad');
      else toast('added to unapplied changes', what, 'ok');
      return true;
    }).catch(function (x) { toast(what, x.message, 'bad'); return false; });
  }
  function showWork() {
    var w = $('changes');
    if (!w || !work) return;
    w.hidden = !work.edits.length;
    $('changes-list').innerHTML = work.edits.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('');
    $('changes-diag').innerHTML = work.diagnostics.length ? diagHtml(work.diagnostics) : '';
    $('btn-wapply').disabled = work.diagnostics.some(function (d) { return d.level === 'error'; });
    workHooks.forEach(function (f) { f(); });
  }
  function rmButton(act, attrs, title) {
    return '<button type="button" class="x" data-act="' + act + '"' + Object.keys(attrs).map(function (k) {
      return ' data-' + k + '="' + esc(attrs[k]) + '"';
    }).join('') + ' title="' + esc(title) + '">&times;</button>';
  }
  function startOver() {
    // router.toml follows the live generation now: start over from it
    sessionStorage.removeItem(WORK_KEY);
    work = null;
    return loadWork();
  }
  function changesWindow() {
    var out = $('changes-out');
    $('btn-wdiff').addEventListener('click', function () {
      var b = this; busy(b, true);
      api('POST', '/api/diff', { toml: work.toml }).then(function (r) {
        work.diagnostics = r.diagnostics; showWork();
        out.hidden = false;
        out.innerHTML = r.ok ? (r.diff.trim() ? diffHtml(r.diff) : 'no changes') : esc(r.output);
      }).catch(function (e) { toast('diff', e.message, 'bad'); }).then(function () { busy(b, false); showWork(); });
    });
    $('btn-wapply').addEventListener('click', function () {
      if (!confirm('Apply these changes? They roll back automatically unless confirmed within 60 seconds.')) return;
      var b = this; busy(b, true);
      api('POST', '/api/apply', { toml: work.toml }).then(function (r) {
        toast(r.ok ? 'applied' : 'apply failed', r.ok ? 'confirm within 60 s' : 'see unapplied changes', r.ok ? 'warn' : 'bad');
        if (r.ok) startOver();
        else {
          out.hidden = false;
          out.textContent = r.output;
        }
        refresh();
      }).catch(function (e) { toast('apply', e.message, 'bad'); }).then(function () { busy(b, false); showWork(); });
    });
    $('btn-wdiscard').addEventListener('click', function () {
      if (!confirm('Discard ' + work.edits.length + ' unapplied change(s)?')) return;
      out.hidden = true;
      startOver();
    });
    document.addEventListener('click', function (ev) {
      var b = ev.target.closest('[data-act]');
      if (!b || !work) return;
      var a = b.getAttribute('data-act'), d = function (k) { return b.getAttribute('data-' + k); };
      if (a === 'view-rm') edit({ op: 'view_client_remove', view: d('view'), client: d('client') }, 'take ' + d('client') + ' out of view ' + d('view'));
    });
  }
  // a form that clears its text fields once its edit went in
  function onSubmit(id, fn) {
    var f = $(id);
    f.addEventListener('submit', function (ev) {
      ev.preventDefault();
      fn().then(function (ok) {
        if (ok) f.querySelectorAll('input:not([type=checkbox]):not([type=number])').forEach(function (i) { i.value = ''; });
      });
    });
  }

  // ---- forms from router.toml's schema (/api/schema: the Rust types with
  // their doc comments, defaults and choices)
  var SCHEMA = null;
  function loadSchema() { return api('GET', '/api/schema').then(function (s) { SCHEMA = s; }); }
  function deref(s) {
    while (s && s.$ref) s = SCHEMA.$defs[s.$ref.split('/').pop()];
    return s || {};
  }
  function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
  // a schema node as a field: kind, help, default, optional, choices
  function norm(s0) {
    var s = deref(s0);
    var f = { desc: s0.description || s.description || '', def: s0['default'] !== undefined ? s0['default'] : s['default'], optional: false };
    if (s.anyOf) {
      var alt = s.anyOf.filter(function (x) { return x.type !== 'null'; });
      var inner = norm(alt[0]);
      inner.optional = alt.length < s.anyOf.length;
      inner.desc = f.desc || inner.desc;
      if (inner.def === undefined) inner.def = f.def;
      return inner;
    }
    var type = s.type;
    if (Array.isArray(type)) {
      f.optional = type.indexOf('null') >= 0;
      type = type.filter(function (t) { return t !== 'null'; });
      if (type.length > 1) { f.kind = 'ports'; return f; }
      type = type[0];
    }
    if (s['x-ports']) { f.kind = 'ports'; return f; }
    if (s.oneOf && s.oneOf.every(function (o) { return o['const'] !== undefined; })) {
      f.kind = 'enum';
      f.options = s.oneOf.map(function (o) { return [o['const'], o.description || '']; });
    } else if (s['enum']) {
      f.kind = 'enum';
      f.options = s['enum'].map(function (v) { return [v, '']; });
    } else if (type === 'boolean') f.kind = 'bool';
    else if (type === 'integer' || type === 'number') f.kind = 'int';
    else if (type === 'array') {
      var it = deref(s.items || {});
      if (s.minItems === 2 && s.maxItems === 2 && it.type === 'string') f.kind = 'pair';
      else if (it.type === 'array') f.kind = 'pairs';
      else if (it.properties) { f.kind = 'list'; f.item = s.items; }
      else f.kind = 'strs';
    } else if (s.properties) { f.kind = 'obj'; f.props = s.properties; f.required = s.required || []; }
    else if (s.additionalProperties) { f.kind = 'map'; f.item = s.additionalProperties; }
    else f.kind = 'str';
    return f;
  }
  // the field node of a list or section at `path` (keys only)
  function schemaAt(path) {
    var node = SCHEMA;
    path.forEach(function (k) {
      var n = deref(node);
      if (n.anyOf) n = deref(n.anyOf.filter(function (x) { return x.type !== 'null'; })[0]);
      node = (n.properties || {})[k] || {};
    });
    return norm(node);
  }
  function getAt(obj, path) {
    return path.reduce(function (o, k) { return o == null ? undefined : o[k]; }, obj);
  }
  function h(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === undefined || v === null || v === false) return;
      if (k === 'text') e.textContent = v;
      else if (k === 'class') e.className = v;
      else if (k === 'value') e.value = v;
      else e.setAttribute(k, v === true ? '' : v);
    });
    (kids || []).forEach(function (c) { if (c) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return e;
  }
  // help text: the doc comment without its markdown ticks
  function plain(s) { return String(s || '').replace(/`/g, '').replace(/\s*\n\s*/g, ' '); }

  // the tiers, whichever name the file uses ([[tiers]], older [[networks]])
  function tiersOf(d) { return (d && (d.tiers || d.networks)) || []; }
  function tierKey(d) { return d && d.networks && !d.tiers ? 'networks' : 'tiers'; }

  // names to pick from, by field (section.field): a datalist on the input
  function suggestions(key) {
    var d = (work && work.doc) || {};
    var nets = tiersOf(d).map(function (n) { return [n.name, n.address + (n.vlan ? ' vlan ' + n.vlan : '') + (n.kind && n.kind !== 'open' ? ' ' + n.kind : '')]; });
    var roles = Object.keys(d.interfaces || {}).map(function (k) { return [k, (d.interfaces[k].name || '') + ' ' + d.interfaces[k].mac]; });
    var ends = [['internal', 'every internal network'], ['internet', 'everything outside'], ['self', 'the router'], ['any', 'anything']]
      .concat(nets.map(function (n) { return ['net:' + n[0], n[1]]; }))
      .concat((d.hosts || []).map(function (x) { return ['host:' + x.name, x.ip]; }))
      .concat((d.tables || []).map(function (x) { return ['table:' + x.name, (x.entries || []).length + ' entries']; }));
    var table = {
      'hosts.network': nets, 'links.network': nets, 'proxy.allow.network': nets,
      'rules.network': nets.concat([['all', 'every internal network'], ['wan', 'from the internet (block only)']]),
      'analyzer.rules.network': nets.concat([['wan', 'the WAN']]),
      'networks.interface': roles, 'networks.bridge': roles, 'tiers.interface': roles, 'tiers.bridge': roles,
      'lan.ports': roles, 'wan.interface': roles, 'hosts.tier': nets,
      'rules.from': ends, 'rules.to': ends, 'links.to': ends, 'forwards.from': ends,
      'vhosts.allow_from': [['cloudflare', "Cloudflare's ranges"]].concat(ends.slice(4)),
      'dns.views.clients': ends.slice(4),
      'wifi.networks.tier': nets,
      'wifi.networks.aps': (((d.wifi || {}).aps) || []).map(function (a) { return [a.name, a.host]; }),
      'wifi.aps.host': (d.hosts || []).map(function (x) { return [x.name, x.ip + ' ' + x.network + (x.mac ? '' : ' (no mac)')]; })
    };
    return table[key];
  }
  // fields that name something in the file: a dropdown, not free text
  var PICK = ['hosts.network', 'links.network', 'proxy.allow.network', 'rules.network', 'analyzer.rules.network',
    'wifi.networks.tier', 'wifi.aps.host', 'networks.interface', 'tiers.interface', 'wan.interface', 'hosts.tier'];
  var dlCount = 0;
  function datalist(key) {
    var list = suggestions(key);
    if (!list) return null;
    var id = 'dl-' + (++dlCount);
    var dl = h('datalist', { id: id }, list.map(function (o) { return h('option', { value: o[0], label: o[1] }); }));
    return { id: id, el: dl };
  }

  // one input for a field: { el, get } where get() is the value or null
  function widget(key, f, v) {
    var shown = v !== undefined ? v : (f.def !== undefined && f.def !== null ? f.def : undefined);
    var dl = datalist(key), el, get, i;
    switch (f.kind) {
      case 'bool':
        if (f.optional && f.def === undefined) {
          el = h('select', {}, [h('option', { value: '', text: '(default)' }), h('option', { value: 'true', text: 'yes' }), h('option', { value: 'false', text: 'no' })]);
          el.value = v === undefined || v === null ? '' : String(v);
          get = function () { return el.value === '' ? null : el.value === 'true'; };
        } else {
          el = h('input', { type: 'checkbox' });
          el.checked = !!shown;
          get = function () { return el.checked; };
        }
        break;
      case 'int':
        i = h('input', { type: 'number', value: shown === undefined || shown === null ? '' : shown, placeholder: f.optional ? '(none)' : '' });
        el = i;
        get = function () { return i.value === '' ? null : Number(i.value); };
        break;
      case 'ports':
        i = h('input', { value: shown === undefined || shown === null ? '' : shown, placeholder: '443, 8000-8010', size: 14 });
        el = i;
        get = function () { var x = i.value.trim(); return x === '' ? null : (/^\d+$/.test(x) ? Number(x) : x); };
        break;
      case 'enum':
        el = h('select', {}, (f.optional || f.def !== undefined ? [h('option', { value: '', text: f.def !== undefined && f.def !== null ? '(default: ' + f.def + ')' : '(none)' })] : [])
          .concat(f.options.map(function (o) { return h('option', { value: o[0], text: o[0] + (o[1] ? ': ' + plain(o[1]) : '') }); })));
        el.value = v === undefined || v === null ? (f.optional || f.def !== undefined ? '' : f.options[0][0]) : v;
        get = function () { return el.value === '' ? (f.def !== undefined ? f.def : null) : el.value; };
        break;
      case 'strs':
        var ta = h('textarea', { rows: Math.max(2, (shown || []).length + 1), placeholder: 'one per line' });
        ta.value = (shown || []).join('\n');
        get = function () { return ta.value.split('\n').map(function (x) { return x.trim(); }).filter(Boolean); };
        el = ta;
        if (dl) {
          // a textarea has no datalist: pick to add a line
          var pick = h('select', {}, [h('option', { value: '', text: 'add…' })].concat(suggestions(key).map(function (o) { return h('option', { value: o[0], text: o[0] + '  ' + o[1] }); })));
          pick.addEventListener('change', function () { if (pick.value) { ta.value = (ta.value.trim() ? ta.value.trim() + '\n' : '') + pick.value; pick.value = ''; } });
          el = h('div', { class: 'col' }, [ta, pick]);
          dl = null;
        }
        break;
      case 'pair':
        var a = h('input', { value: shown ? shown[0] : '', placeholder: 'from', size: 15 }), b = h('input', { value: shown ? shown[1] : '', placeholder: 'to', size: 15 });
        el = h('span', { class: 'row' }, [a, '–', b]);
        get = function () { return a.value.trim() || b.value.trim() ? [a.value.trim(), b.value.trim()] : null; };
        break;
      case 'pairs':
        var pt = h('textarea', { rows: Math.max(2, (shown || []).length + 1), placeholder: 'from - to, one range per line' });
        pt.value = (shown || []).map(function (p) { return p.join(' - '); }).join('\n');
        el = pt;
        get = function () {
          return pt.value.split('\n').map(function (x) { return x.trim(); }).filter(Boolean).map(function (x) { return x.split(/\s*[-–]\s*|\s+/); });
        };
        break;
      case 'obj':
        var sub = form(key, f, v || {});
        if (f.optional) {
          var on = h('input', { type: 'checkbox' });
          on.checked = v !== undefined && v !== null;
          sub.el.hidden = !on.checked;
          on.addEventListener('change', function () { sub.el.hidden = !on.checked; });
          el = h('div', { class: 'col' }, [h('label', { class: 'row' }, [on, 'set']), sub.el]);
          get = function () { return on.checked ? sub.get() : null; };
        } else {
          el = sub.el;
          get = sub.get;
        }
        break;
      case 'list':
        var itemF = norm(f.item), rows = [], box = h('div', { class: 'col nested' });
        var addRow = function (val) {
          var r = form(key, itemF, val || {}), x = h('button', { type: 'button', class: 'x', title: 'remove', text: '×' });
          var wrap = h('div', { class: 'item' }, [r.el, x]);
          var entry = { get: r.get };
          x.addEventListener('click', function () { rows.splice(rows.indexOf(entry), 1); wrap.remove(); });
          rows.push(entry);
          box.insertBefore(wrap, add);
        };
        var add = h('button', { type: 'button', text: '+ add' });
        box.appendChild(add);
        add.addEventListener('click', function () { addRow({}); });
        (shown || []).forEach(addRow);
        el = box;
        get = function () { return rows.map(function (r) { return r.get(); }); };
        break;
      default:
        if (PICK.indexOf(key) >= 0 && suggestions(key)) {
          var list = suggestions(key).slice();
          var cur = shown === undefined || shown === null ? '' : String(shown);
          if (cur && !list.some(function (o) { return o[0] === cur; })) list.unshift([cur, '(not a ' + key.split('.').pop() + ' here)']);
          i = h('select', { 'data-key': key }, [h('option', { value: '', text: f.optional ? (key === 'hosts.tier' ? '(from its address)' : '(none)') : 'pick one' })]
            .concat(list.map(function (o) { return h('option', { value: o[0], text: o[0] + (o[1] ? '  —  ' + o[1] : '') }); })));
          i.value = cur;
          el = i;
          dl = null;
          get = function () { return i.value === '' ? null : i.value; };
          break;
        }
        i = h('input', { value: shown === undefined || shown === null ? '' : shown, list: dl && dl.id, size: 28 });
        el = i;
        get = function () { var x = i.value.trim(); return x === '' ? null : x; };
    }
    // (a new variable: the getters above close over el)
    return { el: dl ? h('span', {}, [el, dl.el]) : el, get: get };
  }

  // a table's fields: the value only carries what differs from the file
  // (a default the file doesn't write stays unwritten)
  // `hide`: fields not shown; their value stays as it is in the file
  function form(key, f, value, hide) {
    var grid = h('div', { class: 'form' }), ws = [];
    Object.keys(f.props).filter(function (n) { return (hide || []).indexOf(n) < 0; }).forEach(function (name) {
      var pf = norm(f.props[name]);
      var w = widget(key + '.' + name, pf, value[name]);
      var req = f.required.indexOf(name) >= 0;
      grid.appendChild(h('label', { class: 'lbl' + (req ? ' req' : ''), title: plain(pf.desc) }, [name]));
      grid.appendChild(h('div', { class: 'fld' }, [w.el, pf.desc ? h('div', { class: 'help', text: plain(pf.desc) }) : null]));
      ws.push([name, pf, w]);
    });
    return {
      el: grid,
      get: function () {
        var o = {};
        (hide || []).forEach(function (n) { if (value[n] !== undefined) o[n] = value[n]; });
        ws.forEach(function (x) {
          var name = x[0], pf = x[1], val = x[2].get(), had = Object.prototype.hasOwnProperty.call(value, name);
          if (val === null || val === undefined) return;
          if (!had && Array.isArray(val) && !val.length) return;
          if (!had && pf.def !== undefined && same(val, pf.def)) return;
          o[name] = val;
        });
        return o;
      }
    };
  }

  // ---- a list of router.toml entries (or a map such as [interfaces]):
  // the table, and an editor for one entry. opts: columns [[title, fn]],
  // label(item), filter(item)
  var editors = {};
  function listEditor(el, path, opts) {
    opts = opts || {};
    var f = schemaAt(path), map = f.kind === 'map', itemF = norm(f.item), key = path.join('.');
    var spath = path;
    // the path in the file: [[networks]] in older files
    var real = function () { return spath[0] === 'tiers' ? [tierKey(work.doc)].concat(spath.slice(1)) : spath; };
    var tbl = h('table', { class: 'x11 pick' }), box = h('div', { class: 'editor', hidden: true });
    var addBtn = h('button', { type: 'button', class: 'primary', text: '+ add' });
    el.innerHTML = '';
    el.appendChild(tbl);
    el.appendChild(h('div', { class: 'row' }, [addBtn, f.desc ? h('span', { class: 'dim', text: plain(f.desc) }) : null]));
    el.appendChild(box);
    function items() {
      var v = getAt(work.doc, real());
      if (map) return Object.keys(v || {}).map(function (k) { var o = Object.assign({}, v[k]); o._key = k; return o; });
      return v || [];
    }
    var label = opts.label || function (it, i) { return it._key || it.name || it.ssid || it.to || (key + ' ' + (i + 1)); };
    var cols = opts.columns || Object.keys(itemF.props).filter(function (n) {
      return ['str', 'int', 'bool', 'enum', 'ports', 'strs'].indexOf(norm(itemF.props[n]).kind) >= 0;
    }).slice(0, 5).map(function (n) {
      return [n, function (it) { var v = it[n]; return esc(Array.isArray(v) ? v.join(', ') : v === undefined ? '' : v); }];
    });
    if (map) cols = [['role', function (it) { return esc(it._key); }]].concat(cols);
    function draw() {
      var list = items();
      table(tbl.id = tbl.id || ('t-' + key.replace(/\W/g, '-')), cols.map(function (c) { return c[0]; }).concat(['']), list.map(function (it, i) {
        var btns = (map ? '' : (i ? '<button type="button" class="x" data-mv="-1" title="move up">&uarr;</button>' : '') +
          (i < list.length - 1 ? '<button type="button" class="x" data-mv="1" title="move down">&darr;</button>' : '')) +
          '<button type="button" class="x" data-rm="1" title="remove">&times;</button>';
        return '<tr data-i="' + i + '">' + cols.map(function (c) { return td(c[1](it)); }).join('') + td(btns, 'acts') + '</tr>';
      }));
    }
    function open(i, value) {
      box.innerHTML = '';
      box.hidden = false;
      var isNew = i === null, old = isNew ? {} : items()[i], val = value || old;
      var keyIn = map ? h('input', { value: isNew ? (val._key || '') : old._key, placeholder: 'role', size: 16 }) : null;
      var fm = form(key, itemF, val, opts.hide);
      var save = h('button', { type: 'button', class: 'primary', text: isNew ? 'add' : 'save' });
      var cancel = h('button', { type: 'button', text: 'cancel' });
      box.appendChild(h('div', { class: 'titlebar sub', text: isNew ? 'new entry in ' + key : 'editing ' + label(old, i) }));
      if (keyIn) box.appendChild(h('div', { class: 'form' }, [h('label', { class: 'lbl req', text: 'role' }), h('div', { class: 'fld' }, [keyIn])]));
      box.appendChild(fm.el);
      var extra = opts.extra ? opts.extra(val, isNew) : null;
      if (extra) box.appendChild(extra.el);
      box.appendChild(h('div', { class: 'row' }, [save, cancel, h('span', { class: 'dim', text: 'goes into unapplied changes; nothing is live until apply' })]));
      cancel.addEventListener('click', function () { box.hidden = true; box.innerHTML = ''; tbl.querySelectorAll('tr.on').forEach(function (r) { r.classList.remove('on'); }); });
      save.addEventListener('click', function () {
        var v = fm.get(), e, what = (isNew ? 'add ' : 'change ') + key + ' ' + (v.name || v.ssid || (keyIn && keyIn.value) || v.to || '');
        if (map) {
          var k = keyIn.value.trim();
          if (!k) { toast('role', 'give it a name', 'bad'); return; }
          e = isNew || k === old._key ? { op: 'set', path: real().concat([k]), value: v } :
            { op: 'batch', edits: [{ op: 'set', path: real().concat([old._key]), value: null }, { op: 'set', path: real().concat([k]), value: v }] };
        } else {
          e = isNew ? { op: 'append', path: real(), value: v } : { op: 'set', path: real().concat([i]), value: v };
        }
        busy(save, true);
        // the extra part may change the value first (a passphrase set on the router)
        Promise.resolve(extra ? extra.apply(v) : v).then(function (v2) {
          if (e.value) e.value = v2;
          return edit(e, what.trim());
        }).then(function (ok) { busy(save, false); if (ok) { box.hidden = true; box.innerHTML = ''; } })
          .catch(function (x) { busy(save, false); toast('not saved', x.message, 'bad'); });
      });
      box.scrollIntoView({ block: 'nearest' });
      var first = box.querySelector('input:not([type=checkbox]), select, textarea');
      if (first) first.focus();
    }
    addBtn.addEventListener('click', function () { open(null); });
    // something else must come first (the Wi-Fi country): the button says what
    function guard() {
      var why = opts.addGuard ? opts.addGuard() : '';
      addBtn.disabled = !!why;
      addBtn.title = why || '';
    }
    tbl.addEventListener('click', function (ev) {
      var tr = ev.target.closest('tr[data-i]');
      if (!tr) return;
      var i = Number(tr.getAttribute('data-i')), it = items()[i], b = ev.target.closest('button');
      if (b && b.hasAttribute('data-rm')) {
        if (!confirm('Remove ' + label(it, i) + '?')) return;
        edit({ op: 'set', path: real().concat([map ? it._key : i]), value: null }, 'remove ' + key + ' ' + label(it, i));
      } else if (b && b.hasAttribute('data-mv')) {
        var to = i + Number(b.getAttribute('data-mv'));
        edit({ op: 'move', path: real(), from: i, to: to }, 'move ' + key + ' ' + label(it, i) + (to < i ? ' up' : ' down'));
      } else {
        tbl.querySelectorAll('tr.on').forEach(function (r) { r.classList.remove('on'); });
        tr.classList.add('on');
        open(i);
      }
    });
    workHooks.push(draw, guard);
    draw();
    guard();
    var api_ = { add: function (prefill) { open(null, prefill || {}); }, draw: draw };
    editors[key] = api_;
    return api_;
  }

  // ---- settings: every section of router.toml
  var SECTION_NOTES = {
    interfaces: 'Ports by role, bound to MAC addresses.',
    lan: 'The house ports: one bridge, any device in any port; tiers without a port of their own are on it.',
    tiers: 'Address ranges: devices land in one by MAC (macs), cable (wired) or the Wi-Fi VLAN; open tiers reach everything, the rules decide the rest.',
    hosts: 'Known devices: DNS names, and with a mac a DHCP reservation (also on the dhcp page).',
    rules: 'Explicit filter rules (the firewall page writes these for you).', forwards: 'Port forwards (nat on the firewall page).',
    vhosts: 'Sites on nginx (the reverse proxy page).', analyzer: 'Standing rules (the analyzer page); ad hoc captures need none of this.',
    wifi: 'SSIDs and the OpenWrt access points (the wifi page).',
    tables: 'Named address lists (aliases) for rules: use them as table:NAME, e.g. an office\'s addresses.'
  };
  function settingsPage() {
    var nav = $('set-nav'), body = $('set-body'), cur = null;
    var secs = Object.keys(SCHEMA.properties);
    nav.innerHTML = secs.map(function (k) { return '<a href="#' + k + '" data-sec="' + k + '">' + esc(k) + '</a>'; }).join('');
    function show(sec) {
      cur = sec;
      nav.querySelectorAll('a').forEach(function (a) { a.classList.toggle('on', a.getAttribute('data-sec') === sec); });
      $('set-title').textContent = '[' + sec + ']';
      var f = schemaAt([sec]);
      body.innerHTML = '';
      if (f.desc || SECTION_NOTES[sec]) body.appendChild(h('div', { class: 'dim', text: plain(f.desc || '') + ' ' + (SECTION_NOTES[sec] || '') }));
      if (f.kind === 'list' || f.kind === 'map') {
        var box = h('div', { class: 'lsted' });
        body.appendChild(box);
        workHooks = workHooks.filter(function (x) { return !x.settings; });
        var ed = listEditor(box, [sec]);
        ed.draw.settings = true;
        return;
      }
      var value = (work.doc || {})[sec], exists = value !== undefined;
      var fm = form(sec, f, value || {});
      var save = h('button', { type: 'button', class: 'primary', text: exists ? 'save' : 'add [' + sec + ']' });
      body.appendChild(fm.el);
      var row = h('div', { class: 'row' }, [save]);
      if (exists && (f.optional || f.def !== undefined)) {
        var rm = h('button', { type: 'button', class: 'danger', text: 'remove [' + sec + ']' });
        rm.addEventListener('click', function () {
          if (confirm('Remove the whole [' + sec + '] section' + (f.def !== undefined ? ' (back to the defaults)' : '') + '?')) edit({ op: 'set', path: [sec], value: null }, 'remove [' + sec + ']');
        });
        row.appendChild(rm);
      }
      if (!exists) row.appendChild(h('span', { class: 'dim', text: f.def !== undefined ? 'not in the file: the defaults apply' : 'not in the file: off' }));
      body.appendChild(row);
      save.addEventListener('click', function () { edit({ op: 'set', path: [sec], value: fm.get() }, 'change [' + sec + ']'); });
    }
    workHooks.push(function () {
      // list sections redraw themselves; a section form redraws after its save
      var f = cur && schemaAt([cur]);
      if (f && f.kind !== 'list' && f.kind !== 'map') show(cur);
    });
    nav.addEventListener('click', function (ev) {
      var a = ev.target.closest('a[data-sec]');
      if (a) { ev.preventDefault(); history.replaceState(null, '', '#' + a.getAttribute('data-sec')); show(a.getAttribute('data-sec')); }
    });
    show(secs.indexOf(location.hash.slice(1)) >= 0 ? location.hash.slice(1) : 'system');
  }

  // what each of pf's tables is for
  function tableNote(n) {
    var fixed = {
      internal: 'every internal network: "internal ranges" in rules',
      martians: 'addresses that never come from the internet: dropped on the WAN',
      martians6: 'the same for IPv6',
      public_resolvers: 'well-known DoH/DoT resolvers, blocked so clients can\'t go around the router\'s DNS',
      cls_realtime: 'filled by octopus-dns from [traffic] destinations: the realtime queue',
      cls_streaming: 'filled by octopus-dns from [traffic] destinations: the streaming queue',
      cls_bulk: 'filled by octopus-dns from [traffic] destinations: the bulk queue',
      lab_block: 'sources blocked by analyzer block rules, for block_for seconds',
      cloudflare: 'Cloudflare\'s ranges, for public sites with allow_from = cloudflare',
      wg_mgmt: 'WireGuard peers with mgmt access',
      wg_lan: 'WireGuard peers with lan access'
    };
    if (fixed[n]) return fixed[n];
    if (n.indexOf('t_') === 0) return 'your table ' + n.slice(2) + ' (settings, tables): table:' + n.slice(2) + ' in rules';
    return '';
  }

  // ---- firewall: the overview (/api/policy of the working copy) and the
  // new-rule box; a row starts the box from it, an entry of the file
  // (rules, forwards, links) is edited in place
  var policy = null, fwAt = null;
  var SECTIONS = { 'in': 'from the internet', out: 'from inside out', internal: 'between tiers and to the router' };
  var ACTION_CLASS = { allow: 'ok', deny: 'bad', nat: 'warn', redirect: 'warn', proxy: 'warn' };
  function loadPolicy() {
    if (!work) return;
    api('POST', '/api/policy', { toml: work.toml }).then(function (r) { policy = r.rows; policyTable(last); }).catch(function (e) {
      $('t-policy').innerHTML = '<tr><td class="bad">policy: ' + esc(e.message) + '</td></tr>';
    });
  }
  function policyTable(s) {
    if (!policy) return;
    var hits = {};
    ((s && s.pf.labels) || []).forEach(function (l) { hits[l.label] = l; });
    var head = ['source', 'destination', 'service', 'action', '#packets', '#bytes', 'note'], rows = [];
    ['in', 'out', 'internal'].forEach(function (sec) {
      policy.forEach(function (r, i) {
        if (r.section !== sec) return;
        if (!rows.length || rows[rows.length - 1].sec !== sec) {
          rows.push({ sec: sec, html: '<tr class="section"><th colspan="' + head.length + '">' + esc(SECTIONS[sec]) + '</th></tr>' });
        }
        var p = 0, b = 0, known = false;
        r.labels.forEach(function (l) { if (hits[l]) { p += hits[l].packets; b += hits[l].bytes; known = true; } });
        var mark = r.ref ? ' <span class="dim" title="in router.toml: click to edit">&#9998;</span>' : '';
        rows.push({ sec: sec, html: '<tr data-i="' + i + '" title="' + esc(r.labels.join(' ')) + '">' + td(esc(r.source)) + td(esc(r.destination)) + td(esc(r.service)) +
          td(esc(r.action) + mark, ACTION_CLASS[r.action]) + td(known ? p : '', p ? 'num' : 'num dim') + td(known ? bytes(b) : '', b ? 'num' : 'num dim') +
          td(esc(r.note), 'dim') + '</tr>' });
      });
    });
    table('t-policy', head, rows.map(function (x) { return x.html; }));
  }
  function endpointChoices(dst) {
    var d = work.doc || {}, o = [['internal', 'internal ranges'], ['internet', 'the internet'], ['self', 'the router']];
    if (dst) o.push(['any', 'anything']);
    tiersOf(d).forEach(function (n) { o.push(['net:' + n.name, 'tier ' + n.name + ' (' + n.address + ')']); });
    (d.hosts || []).forEach(function (x) { o.push(['host:' + x.name, 'host ' + x.name + ' (' + x.ip + ')']); });
    (d.tables || []).forEach(function (x) { o.push(['table:' + x.name, 'table ' + x.name]); });
    o.push(['', 'an address or prefix…']);
    return o;
  }
  var fw = {};
  function endpointField(name, dst) {
    var sel = h('select', { id: 'fw-' + name }), other = h('input', { id: 'fw-' + name + '-ip', placeholder: '203.0.113.7 or 10.0.0.0/24', size: 18, hidden: true });
    sel.addEventListener('change', function () { other.hidden = sel.value !== ''; if (!other.hidden) other.focus(); });
    return {
      el: h('span', { class: 'row' }, [sel, other]),
      fill: function () { options(sel, endpointChoices(dst)); },
      get: function () { return sel.value === '' ? other.value.trim() : sel.value; },
      set: function (tok) {
        tok = tok || (dst ? 'any' : 'internal');
        // bare names in the file: find their kind
        var known = endpointChoices(dst).map(function (o) { return o[0]; });
        var full = known.indexOf(tok) >= 0 ? tok : ['net:', 'host:', 'table:'].map(function (p) { return p + tok; }).filter(function (t) { return known.indexOf(t) >= 0; })[0];
        if (full) { sel.value = full; other.hidden = true; other.value = ''; } else { sel.value = ''; other.hidden = false; other.value = tok; }
      }
    };
  }
  function firewallBox() {
    var box = $('fw-new');
    $('t-guard').addEventListener('click', function (ev) {
      var b = ev.target.closest('[data-release]');
      if (!b || !confirm('Let ' + b.getAttribute('data-release') + ' reach the router again?')) return;
      busy(b, true);
      api('POST', '/api/guard-release', { mac: b.getAttribute('data-release') }).then(function (r) {
        toast(r.ok ? 'released' : 'not released', r.output, r.ok ? 'ok' : 'bad'); refresh();
      }).catch(function (e) { toast('release', e.message, 'bad'); });
    });
    fw.type = h('select', { id: 'fw-type' }, [['allow', 'allow'], ['deny', 'deny'], ['nat', 'nat (port forward, allows it too)']].map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
    fw.src = endpointField('src', false);
    fw.dst = endpointField('dst', true);
    fw.proto = h('select', { id: 'fw-proto' }, ['any', 'tcp', 'udp', 'tcp/udp', 'icmp', 'gre', 'esp'].map(function (p) { return h('option', { value: p, text: p }); }));
    fw.port = h('input', { id: 'fw-port', placeholder: '443, 8000-8010', size: 14 });
    fw.toPort = h('input', { id: 'fw-toport', type: 'number', placeholder: 'same', size: 6 });
    fw.reflect = h('input', { id: 'fw-reflect', type: 'checkbox' });
    fw.desc = h('input', { id: 'fw-desc', placeholder: 'what it is for', size: 30 });
    fw.log = h('input', { id: 'fw-log', type: 'checkbox' });
    fw.save = h('button', { type: 'button', class: 'primary', id: 'fw-save', text: 'add rule' });
    fw.del = h('button', { type: 'button', class: 'danger', id: 'fw-del', text: 'delete this rule', hidden: true });
    fw.clear = h('button', { type: 'button', id: 'fw-clear', text: 'clear' });
    fw.help = h('div', { class: 'dim', id: 'fw-help' });
    var natOnly = h('span', { class: 'row' }, [h('label', { class: 'row' }, ['inside port', fw.toPort]), h('label', { class: 'row' }, [fw.reflect, 'reflect (inside clients via the public address)'])]);
    box.appendChild(h('div', { class: 'form' }, [
      h('label', { class: 'lbl', text: 'type' }), h('div', { class: 'fld' }, [fw.type]),
      h('label', { class: 'lbl', text: 'source' }), h('div', { class: 'fld' }, [fw.src.el]),
      h('label', { class: 'lbl', text: 'destination' }), h('div', { class: 'fld' }, [fw.dst.el]),
      h('label', { class: 'lbl', text: 'service' }), h('div', { class: 'fld' }, [h('span', { class: 'row' }, [fw.proto, 'port', fw.port, natOnly])]),
      h('label', { class: 'lbl', text: 'description' }), h('div', { class: 'fld' }, [h('span', { class: 'row' }, [fw.desc, h('label', { class: 'row' }, [fw.log, 'log'])])])
    ]));
    box.appendChild(h('div', { class: 'row' }, [fw.save, fw.del, fw.clear]));
    box.appendChild(fw.help);
    function sync() {
      var t = fw.type.value;
      natOnly.hidden = t !== 'nat';
      fw.help.textContent = t === 'nat' ? 'nat: a port on the WAN address forwarded to one inside host (source: the internet, or outside addresses). It also allows that traffic.' :
        t === 'allow' ? 'allow: applies where the traffic comes in, on the source\'s network; internal ranges = every network. From the internet only nat lets anything in.' :
          'deny: on the source\'s network; from the internet it blocks before any port forward. Rules are first-match, in file order (move them in settings → rules).';
    }
    fw.type.addEventListener('change', sync);
    fw.clear.addEventListener('click', function () { setRule(null, { type: 'allow', source: 'internal', destination: 'internet' }); });
    fw.save.addEventListener('click', function () {
      var r = { type: fw.type.value, source: fw.src.get(), destination: fw.dst.get(), proto: fw.proto.value, port: fw.port.value.trim(),
        description: fw.desc.value.trim(), log: fw.log.checked, reflect: fw.type.value === 'nat' && fw.reflect.checked };
      if (r.type === 'nat' && fw.toPort.value) r.to_port = Number(fw.toPort.value);
      var what = (fwAt ? 'change rule: ' : 'rule: ') + r.type + ' ' + r.source + ' → ' + r.destination + (r.proto !== 'any' ? ' ' + r.proto : '') + (r.port ? ' ' + r.port : '');
      busy(fw.save, true);
      edit({ op: 'firewall', rule: r, at: fwAt }, what).then(function (ok) {
        busy(fw.save, false);
        if (ok) setRule(null, { type: 'allow', source: 'internal', destination: 'internet' });
      });
    });
    fw.del.addEventListener('click', function () {
      if (!fwAt || !confirm('Delete this rule?')) return;
      edit({ op: 'set', path: [fwAt[0], fwAt[1]], value: null }, 'delete ' + fwAt[0] + ' ' + (fwAt[1] + 1)).then(function (ok) {
        if (ok) setRule(null, { type: 'allow', source: 'internal', destination: 'internet' });
      });
    });
    $('t-policy').addEventListener('click', function (ev) {
      var tr = ev.target.closest('tr[data-i]');
      if (!tr || !policy) return;
      $('t-policy').querySelectorAll('tr.on').forEach(function (x) { x.classList.remove('on'); });
      tr.classList.add('on');
      var row = policy[Number(tr.getAttribute('data-i'))];
      if (row.ref) {
        setRule(row.ref, fromEntry(row.ref[0], getAt(work.doc, row.ref)));
      } else {
        setRule(null, { type: row.action === 'deny' ? 'deny' : row.action === 'nat' ? 'nat' : 'allow', source: row.src, destination: row.dst });
        $('fw-mode').textContent = 'new rule, started from: ' + row.source + ' → ' + row.destination + ' (' + row.action + ')';
      }
      box.scrollIntoView({ block: 'nearest' });
    });
    workHooks.push(function () { fw.src.fill(); fw.dst.fill(); loadPolicy(); });
    fw.src.fill(); fw.dst.fill();
    setRule(null, { type: 'allow', source: 'internal', destination: 'internet' });
    sync();
    fw.sync = sync;
  }
  // a rules / forwards / links entry as the box's fields
  function fromEntry(list, e) {
    e = e || {};
    var host = function (ip) { var x = ((work.doc || {}).hosts || []).filter(function (y) { return y.ip === ip; })[0]; return x ? 'host:' + x.name : ip; };
    if (list === 'forwards') {
      return { type: 'nat', source: e.from && e.from !== 'any' ? e.from : 'internet', destination: host(e.to), proto: e.proto || 'tcp', port: e.port,
        to_port: e.to_port, reflect: e.reflect, log: e.log, description: e.name };
    }
    if (list === 'links') return { type: 'allow', source: 'net:' + e.network, destination: e.to, proto: e.proto, port: e.port, description: e.description };
    var src = e.network === 'all' ? (e.from && e.from !== 'any' ? e.from : 'internal') :
      e.network === 'wan' ? (e.from && e.from !== 'any' ? e.from : 'internet') : (e.from && e.from !== 'any' ? e.from : 'net:' + e.network);
    return { type: e.action === 'pass' ? 'allow' : 'deny', source: src, destination: e.to || 'any', proto: e.proto, port: e.port, log: e.log, description: e.description };
  }
  function setRule(at, r) {
    fwAt = at;
    fw.type.value = r.type;
    fw.src.set(r.source);
    fw.dst.set(r.destination);
    fw.proto.value = r.proto || 'any';
    fw.port.value = r.port === undefined || r.port === null ? '' : r.port;
    fw.toPort.value = r.to_port || '';
    fw.reflect.checked = !!r.reflect;
    fw.desc.value = r.description || '';
    fw.log.checked = !!r.log;
    fw.save.textContent = at ? 'save this rule' : 'add rule';
    fw.del.hidden = !at;
    $('fw-mode').textContent = at ? 'editing ' + at[0] + ' ' + (at[1] + 1) + ' of router.toml' : 'click a rule below to start from it';
    if (fw.sync) fw.sync();
  }

  // ---- DNS page: upstreams and views, sinkhole (overrides: a list editor)
  function dnsSetup() {
    var sm = work.summary;
    if (!sm) { $('dns-setup').innerHTML = '<span class="bad">router.toml does not parse: fix it on the config page</span>'; return; }
    var d = sm.dns;
    var ups = function (l) { return (l || []).map(function (u) { return esc(u.ip) + ' <span class="dim">' + esc(u.tls_name) + '</span>'; }).join(', '); };
    $('dns-setup').innerHTML = '<div>engine <code>' + esc(d.engine) + '</code></div><div>everyone else: ' +
      (ups(d.upstreams) || '<span class="dim">no upstreams</span>') + '</div>';
    table('t-dviews', ['view', 'upstreams', 'clients'], d.views.map(function (v) {
      return '<tr>' + td(esc(v.name) + (v.description ? '<div class="dim">' + esc(v.description) + '</div>' : '')) + td(ups(v.upstreams)) +
        td(v.clients.map(function (c) {
          return '<span class="chip">' + esc(c) + rmButton('view-rm', { view: v.name, client: c }, 'take ' + c + ' out of ' + v.name) + '</span>';
        }).join(' ') || '<span class="dim">none</span>') + '</tr>';
    }));
    var names = d.views.map(function (v) { return [v.name, v.name]; });
    if (!d.views.some(function (v) { return v.name === 'unfiltered'; })) names.push(['unfiltered', 'unfiltered (new: plain 1.1.1.1)']);
    options($('view-name'), names);
    $('dl-hosts').innerHTML = sm.hosts.map(function (h) { return '<option value="' + esc(h.name) + '">' + esc(h.ip + ' ' + h.network) + '</option>'; }).join('');
    $('sink-now').innerHTML = d.sinkhole ? 'blocked names resolve to <code>' + esc(d.sinkhole) + '</code>' :
      '<span class="dim">not set: blocked names keep the upstream\'s answer</span>';
  }
  function dnsPage() {
    onSubmit('f-view', function () {
      var c = $('view-client').value.trim(), v = $('view-name').value;
      return edit({ op: 'view_client_add', view: v, client: c }, 'send ' + c + ' to view ' + v);
    });
    onSubmit('f-sinkhole', function () {
      var ip = $('sink-ip').value.trim();
      return edit({ op: 'sinkhole_set', ip: ip }, ip ? 'sinkhole at ' + ip : 'no sinkhole');
    });
    $('btn-sink-clear').addEventListener('click', function () { edit({ op: 'sinkhole_set', ip: '' }, 'no sinkhole'); });
    var ov = listEditor($('le-overrides'), ['dns', 'overrides'], {
      columns: [['name', function (o) { return esc(o.name) + (o.subdomains === false ? '' : ' <span class="dim">and subdomains</span>'); }],
        ['address', function (o) { return esc(o.ip); }], ['description', function (o) { return esc(o.description || ''); }]]
    });
    // a name in the query log: override it
    document.addEventListener('click', function (ev) {
      var a = ev.target.closest('[data-qname]');
      if (!a) return;
      ev.preventDefault();
      ov.add({ name: a.getAttribute('data-qname').replace(/\.$/, ''), ip: (work.summary && work.summary.dns.sinkhole) || '' });
      $('le-overrides').scrollIntoView({ block: 'center' });
    });
    workHooks.push(dnsSetup);
    dnsSetup();
  }

  // ---- dhcp: reservations ([[hosts]] with a mac), a lease can be reserved
  function inPrefix(ip, cidr) {
    var p = String(cidr).split('/'), size = Math.pow(2, 32 - Number(p[1] || 32));
    var n = function (a) { return a.split('.').reduce(function (x, y) { return x * 256 + Number(y); }, 0); };
    return Math.floor(n(ip) / size) === Math.floor(n(p[0]) / size);
  }
  function tierOfIp(ip) {
    var t = tiersOf((work && work.doc) || {}).filter(function (n) { return inPrefix(ip, n.address); })[0];
    return t ? t.name : '';
  }
  function dhcpPage() {
    var ed = listEditor($('le-hosts'), ['hosts'], {
      columns: [['host', function (x) { return esc(x.name); }], ['tier', function (x) { return esc(x.tier || x.network || tierOfIp(x.ip)); }], ['address', function (x) { return esc(x.ip); }],
        ['mac', function (x) { return x.mac ? esc(x.mac) : '<span class="dim">no mac: DNS name only</span>'; }], ['description', function (x) { return esc(x.description || ''); }]]
    });
    document.addEventListener('click', function (ev) {
      var b = ev.target.closest('[data-reserve]');
      if (!b) return;
      var ip = b.getAttribute('data-ip');
      var name = (b.getAttribute('data-host') || '').toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '');
      ed.add({ name: name, ip: ip, mac: b.getAttribute('data-mac') });
      $('le-hosts').scrollIntoView({ block: 'center' });
    });
  }

  // ---- wifi: SSIDs onto router networks, OpenWrt access points
  function slugKey(ssid) {
    return 'wifi_' + String(ssid || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);
  }
  function secretKey(ref) { return /^secret:/.test(ref || '') ? ref.slice(7) : ''; }
  // name, range, VLAN and kind for a tier made from the wifi page: on the
  // house ports ([lan]) as a VLAN; a guest tier comes with its rules
  function newNetworkForm() {
    var d = (work && work.doc) || {}, nets = tiersOf(d), lan = !!d.lan;
    var used = nets.map(function (n) { return n.vlan; });
    var vlan = 3;
    while (used.indexOf(vlan) >= 0) vlan++;
    var apHome = (((d.wifi || {}).aps || [])[0] || {}).host;
    var hostOf = (d.hosts || []).filter(function (x) { return x.name === apHome; })[0];
    var home = (hostOf && (hostOf.tier || hostOf.network || tierOfIp(hostOf.ip))) ||
      (nets.filter(function (n) { return n.kind === 'mgmt'; })[0] || nets[0] || {}).name;
    var name = h('input', { value: 'wifi', size: 12 }), addr = h('input', { placeholder: '192.168.3.1/24', size: 18 });
    var tag = h('input', { type: 'number', value: vlan, min: 2, max: 4094, size: 5 });
    var kind = h('select', {}, (lan ? [['open', 'internal: reaches everything (the rules decide)'], ['guest', 'guests: the internet and the router\'s DNS, nothing inside']] :
      [['lan', 'lan: internet and router services'], ['guest', 'guest: internet only, clients isolated'], ['mgmt', 'mgmt: everything']])
      .map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
    var on = h('select', {}, nets.filter(function (n) { return !n.vlan && (n.interface || n.bridge); }).map(function (n) {
      return h('option', { value: n.name, text: 'the ports of ' + n.name + (n.bridge ? ' (' + n.bridge.join(', ') + ')' : n.interface ? ' (' + n.interface + ')' : '') });
    }));
    on.value = home;
    var where = lan ? [h('label', { class: 'lbl', text: 'carried on' }), h('div', { class: 'fld' }, [h('span', { text: 'the house ports ([lan]), tagged' })])] :
      [h('label', { class: 'lbl', text: 'carried on' }), h('div', { class: 'fld' }, [on, h('div', { class: 'help', text: 'where the access points are plugged in' })])];
    var box = h('div', { class: 'form newnet', hidden: true }, [
      h('label', { class: 'lbl req', text: 'new tier' }), h('div', { class: 'fld' }, [name, h('div', { class: 'help', text: 'its name in router.toml' })]),
      h('label', { class: 'lbl req', text: 'router address' }), h('div', { class: 'fld' }, [addr, h('div', { class: 'help', text: 'the router in the new range and its size, e.g. 192.168.3.1/24; DHCP hands out the rest' })]),
      h('label', { class: 'lbl', text: 'vlan' }), h('div', { class: 'fld' }, [tag, h('div', { class: 'help', text: 'the tag it travels with between router and access points' })]),
      h('label', { class: 'lbl', text: 'kind' }), h('div', { class: 'fld' }, [kind])
    ].concat(where));
    function ip(n) { return [n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255].join('.'); }
    return {
      el: box,
      show: function (yes) { box.hidden = !yes; if (yes) addr.focus(); },
      create: function (v) {
        if (v.tier !== '__new') return Promise.resolve(v);
        var m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(addr.value.trim());
        if (!m || Number(m[5]) > 30) return Promise.reject(new Error('router address: like 192.168.3.1/24'));
        var a = ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0, size = Math.pow(2, 32 - Number(m[5]));
        var base = a - a % size;
        var t = { name: name.value.trim(), address: addr.value.trim(), vlan: Number(tag.value), dhcp: { range: [ip(base + 10), ip(base + size - 2)] } };
        var edits = [];
        if (!lan) {
          t.kind = kind.value;
          var src = nets.filter(function (n) { return n.name === on.value; })[0] || {};
          if (src.bridge) t.bridge = src.bridge; else t.interface = src.interface;
        }
        edits.push({ op: 'append', path: [tierKey(d)], value: t });
        if (lan && kind.value === 'guest') {
          // the guests' policy as ordinary rules, editable on the firewall page
          var g = 'net:' + t.name;
          edits.push({ op: 'append', path: ['rules'], value: { network: 'all', action: 'pass', from: g, to: 'self', proto: 'tcp/udp', port: '53,123', description: 'guests: the router\'s DNS and NTP' } });
          edits.push({ op: 'append', path: ['rules'], value: { network: 'all', action: 'pass', from: g, to: 'self', proto: 'icmp', description: 'guests: ping the router' } });
          edits.push({ op: 'append', path: ['rules'], value: { network: 'all', action: 'block', from: g, to: 'internal', description: 'guests: nothing else inside (allow exceptions above this)' } });
        }
        var what = 'add tier ' + t.name + ' (' + t.address + ', vlan ' + t.vlan + (kind.value === 'guest' ? ', guests' : '') + ')';
        return edit(edits.length === 1 ? edits[0] : { op: 'batch', edits: edits }, what).then(function (ok) {
          if (!ok) throw new Error('the tier was not added');
          v.tier = t.name;
          return v;
        });
      }
    };
  }

  function wifiPage() {
    var d = function () { return (work && work.doc) || {}; };
    var netOf = function (name) { return tiersOf(d()).filter(function (n) { return n.name === name; })[0] || {}; };
    var have = function (key) { return ((last && last.wifi_secrets) || []).indexOf(key) >= 0; };
    // a guest tier: the old kind, or the rules that block it from inside
    var isGuest = function (t) {
      return netOf(t).kind === 'guest' || (d().rules || []).some(function (r) { return r.from === 'net:' + t && r.to === 'internal' && r.action !== 'pass'; });
    };
    var ssids = listEditor($('le-ssids'), ['wifi', 'networks'], {
      columns: [['ssid', function (n) { return esc(n.ssid) + (n.hidden ? ' <span class="dim">hidden</span>' : ''); }],
        ['tier', function (n) { var t = n.tier || n.network; return esc(t) + (isGuest(t) ? ' <span class="warn">guests</span>' : '') + (netOf(t).vlan ? ' <span class="dim">vlan ' + netOf(t).vlan + '</span>' : ''); }],
        ['security', function (n) { return esc(n.security || 'wpa2-wpa3'); }],
        ['password', function (n) {
          if ((n.security || '') === 'open') return '<span class="dim">none</span>';
          var k = secretKey(n.password);
          return !k ? '<span class="bad">not set</span>' : have(k) ? '<span class="ok">set</span>' : '<span class="bad">' + esc(k) + ' missing</span>';
        }],
        ['bands', function (n) { return esc((n.bands || ['2g', '5g']).join(' ')); }],
        ['clients isolated', function (n) { var iso = n.isolate !== undefined ? n.isolate : isGuest(n.tier || n.network); return iso ? 'yes' : '<span class="dim">no</span>'; }]],
      // the password never comes back: typed here, stored on the router;
      // router.toml only holds its name (password = "secret:wifi_...")
      hide: ['password'],
      addGuard: function () { return work.summary && work.summary.wifi_country ? '' : 'set the country first'; },
      extra: function (val) {
        var k = secretKey(val.password), stored = k && have(k);
        var pw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: stored ? 'leave empty to keep it' : '8 to 63 characters', size: 30 });
        var el = h('div', { class: 'form' }, [h('label', { class: 'lbl req', text: 'password' }),
          h('div', { class: 'fld' }, [pw, h('div', { class: 'help', text: (stored ? 'a password is stored on the router; type a new one to change it. ' : 'none stored yet. ') +
            'It is kept in secrets.toml on the router as soon as you save (never shown again, not in router.toml); the access points get it with the next apply. Open networks need none.' })])]);
        // a new address range for this SSID: a new router network, as a VLAN
        // on the ports the access points are on
        var nn = newNetworkForm();
        var wrap = h('div', { class: 'col' }, [el, nn.el]);
        setTimeout(function () {
          var sel = wrap.parentNode && wrap.parentNode.querySelector('select[data-key="wifi.networks.tier"]');
          if (!sel) return;
          sel.appendChild(h('option', { value: '__new', text: 'new tier…' }));
          sel.addEventListener('change', function () { nn.show(sel.value === '__new'); });
        }, 0);
        return {
          el: wrap,
          apply: function (v) {
            return nn.create(v).then(function (v) { return storePassword(v); });
          }
        };
        function storePassword(v) {
          if (v.security === 'open' || !pw.value) return v;
          var key = secretKey(v.password) || slugKey(v.ssid);
          return api('POST', '/api/secret', { key: key, value: pw.value }).then(function (r) {
            if (!r.ok) throw new Error(r.output || 'not stored');
            v.password = 'secret:' + key;
            if (last) { last.wifi_secrets = (last.wifi_secrets || []).concat([key]); }
            return v;
          });
        }
      }
    });
    var aps = listEditor($('le-aps'), ['wifi', 'aps'], {
      addGuard: function () { return work.summary && work.summary.wifi_country ? '' : 'set the country first'; },
      columns: [['access point', function (a) { return esc(a.name); }],
        ['host', function (a) { var x = (d().hosts || []).filter(function (y) { return y.name === a.host; })[0]; return esc(a.host) + (x ? ' <span class="dim">' + esc(x.ip) + '</span>' : ' <span class="bad">no such host</span>'); }],
        ['channels', function (a) { return esc((a.channel_2g || 'auto') + ' / ' + (a.channel_5g || 'auto')); }],
        ['last push', function (a) {
          var st = ((last && last.aps) || {})[a.name];
          if (!st) return '<span class="dim">never</span>';
          return '<span class="' + (st.ok ? 'ok' : 'bad') + '">' + esc(st.result) + '</span> <span class="dim">' + esc(when(st.at).slice(0, 16)) + '</span>';
        }]]
    });
    // [wifi] country: needed before anything else
    var box = $('wifi-country'), cin = h('input', { size: 3, maxlength: 2, placeholder: 'CZ' }), cbtn = h('button', { type: 'button', text: 'set' });
    box.appendChild(h('label', { class: 'row' }, ['country (regulatory domain)', cin]));
    box.appendChild(cbtn);
    var note = h('span', { class: 'dim' });
    box.appendChild(note);
    // the regulatory domain: set, or the time zone's country
    var syncCountry = function () {
      var w = d().wifi, sm = work.summary || {};
      cin.value = (w && w.country) || '';
      cin.placeholder = sm.wifi_country || '';
      note.innerHTML = sm.wifi_country_set ? '' : sm.wifi_country ?
        '<span class="dim">' + esc(sm.wifi_country) + ' from the time zone ' + esc(sm.timezone) + ' (which channels and power are legal); set it only if the access points are elsewhere</span>' :
        '<span class="warn">set the country first</span>: it decides the channels and power the access points may use, and the time zone doesn\'t say';
    };
    cbtn.addEventListener('click', function () {
      var c = cin.value.trim().toUpperCase();
      edit(d().wifi ? { op: 'set', path: ['wifi', 'country'], value: c } : { op: 'set', path: ['wifi'], value: { country: c } }, 'wifi country ' + c);
    });
    workHooks.push(syncCountry);
    syncCountry();
    var push = function (force) {
      return function () {
        var b = this; busy(b, true);
        api('POST', '/api/ap-push', { force: force }).then(function (r) {
          toast(r.ok ? 'pushed' : 'not every access point was updated', r.output, r.ok ? 'ok' : 'bad'); refresh();
        }).catch(function (e) { toast('push', e.message, 'bad'); }).then(function () { busy(b, false); });
      };
    };
    $('btn-push').addEventListener('click', push(false));
    $('btn-push-force').addEventListener('click', push(true));
    render.wifi = function (s) {
      $('ap-key').textContent = s.ap_key || 'none yet (octopus ap key on the router)';
      ssids.draw(); aps.draw();
    };
    if (last) render.wifi(last);
  }

  // ---- reverse proxy: [[vhosts]]
  function vhostsPage() {
    var dom = function () { return ((work.doc || {}).system || {}).domain || ''; };
    var names = function (v) { return v.hostnames && v.hostnames.length ? v.hostnames : [v.name.indexOf('.') >= 0 ? v.name : v.name + '.' + dom()]; };
    listEditor($('le-vhosts'), ['vhosts'], {
      columns: [['site', function (v) { return esc(v.name); }], ['names', function (v) { return esc(names(v).join(', ')); }],
        ['to', function (v) { return esc(v.upstream); }],
        ['internet', function (v) { return v['public'] ? '<span class="warn">public</span>' + (v.allow_from ? ' <span class="dim">from ' + esc(v.allow_from.join(', ')) + '</span>' : '') : '<span class="dim">inside only</span>'; }],
        ['certificate', function (v) { return v.cert ? esc(v.cert) : v['public'] ? "Let's Encrypt" : 'services root'; }]]
    });
  }

  // ---- analyzer page: rules, one-shot captures and the packet viewer
  function unb64(s) {
    var b = atob(s || ''), a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }
  // offset, hex, text; headers dim, the regex match marked
  function hexdump(data, payloadAt, match) {
    function cls(i) {
      if (match && i >= payloadAt + match[0] && i < payloadAt + match[1]) return 'm';
      return i < payloadAt ? 'h' : 'p';
    }
    var lines = [];
    for (var off = 0; off < data.length; off += 16) {
      var hex = '', txt = '';
      for (var j = 0; j < 16; j++) {
        var i = off + j, gap = j === 7 ? '  ' : ' ';
        if (i >= data.length) { hex += '  ' + gap; continue; }
        var c = cls(i), b = data[i];
        hex += '<span class="' + c + '">' + (b < 16 ? '0' : '') + b.toString(16) + '</span>' + gap;
        txt += '<span class="' + c + '">' + (b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : '.') + '</span>';
      }
      lines.push('<span class="off">' + ('000' + off.toString(16)).slice(-4) + '</span>  ' + hex + ' ' + txt);
    }
    return lines.join('\n');
  }
  var cap = null;
  function showPacket(i) {
    var p = cap.packets[i], data = unb64(p.data);
    $('t-packets').querySelectorAll('tr[data-i]').forEach(function (tr) { tr.classList.toggle('on', Number(tr.getAttribute('data-i')) === i); });
    $('pkt-hex').innerHTML = '<span class="dim">packet ' + (i + 1) + ': ' + p.caplen + ' bytes captured of ' + p.len +
      (data.length < p.caplen ? ', the first ' + data.length + ' shown (the pcap has them all)' : '') + '; header dim, payload, ' +
      '</span><span class="m">match</span>\n' + hexdump(data, p.payload_at, p.match);
  }
  function showCapture(r) {
    cap = r;
    $('cap-status').innerHTML = 'bpf filter <code>' + esc(r.filter || '(none)') + '</code>';
    $('pkt-summary').textContent = r.packets.length + ' kept of ' + r.seen + ' seen on ' + r['interface'] +
      (r.limit ? ', stopped at the packet limit' : '') + (r.pcap_truncated ? ', pcap cut at 8 MiB' : '');
    table('t-packets', ['#', 'time (UTC)', 'from', 'to', 'proto', '#len', 'match'], r.packets.map(function (p, i) {
      var port = function (n) { return n ? '<span class="dim">:' + n + '</span>' : ''; };
      return '<tr data-i="' + i + '">' + td(i + 1, 'num dim') + td(esc(when(p.ts).slice(11, 19)) + '<span class="dim">.' + ('00000' + p.usec).slice(-6) + '</span>') +
        td(esc(p.src || '-') + port(p.sport)) + td(esc(p.dst || '-') + port(p.dport)) + td(esc(p.proto), 'dim') + td(p.len, 'num') +
        td(p.match ? 'bytes ' + p.match[0] + '-' + p.match[1] : '', 'ok') + '</tr>';
    }));
    $('pkt-pcap').disabled = !r.packets.length;
    if (r.packets.length) showPacket(0); else $('pkt-hex').textContent = '';
  }
  // the last capture's pcap, saved through a link the browser follows (a
  // download, not a fetch: the CSP's connect-src stays 'self')
  function downloadPcap() {
    if (!cap) return;
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([unb64(cap.pcap)], { type: 'application/vnd.tcpdump.pcap' }));
    a.download = 'capture-' + cap['interface'] + '-' + new Date().toISOString().slice(0, 19).replace(/[-:]/g, '') + '.pcap';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 10000);
  }
  // the standing rules' switch, from the working copy
  function analyzerState() {
    var an = ((work && work.doc) || {}).analyzer || {}, n = (an.rules || []).length;
    $('an-enabled').checked = !!an.enabled;
    $('an-state').textContent = an.enabled ? (n ? n + ' rule(s) run' : 'on, but there are no rules yet') : 'off: the rules are kept, nothing runs';
    $('an-running').hidden = !an.enabled;
  }
  function analyzerPage() {
    $('pkt-pcap').addEventListener('click', downloadPcap);
    $('an-enabled').addEventListener('change', function () {
      var on = this.checked;
      edit({ op: 'set', path: ['analyzer', 'enabled'], value: on }, (on ? 'run' : 'stop') + ' the standing analyzer rules').then(function (ok) { if (!ok) analyzerState(); });
    });
    workHooks.push(analyzerState);
    analyzerState();
    listEditor($('le-analyzer'), ['analyzer', 'rules'], {
      columns: [['rule', function (r) { return esc(r.name); }], ['network', function (r) { return esc(r.network); }],
        ['fcap', function (r) { return '<code>' + esc(r.fcap) + '</code>'; }], ['payload regex (PCRE)', function (r) { return esc(r.regex || ''); }],
        ['action', function (r) { return esc(r.action || 'log'); }]]
    });
    $('f-capture').addEventListener('submit', function (ev) {
      ev.preventDefault();
      var b = $('btn-capture'), sec = Number($('cap-sec').value) || 10, ifname = $('cap-if').value;
      busy(b, true);
      $('cap-status').textContent = 'capturing on ' + ifname + ' for up to ' + sec + ' s';
      api('POST', '/api/capture', { 'interface': ifname, fcap: $('cap-fcap').value, pcre: $('cap-pcre').value, seconds: sec,
        max_packets: Number($('cap-max').value) || 100 }).then(showCapture).catch(function (e) {
        $('cap-status').innerHTML = '<span class="bad">' + esc(e.message) + '</span>';
      }).then(function () { busy(b, false); });
    });
    $('t-packets').addEventListener('click', function (ev) {
      var tr = ev.target.closest('tr[data-i]');
      if (tr && cap) showPacket(Number(tr.getAttribute('data-i')));
    });
  }

  function refresh() {
    return api('GET', '/api/status').then(function (s) {
      last = s;
      statusbar(s);
      if (render[page]) render[page](s);
    }).catch(function (e) {
      $('statusbar').innerHTML = '<span class="bad">&#9679; status: ' + esc(e.message) + '</span>';
    });
  }

  // ---- config page
  function diffHtml(text) {
    return text.split('\n').map(function (l) {
      var c = l.charAt(0) === '+' && l.indexOf('+++') !== 0 ? 'add' :
              l.charAt(0) === '-' && l.indexOf('---') !== 0 ? 'del' :
              l.indexOf('@@') === 0 ? 'hunk' : '';
      return c ? '<span class="' + c + '">' + esc(l) + '</span>' : esc(l);
    }).join('\n');
  }

  function diagHtml(d) {
    if (!d.length) return '<span class="ok">no errors, no warnings</span>';
    return d.map(function (x) {
      return '<div class="' + (x.level === 'error' ? 'bad' : 'warn') + '">' + esc(x.level) + ' [' + esc(x.code) + '] ' + esc(x.msg) + '</div>';
    }).join('');
  }

  function busy(btn, on) {
    btn.disabled = on;
    btn.classList.toggle('busy', on);
  }

  function configPage() {
    var ta = $('config-text');
    var out = $('out'), outTitle = $('out-title');
    function show(title, html) { outTitle.textContent = title; out.innerHTML = html; }

    $('btn-check').addEventListener('click', function () {
      var b = this; busy(b, true);
      api('POST', '/api/check', { toml: ta.value }).then(function (r) {
        show('check', diagHtml(r.diagnostics) + (r.ok ? '<div class="dim">' + r.files.length + ' files would be rendered</div>' : ''));
        toast(r.ok ? 'check passed' : 'check failed', r.ok ? '' : 'see the output window', r.ok ? 'ok' : 'bad');
      }).catch(function (e) { toast('check', e.message, 'bad'); }).then(function () { busy(b, false); });
    });

    $('btn-diff').addEventListener('click', function () {
      var b = this; busy(b, true);
      api('POST', '/api/diff', { toml: ta.value }).then(function (r) {
        show('diff against the router', r.diagnostics.length ? diagHtml(r.diagnostics) : '');
        out.innerHTML += '<pre class="diff">' + diffHtml(r.diff || '') + '</pre>';
      }).catch(function (e) { toast('diff', e.message, 'bad'); }).then(function () { busy(b, false); });
    });

    $('btn-apply').addEventListener('click', function () {
      if (!confirm('Apply this configuration? It rolls back automatically unless confirmed within 60 seconds.')) return;
      var b = this; busy(b, true);
      api('POST', '/api/apply', { toml: ta.value }).then(function (r) {
        show('apply', '<pre>' + esc(r.output) + '</pre>');
        toast(r.ok ? 'applied' : 'apply failed', r.ok ? 'confirm within 60 s' : 'see the output window', r.ok ? 'warn' : 'bad');
        if (r.ok) startOver();
        refresh();
      }).catch(function (e) { toast('apply', e.message, 'bad'); }).then(function () { busy(b, false); });
    });

    $('btn-reload').addEventListener('click', function () {
      api('GET', '/api/config').then(function (r) { ta.value = r.toml; toast('reloaded', 'router.toml from the router', 'ok'); });
    });
  }

  // the config page edits the text of the working copy when other pages
  // left changes in it; its apply starts the working copy over too
  function configWork() {
    if (work && work.edits.length) {
      $('config-text').value = work.toml;
      $('out').innerHTML = '<span class="warn">the text includes ' + work.edits.length + ' unapplied change(s) from the other pages (listed above)</span>';
    }
  }

  function pendingButtons() {
    var c = $('btn-confirm'), r = $('btn-rollback');
    if (c) c.addEventListener('click', function () {
      var b = this; busy(b, true);
      api('POST', '/api/confirm').then(function (x) {
        toast(x.ok ? 'confirmed' : 'confirm failed', x.output, x.ok ? 'ok' : 'bad'); refresh();
      }).catch(function (e) { toast('confirm', e.message, 'bad'); }).then(function () { busy(b, false); });
    });
    if (r) r.addEventListener('click', function () {
      var b = this; busy(b, true);
      api('POST', '/api/rollback').then(function (x) {
        toast(x.ok ? 'rolled back' : 'rollback failed', x.output, x.ok ? 'ok' : 'bad'); refresh();
      }).catch(function (e) { toast('rollback', e.message, 'bad'); }).then(function () { busy(b, false); });
    });
  }

  // tick the countdown locally between polls
  setInterval(function () {
    if (last && last.state.pending && last.state.pending.remaining > 0) {
      last.state.pending.remaining--;
      statusbar(last);
    }
  }, 1000);

  document.addEventListener('DOMContentLoaded', function () {
    pendingButtons();
    if (page === 'config') configPage();
    if (page === 'status') {
      $('tr-if').addEventListener('change', function () { trIf = this.value; traffic(); });
      $('tr-range').addEventListener('change', function () { trRange = this.value; traffic(); });
    }
    changesWindow();
    // the working copy and the schema first: most pages build on them
    Promise.all([loadWork(), loadSchema()]).then(function () {
      var init = { dns: dnsPage, analyzer: analyzerPage, dhcp: dhcpPage, vhosts: vhostsPage, wifi: wifiPage, settings: settingsPage, firewall: firewallBox, config: configWork }[page];
      if (init) init();
      if (page === 'firewall') loadPolicy();
    }).catch(function (e) { toast('page', e.message, 'bad'); });
    refresh();
    setInterval(refresh, page === 'config' ? 10000 : 5000);
  });
  window.Octopus = { toast: toast, refresh: refresh };
})();
