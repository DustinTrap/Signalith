// Servers page: the Signalith servers that share this OpenSearch, and the
// one that runs the background jobs (detections, threat intel downloads
// and retention). It only shows; it is live while open, so a takeover
// shows up within seconds. Everyone sees names, states and versions;
// admins also see addresses, clocks and what to fix.
'use strict';

(function () {
  const REFRESH_MS = 5000;
  const S = { data: null, key: '', at: 0, tried: 0, busy: false, failed: false, ticker: null, seq: 0 };

  // [pulse state, label] for each server state from api/cluster.
  const STATE = {
    ready: ['', 'Running'],
    starting: ['idle', 'Starting'],
    stopping: ['idle', 'Stopping'],
    stopped: ['idle', 'Stopped'],
    offline: ['down', 'Not answering'],
    conflict: ['down', 'Identity in use'],
  };
  const gone = (s) => s.state === 'offline' || s.state === 'stopped';
  const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

  pageHooks.push((name) => {
    if (name !== 'servers') return;
    if (!S.ticker) S.ticker = setInterval(tick, 1000);
    load();
  });

  // tick updates the "updated Ns ago" line and reloads every few seconds;
  // it stops when another page is open.
  function tick() {
    if (currentPage !== 'servers') {
      clearInterval(S.ticker);
      S.ticker = null;
      return;
    }
    if (document.hidden) return;
    foot();
    if (S.data && Date.now() - S.tried >= REFRESH_MS) load(true);
  }

  async function load(quiet) {
    if (S.busy) return;
    if (!S.data && quiet !== true) skeleton();
    S.busy = true;
    S.tried = Date.now();
    const seq = ++S.seq;
    try {
      const d = await api('api/cluster');
      if (seq !== S.seq) return;
      S.data = d;
      S.at = Date.now();
      S.failed = false;
      render(d);
    } catch (e) {
      if (seq !== S.seq) return;
      S.failed = true;
      if (S.data) foot();
      else failed(e);
    } finally {
      S.busy = false;
    }
  }

  // ---------- small parts ----------
  function alertBox(tone, title, body) {
    const ic = { danger: 'circle-alert', warning: 'triangle-alert', info: 'info' }[tone];
    const attrs = { class: 'alert', 'data-tone': tone };
    if (tone === 'danger') attrs.role = 'alert';
    return el('div', attrs, icon(ic), el('div', {}, el('b', {}, title), body ? el('p', {}, ...linked(body)) : null));
  }

  // linked turns the names of pages an admin can open into links.
  function linked(text) {
    const pages = can('admin') ? { 'Data retention page': 'retention', 'Settings page': 'settings' } : {};
    const names = Object.keys(pages);
    if (!names.length) return [text];
    const parts = [];
    const re = new RegExp(names.join('|'), 'g');
    let last = 0;
    let m;
    while ((m = re.exec(text))) {
      if (m.index > last) parts.push(text.slice(last, m.index));
      parts.push(el('a', { href: '#' + pages[m[0]], 'data-page': pages[m[0]] }, m[0]));
      last = re.lastIndex;
    }
    parts.push(text.slice(last));
    return parts;
  }

  // split makes a warning from api/cluster into a headline (its first
  // sentence) and what it means and what to do (the rest).
  function split(text) {
    const cut = text.indexOf('. ');
    return cut > 0 ? [text.slice(0, cut + 1), text.slice(cut + 2)] : [text, ''];
  }

  // seen says how long ago a server last wrote its heartbeat, in seconds
  // under a minute: a server stops answering within one.
  function seen(t) {
    const s = Math.round((Date.now() - new Date(t).getTime()) / 1000);
    if (!isFinite(s)) return '';
    return s < 60 ? `${Math.max(s, 1)}s ago` : ago(t);
  }

  // uptime says briefly how long a server has run.
  function uptime(t) {
    const s = (Date.now() - new Date(t).getTime()) / 1000;
    if (!isFinite(s) || s < 60) return 'Up less than a minute';
    const n = (v, one, many) => `${v} ${v === 1 ? one : many}`;
    if (s < 3600) return 'Up ' + n(Math.floor(s / 60), 'minute', 'minutes');
    if (s < 86400) return 'Up ' + n(Math.floor(s / 3600), 'hour', 'hours');
    return 'Up ' + n(Math.floor(s / 86400), 'day', 'days');
  }

  // clockOff says how far a server's clock is off OpenSearch's, only
  // when that matters: more than 2 seconds.
  function clockOff(s) {
    const ms = s.clock_offset_ms;
    if (ms == null || gone(s) || Math.abs(ms) <= 2000) return '';
    return `Clock ${(Math.abs(ms) / 1000).toFixed(1)} s ${ms > 0 ? 'behind' : 'ahead'}`;
  }

  const none = () => el('span', { class: 'sv-none' }, el('span', { 'aria-hidden': 'true' }, '–'), el('span', { class: 'sr-only' }, 'None'));

  // ---------- the list ----------
  function serverCell(s) {
    const addr = s.node_url || s.listen || '';
    return el('td', { 'data-col': 'server' },
      el('div', { class: 'sv-server' },
        el('span', { class: 'sv-server__icon' }, icon('server')),
        el('div', { class: 'sv-server__text' },
          el('div', { class: 'sv-server__name' }, el('span', { title: s.name }, s.name),
            s.self ? el('span', { class: 'badge badge--outline', title: 'The server that answered this page' }, 'This server') : null),
          addr ? el('div', { class: 'sv-server__addr mono', title: addr }, addr) : null)));
  }

  function statusCell(s) {
    const [state, label] = STATE[s.state] || ['idle', cap(s.state)];
    const pulse = el('span', { class: 'pulse', 'aria-hidden': 'true' });
    if (state) pulse.dataset.state = state;
    let sub = null;
    if (gone(s) && s.offline_since) {
      sub = el('div', { class: 'sv-sub', title: new Date(s.offline_since).toLocaleString() }, 'Last seen ' + seen(s.offline_since));
    } else if (s.state === 'ready' && s.started_at) {
      sub = el('div', { class: 'sv-sub', title: 'Started ' + new Date(s.started_at).toLocaleString() }, uptime(s.started_at));
    }
    const clock = clockOff(s);
    return el('td', { 'data-col': 'status' },
      el('span', { class: 'sv-state' }, pulse, label), sub,
      clock ? el('div', { class: 'sv-sub sv-warn', title: 'Keep every server’s clock in sync with NTP' }, icon('clock', 'icon--sm'), clock) : null);
  }

  function jobsCell(s, d) {
    const lease = d.lease || {};
    let body;
    if (s.jobs === 'runs' && lease.frozen) {
      body = [el('span', { class: 'badge badge--warning', title: 'OpenSearch’s disk is full: only the disk guard runs' }, icon('hard-drive', 'icon--sm'), 'Disk guard only')];
    } else if (s.jobs === 'runs') {
      body = [el('span', { class: 'badge badge--accent' }, icon('zap', 'icon--sm'), 'Runs jobs')];
    } else if (s.jobs === 'standby') {
      body = [el('span', { class: 'sv-standby' }, 'Standby')];
      const runner = (d.servers || []).find((x) => x.jobs === 'runs');
      if (s.cannot_take_over) {
        body.push(el('div', { class: 'sv-sub sv-warn' }, icon('triangle-alert', 'icon--sm'), el('span', {}, 'Won’t take over: ' + s.cannot_take_over)));
      } else if (runner) {
        body.push(el('div', { class: 'sv-sub' }, `Takes over if ${runner.name} stops`));
      }
    } else if (gone(s)) {
      body = [none()];
    } else {
      body = [el('span', { class: 'sv-standby' }, 'Doesn’t run them')];
      let why = s.not_eligible || '';
      if (/^detections\.scheduler is off/.test(why)) why = 'Run detections on schedule is off';
      if (why) body.push(el('div', { class: 'sv-sub' }, cap(why)));
    }
    return el('td', { 'data-col': 'jobs' }, ...body);
  }

  function row(s, d) {
    const attrs = { 'data-server': s.name };
    if (gone(s)) attrs.class = 'sv-gone';
    return el('tr', attrs, serverCell(s), statusCell(s), jobsCell(s, d),
      el('td', { 'data-col': 'version' }, s.version ? el('span', { class: 'mono' }, s.version) : none()));
  }

  function table(rows, busy) {
    return el('table', { class: 'table sv-table', 'aria-busy': String(!!busy) },
      el('thead', {}, el('tr', {},
        el('th', { scope: 'col', 'data-col': 'server' }, 'Server'),
        el('th', { scope: 'col', 'data-col': 'status' }, 'Status'),
        el('th', { scope: 'col', 'data-col': 'jobs' }, 'Background jobs'),
        el('th', { scope: 'col', 'data-col': 'version' }, 'Version'))),
      el('tbody', {}, ...rows));
  }

  // alerts says what needs a look, red for problems and amber for
  // attention. Admins get the server's own warnings, which name the fix;
  // viewers get the two that matter to them.
  function alerts(d, servers) {
    const out = [];
    const lease = d.lease || {};
    const diskFull = d.writes_refused || lease.frozen;
    if (Array.isArray(d.warnings)) {
      for (const w of d.warnings) {
        const [title, body] = split(w.text);
        out.push(alertBox(w.level === 'red' ? 'danger' : 'warning', title, body));
      }
      if (diskFull && !d.writes_refused) out.push(diskAlert(lease));
      return out;
    }
    if (diskFull) out.push(diskAlert(lease));
    else if (servers.length && !servers.some((s) => s.jobs === 'runs')) {
      out.push(alertBox('warning', 'No server runs detections, threat intel downloads or retention right now.',
        'If another server may run them, it takes them over within a minute. Admins see more on this page.'));
    }
    return out;
  }
  function diskAlert(lease) {
    const who = lease.holder_name;
    return alertBox('danger', 'OpenSearch’s disk is full, so it refuses new events.',
      (who ? `${who} keeps only the disk guard running, which deletes the oldest days to make room. ` : '') +
      'New events are stored again by themselves once there is room. An admin can make room sooner by giving OpenSearch more disk.');
  }

  // summary is the line under the list's title: who runs the jobs, and
  // OpenSearch's state.
  function summary(d, servers) {
    const parts = [];
    const runner = servers.find((s) => s.jobs === 'runs');
    if (runner) parts.push(`Jobs run on ${runner.name}`);
    else parts.push('No server runs the jobs right now');
    const versions = [...new Set(servers.filter((s) => !gone(s) && s.version).map((s) => s.version))];
    if (servers.length > 1 && versions.length === 1) parts.push('all on ' + versions[0]);
    const os = (d.opensearch || {}).status;
    if (os) parts.push(os === 'unreachable' ? 'OpenSearch can’t be reached' : 'OpenSearch ' + os);
    return parts.join(' · ');
  }

  function render(d) {
    const servers = d.servers || [];
    // Re-render only when something visible changed, so focus and
    // selection survive the refresh.
    const key = JSON.stringify(d) + servers.map((s) => (gone(s) ? seen(s.offline_since) : uptime(s.started_at))).join();
    if (key === S.key) { foot(); return; }
    S.key = key;
    const box = $('servers');
    box.removeAttribute('aria-busy');
    const parts = [];
    const al = alerts(d, servers);
    if (al.length) parts.push(el('div', { class: 'sv-alerts' }, ...al));

    const n = servers.length;
    const card = el('div', { class: 'card sv-card' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title' }, n === 1 ? '1 server' : `${n} servers`),
        el('p', { class: 'card__sub' }, summary(d, servers)))),
      el('div', { class: 'table-wrap' }, table(servers.map((s) => row(s, d)))),
      el('div', { class: 'table-foot' }, el('span', { class: 'live', id: 'servers-live' }),
        n === 1 ? el('span', { class: 'sv-foot-note' }, 'This is the only server. Adding more servers comes in a later release.') : null));
    parts.push(card);

    // Servers that were set up by hand before this version: an older
    // version does not take turns, so it would run the jobs a second time.
    if (n > 1 && can('admin')) {
      parts.push(el('div', { class: 'callout sv-note' }, icon('info'), el('div', {},
        el('b', {}, 'Upgrading servers you set up by hand? '),
        'Upgrade them all together, or first turn off ', el('i', {}, 'Run detections on schedule'),
        ' (detections.scheduler: false) on the ones you have not upgraded yet. Older versions don’t take turns, so they would run detections, threat intel downloads and retention a second time.')));
    }
    box.replaceChildren(...parts);
    foot();
  }

  // foot says when the list was last read.
  function foot() {
    const live = $('servers-live');
    if (!live || !S.at) return;
    const s = Math.max(0, Math.round((Date.now() - S.at) / 1000));
    const when = s < 5 ? 'just now' : s < 60 ? s + 's ago' : ago(S.at);
    const pulse = el('span', { class: 'pulse', 'aria-hidden': 'true' });
    if (S.failed) pulse.dataset.state = 'warn';
    live.replaceChildren(pulse, S.failed ? `Couldn’t refresh, retrying · updated ${when}` : `Live · updated ${when}`);
  }

  function skeleton() {
    const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
    const r = () => el('tr', {}, el('td', { 'data-col': 'server' }, bar('140px')), el('td', { 'data-col': 'status' }, bar('80px')),
      el('td', { 'data-col': 'jobs' }, bar('90px')), el('td', { 'data-col': 'version' }, bar('48px')));
    const box = $('servers');
    S.key = '';
    box.setAttribute('aria-busy', 'true');
    box.replaceChildren(el('div', { class: 'card sv-card' },
      el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Servers'))),
      el('div', { class: 'table-wrap' }, table([r(), r()], true))));
  }

  function failed(e) {
    const box = $('servers');
    S.key = '';
    box.removeAttribute('aria-busy');
    box.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger', role: 'alert' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, 'Couldn’t load the servers'),
      el('p', { class: 'empty__text' }, e.message || 'The Signalith server did not respond.'),
      el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => load() }, icon('refresh-cw'), 'Try again')))));
  }
})();
