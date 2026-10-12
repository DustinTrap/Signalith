// Signalith web UI. Plain JavaScript, no build step, so the server can
// embed it and run on Windows and Linux without Node.
'use strict';

const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...children) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
};

// icon returns an inline SVG for symbol #i-NAME in the sprite at the top of
// index.html, for example icon('search') or icon('x', 'icon--sm').
function icon(name, extraClass) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('class', 'icon' + (extraClass ? ' ' + extraClass : ''));
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(ns, 'use');
  use.setAttribute('href', '#i-' + name);
  svg.append(use);
  return svg;
}

// ago describes a past time briefly: just now, 5m ago, 3h ago, 2d ago.
function ago(t) {
  const s = (Date.now() - new Date(t).getTime()) / 1000;
  if (!isFinite(s)) return '';
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

// api calls the Signalith API. Paths are relative to the page so the UI
// works behind a proxy; a signed-out session goes to the sign-in page and
// comes back here afterwards.
let signingIn = false;
async function api(path, body, method) {
  const opts = body === undefined ? { method: method || 'GET' } : {
    method: method || 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  };
  const resp = await fetch(path.replace(/^\//, ''), opts);
  const data = await resp.json().catch(() => ({}));
  if (resp.status === 401 && !signingIn) {
    signingIn = true;
    location.assign('login?next=' + encodeURIComponent(location.pathname + location.search + location.hash));
  }
  if (!resp.ok) {
    const err = new Error(data.error || resp.statusText);
    err.pos = data.pos;
    err.problems = data.problems;
    throw err;
  }
  return data;
}

// ---------- app shell: navigation ----------
// Each page is a <section id="page-NAME" class="page">; its nav item
// (.nav__item[data-page=NAME]) gives the title and group shown in the top
// bar. The URL hash names the page, so links and Back work.
const appEl = $('app');
const narrow = matchMedia('(max-width: 960px)');
let currentPage = null;

function pageInfo(name) {
  const item = document.querySelector(`.nav__item[data-page="${name}"]`);
  const group = item && item.closest('.nav__group');
  return { title: item ? item.querySelector('span').textContent : name, group: group ? group.dataset.group : 'Help' };
}

// selectPage shows a page without loading its data.
function selectPage(name) {
  currentPage = name;
  document.querySelectorAll('.nav__item[data-page]').forEach((a) => {
    if (a.dataset.page === name) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  document.querySelectorAll('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + name));
  const { title, group } = pageInfo(name);
  $('crumb-group').textContent = group;
  $('crumb-page').textContent = title;
  document.title = title + ' · Signalith';
}

// showPage opens a page and loads its data. opts.replace keeps the
// current history entry instead of adding one.
function showPage(name, opts = {}) {
  if (!$('page-' + name)) return;
  const switching = name !== currentPage;
  selectPage(name);
  setNavOpen(false);
  if (location.hash !== '#' + name) {
    try { history[opts.replace ? 'replaceState' : 'pushState'](null, '', '#' + name); } catch (_) { /* sandboxed */ }
  }
  if (switching) window.scrollTo(0, 0);
  if (name === 'data') loadAgentConfig();
  if (name === 'health') loadHealth();
  if (typeof onPageShown === 'function') onPageShown(name);
  try { localStorage.setItem('signalith.page', name); } catch (_) { /* storage may be blocked */ }
}

function pageFromHash() {
  const name = decodeURIComponent(location.hash.slice(1));
  return name && $('page-' + name) ? name : null;
}
const followHash = () => {
  const name = pageFromHash();
  if (name && name !== currentPage) showPage(name, { replace: true });
};
window.addEventListener('hashchange', followHash);
window.addEventListener('popstate', followHash);

// Links to pages (nav items, the logo, the health card) switch in place.
document.addEventListener('click', (ev) => {
  const link = ev.target.closest('a[data-page]');
  if (!link || ev.button !== 0 || ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.altKey) return;
  ev.preventDefault();
  showPage(link.dataset.page);
});

// ---------- app shell: phone drawer ----------
function setNavOpen(open) {
  appEl.toggleAttribute('data-nav-open', open);
  $('nav-toggle').setAttribute('aria-expanded', String(open));
  syncDrawer();
}
// Off screen, the closed drawer must not take keyboard focus; while it is
// open, the page behind the scrim must not either.
const mainEl = document.querySelector('.main');
function syncDrawer() {
  const open = appEl.hasAttribute('data-nav-open');
  $('sidebar').inert = narrow.matches && !open;
  mainEl.inert = narrow.matches && open;
}
narrow.addEventListener('change', () => { if (!narrow.matches) setNavOpen(false); syncDrawer(); });
syncDrawer();
$('nav-toggle').addEventListener('click', () => {
  setNavOpen(true);
  const here = document.querySelector('.nav__item[aria-current="page"]');
  (here || $('jump')).focus();
});
document.querySelectorAll('[data-nav-close]').forEach((b) => b.addEventListener('click', () => {
  setNavOpen(false);
  $('nav-toggle').focus();
}));
// The scrim sits behind the drawer and behind slide-over inspectors
// (.app[data-inspect]); clicking it closes both.
$('scrim').addEventListener('click', () => {
  setNavOpen(false);
  appEl.removeAttribute('data-inspect');
});

// ---------- app shell: page jumper ----------
// Typing in the sidebar box filters the nav; Enter opens the first match.
// Ctrl+K (Cmd+K on a Mac), or / when not typing, focuses it.
const JUMP_WORDS = {
  dashboards: 'home overview posture charts', findings: 'alerts incidents queue triage', cases: 'cases investigations',
  risk: 'risk scores', search: 'query events logs hunt', intel: 'threat intel ioc indicators feeds',
  detections: 'rules sigma alerts', coverage: 'mitre attack matrix techniques tactics', assets: 'hosts users identities cmdb priority',
  data: 'ingest agents fluent bit sources onboarding', health: 'status opensearch ingest', help: 'help syntax language commands',
};
const jump = $('jump');
$('jump-key').textContent = /Mac|iPhone|iPad/.test(navigator.platform) ? '\u2318K' : 'Ctrl K';

function jumpMatches() {
  const q = jump.value.trim().toLowerCase();
  const hits = [];
  document.querySelectorAll('#sidebar .nav__item[data-page]').forEach((a) => {
    const words = [a.textContent, a.dataset.page, JUMP_WORDS[a.dataset.page] || ''].join(' ').toLowerCase();
    const hit = !q || words.includes(q);
    a.classList.toggle('hidden', !hit);
    if (hit) hits.push(a);
  });
  document.querySelectorAll('#sidebar .nav__group').forEach((g) => g.classList.toggle('hidden', !g.querySelector('.nav__item:not(.hidden)')));
  $('jump-empty').classList.toggle('hidden', hits.length > 0);
  return hits;
}
function clearJump() {
  jump.value = '';
  jumpMatches();
}
jump.addEventListener('input', jumpMatches);
jump.addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') {
    ev.preventDefault();
    const first = jumpMatches()[0];
    if (first) {
      clearJump();
      jump.blur();
      showPage(first.dataset.page);
    }
  } else if (ev.key === 'ArrowDown') {
    const first = jumpMatches()[0];
    if (first) { ev.preventDefault(); first.focus(); }
  } else if (ev.key === 'Escape') {
    ev.stopPropagation();
    if (jump.value) clearJump(); else jump.blur();
  }
});
jump.addEventListener('blur', () => { setTimeout(() => { if (document.activeElement !== jump && !$('sidebar').contains(document.activeElement)) clearJump(); }, 150); });

function focusJump() {
  if (narrow.matches) setNavOpen(true);
  jump.focus();
  jump.select();
}
const isTyping = (t) => !!(t && t.closest && t.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"])'));

// ---------- app shell: theme ----------
// The saved choice lives under signalith.theme (see assets/theme.js);
// no saved choice follows the system setting.
function setTheme(t) {
  const root = document.documentElement;
  if (t) root.dataset.theme = t; else delete root.dataset.theme;
  try {
    if (t) localStorage.setItem('signalith.theme', t); else localStorage.removeItem('signalith.theme');
  } catch (_) { /* storage may be blocked */ }
  syncThemeButtons();
}
function syncThemeButtons() {
  const t = document.documentElement.dataset.theme || '';
  document.querySelectorAll('[data-set-theme]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.setTheme === t)));
}
const prefersDark = matchMedia('(prefers-color-scheme: dark)');
document.querySelectorAll('[data-theme-toggle]').forEach((b) => b.addEventListener('click', () => {
  const t = document.documentElement.dataset.theme;
  setTheme((t ? t === 'dark' : prefersDark.matches) ? 'light' : 'dark');
}));
document.querySelectorAll('[data-set-theme]').forEach((b) => b.addEventListener('click', () => setTheme(b.dataset.setTheme)));
syncThemeButtons();

// ---------- app shell: menus and keys ----------
// details.menu closes on a click outside it and on Esc.
document.addEventListener('click', (ev) => {
  document.querySelectorAll('details.menu[open]').forEach((d) => { if (!d.contains(ev.target)) d.removeAttribute('open'); });
});
document.addEventListener('keydown', (ev) => {
  if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && ev.key.toLowerCase() === 'k') {
    ev.preventDefault();
    focusJump();
    return;
  }
  if (ev.key === '/' && !ev.ctrlKey && !ev.metaKey && !ev.altKey && !isTyping(ev.target) && !document.querySelector('dialog[open]')) {
    ev.preventDefault();
    focusJump();
    return;
  }
  if (ev.key !== 'Escape' || ev.defaultPrevented) return;
  const menu = document.querySelector('details.menu[open]');
  if (menu) {
    menu.removeAttribute('open');
    menu.querySelector('summary').focus();
  } else if (appEl.hasAttribute('data-nav-open')) {
    setNavOpen(false);
    $('nav-toggle').focus();
  } else if (appEl.hasAttribute('data-inspect')) {
    appEl.removeAttribute('data-inspect');
  }
});

// ---------- app shell: user menu ----------
api('api/me').then((m) => {
  const name = m.user || '';
  const initial = (name.replace(/^[^a-z0-9]+/i, '').charAt(0) || '?').toUpperCase();
  $('user-avatar').textContent = initial;
  $('user-avatar-lg').textContent = initial;
  $('user-name').textContent = name;
  $('user-menu-name').textContent = name;
  // A browser that signed in with HTTP Basic auth keeps sending the
  // password, so signing out would not stick.
  const basic = m.auth === 'basic';
  $('sign-out').classList.toggle('hidden', basic);
  $('basic-note').classList.toggle('hidden', !basic);
}).catch(() => {});
$('sign-out').addEventListener('click', async () => {
  $('sign-out').disabled = true;
  try { await fetch('api/logout', { method: 'POST' }); } catch (_) { /* the session ends when it expires */ }
  location.replace('login?signedout');
});

// ---------- app shell: sidebar health ----------
// One calm line about OpenSearch and when the last event arrived; the
// dot turns amber or red when something needs a look on the Health page.
async function refreshHealthCard() {
  if (document.hidden) return;
  let h;
  try { h = await api('api/health'); } catch (_) { return; }
  const os = h.opensearch || {};
  const ing = h.ingest || {};
  const warnings = h.warnings || [];
  const failed = ing.failed || 0;
  // Yellow is normal on a single node, so only red, unreachable, failed
  // events or config warnings change the card.
  let state = '';
  let title = 'Healthy';
  if (!os.status || os.status === 'red' || os.status === 'unreachable') {
    state = 'down';
    title = 'OpenSearch ' + (os.status || 'unknown');
  } else if (failed > 0 || warnings.length) {
    state = 'warn';
    title = 'Needs attention';
  }
  const pulse = $('health-pulse');
  if (state) pulse.dataset.state = state; else delete pulse.dataset.state;
  $('health-title').textContent = title;
  const meta = [ing.last_seen ? 'Last event ' + ago(ing.last_seen) : 'No events since start'];
  if (failed) meta.push(failed.toLocaleString() + ' failed');
  $('health-meta').textContent = meta.join(' · ');
  const card = $('health-card');
  card.title = ['OpenSearch ' + (os.status || 'unknown'), os.error, ...warnings].filter(Boolean).join('\n');
  card.setAttribute('aria-label', `Health: ${title}, OpenSearch ${os.status || 'unknown'}, ${meta.join(', ')}`);
  card.classList.remove('hidden');
  if (h.version) $('user-menu-meta').textContent = 'Signalith ' + h.version;
}
refreshHealthCard();
setInterval(refreshHealthCard, 30000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshHealthCard(); });

// The first page: the URL hash, else the last page used, else Search.
// Shown now so nothing flashes; its data loads once every script is in.
let firstPage = pageFromHash();
try { firstPage = firstPage || localStorage.getItem('signalith.page'); } catch (_) { /* ignore */ }
if (!firstPage || !$('page-' + firstPage)) firstPage = 'search';
selectPage(firstPage);
document.addEventListener('DOMContentLoaded', () => showPage(firstPage, { replace: true }));

// ---------- query text helpers ----------
// splitPipes returns [search, rest] split at the first | outside quotes.
function splitPipes(q) {
  let inQ = false;
  for (let i = 0; i < q.length; i++) {
    const c = q[i];
    if (c === '\\' && inQ) { i++; continue; }
    if (c === '"') inQ = !inQ;
    if (c === '|' && !inQ) return [q.slice(0, i), q.slice(i)];
  }
  return [q, ''];
}
// pipeSegments splits a query at every | outside quotes: the search, then
// one segment per command.
function pipeSegments(q) {
  const out = [];
  let inQ = false;
  let start = 0;
  for (let i = 0; i < q.length; i++) {
    const c = q[i];
    if (c === '\\' && inQ) { i++; continue; }
    if (c === '"') inQ = !inQ;
    if (c === '|' && !inQ) { out.push(q.slice(start, i)); start = i + 1; }
  }
  out.push(q.slice(start));
  return out;
}
const commandOf = (seg) => ((seg || '').trim().match(/^[a-z_]+/i) || [''])[0].toLowerCase();
// eventsPart returns the part of a query that picks the events a stats,
// top or timechart command summarises, or null when nothing summarises them.
function eventsPart(q) {
  const segs = pipeSegments(q);
  const i = segs.findIndex((s, n) => n > 0 && ['stats', 'timechart', 'top'].includes(commandOf(s)));
  return i < 0 ? null : segs.slice(0, i).map((s) => s.trim()).join('\n| ') || '*';
}
function quoteValue(v) {
  v = String(v);
  return /^[^\s|()=!<>,"]+$/.test(v) && !/^(AND|OR|NOT|IN)$/i.test(v) ? v : '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}
function addSearchTerm(term) {
  const [search, rest] = splitPipes($('query').value);
  let s = search.trim();
  if (s === '*' || s === '') s = term; else s = s + ' ' + term;
  setQuery(s + (rest ? '\n' + rest.trim() : ''));
  runSearch();
}
function currentDatamodel() {
  const m = splitPipes($('query').value)[0].match(/datamodel\s*=\s*"?([\w-]+)"?/i);
  return m ? m[1] : '';
}
const isMac = /Mac|iPhone|iPad/.test(navigator.platform);

// ---------- query colouring ----------
// The query box is a textarea over a coloured copy of its text
// (#query-hl), so the analyst types plain text and still sees commands,
// functions, keywords and values apart. The Query guide uses the same
// colouring for its examples.
const lang = { commands: ['stats', 'timechart', 'top', 'where', 'sort', 'head', 'table', 'rename', 'enrich', 'threatmatch', 'intel'], functions: ['count', 'dc', 'sum', 'avg', 'min', 'max'] };
const QL_KEYWORDS = new Set(['and', 'or', 'not', 'in', 'as', 'by', 'over']);
const QL_FUNCS = new Set(lang.functions);
const QL_KEYS = new Set(['datamodel', 'index', 'earliest', 'latest']);

// tokenizeQuery splits query text into [text, class] pieces.
function tokenizeQuery(text) {
  const toks = [];
  const n = text.length;
  let i = 0;
  let cmd = '';
  let afterPipe = false;
  let afterOp = false;
  while (i < n) {
    const c = text[i];
    let j = i + 1;
    let cls = '';
    let op = false;
    if (c === '"') {
      while (j < n && text[j] !== '"') { if (text[j] === '\\') j++; j++; }
      j = Math.min(n, j + 1);
      cls = 'tok-str';
    } else if (c === '|') {
      cls = 'tok-pipe';
      afterPipe = true;
    } else if (/\s/.test(c)) {
      while (j < n && /\s/.test(text[j])) j++;
      toks.push([text.slice(i, j), '']);
      i = j;
      continue;
    } else if ('=!<>'.includes(c)) {
      while (j < n && '=<>'.includes(text[j])) j++;
      op = true;
    } else if (!'(),'.includes(c)) {
      while (j < n && !/[\s|()=!<>,"]/.test(text[j])) j++;
      const w = text.slice(i, j);
      const lw = w.toLowerCase();
      const next = (text.slice(j).match(/^\s*(\S)/) || [])[1];
      if (afterPipe) { cls = 'tok-cmd'; cmd = lw; } else if (QL_KEYWORDS.has(lw) && (cmd || w === w.toUpperCase())) cls = 'tok-kw';
      else if (QL_FUNCS.has(lw) && (next === '(' || (lw === 'count' && (cmd === 'stats' || cmd === 'timechart')))) cls = 'tok-fn';
      else if (!cmd && QL_KEYS.has(lw) && next === '=') cls = 'tok-cmd';
      else if (afterOp) cls = 'tok-str';
      afterPipe = false;
    }
    afterOp = op;
    toks.push([text.slice(i, j), cls]);
    i = j;
  }
  return toks;
}

// renderQuery fills box with coloured query text. opts.lines draws one
// .ln number and one .src span per logical line (the .editor grid), so
// wrapped lines stay next to their number. opts.errorAt marks the token at
// that character offset.
function renderQuery(box, text, opts = {}) {
  const toks = tokenizeQuery(text);
  let mark = -1;
  if (typeof opts.errorAt === 'number') {
    let pos = 0;
    mark = toks.findIndex(([t, cls]) => { pos += t.length; return pos > opts.errorAt && (cls || t.trim()); });
  }
  const lines = [[]];
  toks.forEach(([t, cls], k) => {
    const c = k === mark ? (cls + ' tok-err').trim() : cls;
    t.split('\n').forEach((part, p) => {
      if (p > 0) lines.push([]);
      if (part) lines[lines.length - 1].push(c ? el('span', { class: c }, part) : document.createTextNode(part));
    });
  });
  if (typeof opts.errorAt === 'number' && mark < 0) lines[lines.length - 1].push(el('span', { class: 'tok-err-end' }));
  if (!opts.lines) {
    box.replaceChildren(...lines.flatMap((l, k) => (k ? ['\n', ...l] : l)));
    return;
  }
  box.replaceChildren(...lines.flatMap((l, k) => [el('span', { class: 'ln', 'aria-hidden': 'true' }, String(k + 1)), el('span', { class: 'src' }, ...l)]));
}

const queryBox = $('query');
let queryErrorAt = null;
function renderEditor() {
  renderQuery($('query-hl'), queryBox.value, { lines: true, errorAt: queryErrorAt });
}
// A click on the line numbers still puts the cursor in the query.
$('editor').addEventListener('mousedown', (ev) => {
  if (ev.target !== queryBox && !ev.target.closest('#suggest')) { ev.preventDefault(); queryBox.focus(); }
});

// ---------- state ----------
let fields = [];
let fieldsFor = null;
let syncingBuilder = false;

function setQuery(text, fromBuilder) {
  queryBox.value = text;
  clearQueryError();
  hideExplanation();
  if (!fromBuilder) parseIntoBuilder();
  saveDraft();
}
function saveDraft() {
  try { localStorage.setItem('signalith.query', queryBox.value); } catch (_) { /* ignore */ }
}

// ---------- fields rail ----------
// Fields seen in the stored data come first; fields the data model knows
// but the data has not shown yet fold away underneath.
const FTYPE = { string: ['a', 'text'], text: ['¶', 'free text'], number: ['#', 'number'], ip: ['ip', 'IP address'], time: ['t', 'time'] };
const fieldValuesBox = $('field-values');
let openField = null;
let showUnseen = false;

async function loadFields() {
  const dm = currentDatamodel();
  if (dm === fieldsFor) return;
  fieldsFor = dm;
  openField = null;
  try {
    fields = await api('api/fields?datamodel=' + encodeURIComponent(dm));
  } catch (e) {
    fields = [];
  }
  renderFields();
  $('field-names').replaceChildren(...fields.map((f) => el('option', { value: f.name })));
}

function fieldRow(f) {
  const [glyph, label] = FTYPE[f.type] || [String(f.type || '?').charAt(0), f.type];
  const row = el('button', {
    type: 'button', class: 'field-row' + (f.indexed ? '' : ' is-unseen'), 'aria-expanded': String(openField === f.name),
    title: (f.description || f.name) + (f.indexed ? '' : ' (not seen in your data yet)'),
  }, el('span', { class: 'ftype', 'aria-hidden': 'true' }, glyph), el('span', { class: 'name' }, f.name), el('span', { class: 'sr-only' }, ', ' + label));
  row.dataset.field = f.name;
  row.addEventListener('click', () => toggleField(f));
  return row;
}

function renderFields() {
  const filter = $('field-filter').value.trim().toLowerCase();
  const shown = fields.filter((f) => !filter || f.name.toLowerCase().includes(filter));
  const seen = shown.filter((f) => f.indexed);
  const unseen = shown.filter((f) => !f.indexed);
  $('field-count').textContent = fields.length;
  $('field-count').classList.toggle('hidden', !fields.length);
  const groups = [];
  if (seen.length) groups.push(el('div', { class: 'fields__group' }, el('div', { class: 'section-title' }, 'In your data'), ...seen.map(fieldRow)));
  if (unseen.length && !seen.length) {
    groups.push(el('div', { class: 'fields__group' }, el('div', { class: 'section-title' }, fields.some((f) => f.indexed) ? 'Not seen yet' : 'Data model fields'), ...unseen.map(fieldRow)));
  } else if (unseen.length) {
    const more = el('details', { class: 'fields__group fields__more' },
      el('summary', { class: 'section-title' }, 'Not seen yet', el('span', { class: 'count' }, String(unseen.length)), icon('chevron-down', 'icon--xs chev')),
      ...unseen.map(fieldRow));
    more.open = showUnseen || !!filter || unseen.some((f) => f.name === openField);
    more.addEventListener('toggle', () => { if (!filter) showUnseen = more.open; });
    groups.push(more);
  }
  if (!shown.length) groups.push(el('p', { class: 'fields__empty' }, filter ? 'No field matches.' : 'No fields to show.'));
  fieldValuesBox.remove();
  $('field-list').replaceChildren(...groups);
  placeFieldValues();
}
$('field-filter').addEventListener('input', renderFields);

// placeFieldValues puts the values box under the open field's row.
function placeFieldValues() {
  const row = openField && [...document.querySelectorAll('#field-list .field-row')].find((r) => r.dataset.field === openField);
  if (row) row.after(fieldValuesBox); else $('field-list').after(fieldValuesBox);
  fieldValuesBox.classList.toggle('hidden', !row);
}

async function toggleField(f) {
  openField = openField === f.name ? null : f.name;
  document.querySelectorAll('#field-list .field-row').forEach((r) => r.setAttribute('aria-expanded', String(r.dataset.field === openField)));
  placeFieldValues();
  if (!openField) return;
  const box = fieldValuesBox;
  const desc = f.description ? el('p', { class: 'fv-desc' }, f.description) : null;
  box.setAttribute('aria-busy', 'true');
  box.replaceChildren(...[desc, ...[72, 54, 38].map((w) => el('div', { class: 'fv fv--skeleton' }, el('span', { class: 'skeleton', style: `width:${w}%` })))].filter(Boolean));
  try {
    const q = new URLSearchParams({ field: f.name, datamodel: currentDatamodel(), earliest: $('time').value === '0' ? '' : $('time').value });
    const rows = await api('api/fields/values?' + q);
    if (openField !== f.name) return;
    const total = rows.reduce((s, r) => s + (Number(r.count) || 0), 0) || 1;
    const items = rows.map((r) => {
      const v = r[f.name];
      const pct = typeof r.percent === 'number' ? r.percent : 100 * (Number(r.count) || 0) / total;
      return el('button', { type: 'button', class: 'fv', title: `Filter on ${f.name}=${fmtValue(v)} (${Number(r.count).toLocaleString()} events)`, onclick: () => addSearchTerm(f.name + '=' + quoteValue(v)) },
        el('code', {}, fmtValue(v)), el('span', { class: 'num' }, (pct < 1 && pct > 0 ? '<1' : Math.round(pct)) + '%'),
        el('span', { class: 'bar' }, el('span', { style: `--w:${Math.max(1, Math.min(100, pct)).toFixed(1)}%` })));
    });
    box.replaceChildren(...[desc,
      ...(items.length ? items : [el('p', { class: 'fv-desc' }, 'No values in this time range.')]),
      el('button', { type: 'button', class: 'link-btn fv-more', onclick: () => { setQuery(splitPipes(queryBox.value)[0].trim() + '\n| top limit=20 ' + f.name); runSearch(); } }, 'Top values as a table')].filter(Boolean));
  } catch (e) {
    if (openField !== f.name) return;
    box.replaceChildren(...[desc, el('p', { class: 'field-error' }, icon('circle-alert'), e.message)].filter(Boolean));
  } finally {
    box.removeAttribute('aria-busy');
  }
}

// ---------- autocomplete ----------
let suggestions = [];
let suggestIndex = 0;

function currentWord() {
  const ta = queryBox;
  const upto = ta.value.slice(0, ta.selectionStart);
  const m = upto.match(/[^\s|()=!<>,"]*$/);
  return { word: m[0], start: ta.selectionStart - m[0].length, before: upto.slice(0, ta.selectionStart - m[0].length) };
}
function updateSuggestions() {
  const { word, before } = currentWord();
  const trimmed = before.trimEnd();
  let items = [];
  if (/\|\s*$/.test(before)) {
    items = lang.commands.map((c) => ({ text: c + ' ', kind: 'command' }));
  } else if (/(stats|timechart|,)\s*$/.test(trimmed) && /\|[^|]*(stats|timechart)[^|]*$/.test(before) && !/\bby\b[^|]*$/.test(before)) {
    items = lang.functions.map((f) => ({ text: f === 'count' ? 'count' : f + '(', kind: 'function' }));
  } else if (word.length > 0 && !/[=<>]\s*$/.test(before)) {
    const inSearch = !before.includes('|');
    items = fields.map((f) => ({ text: f.name + (inSearch ? '=' : ''), kind: f.type }));
    if (inSearch) items.push({ text: 'datamodel=', kind: 'source' }, { text: 'earliest=', kind: 'time' });
  } else if (/datamodel=$/i.test(before)) {
    items = ['Authentication', 'Endpoint', 'Network_Traffic', 'Change', 'Other'].map((m) => ({ text: m + ' ', kind: 'model' }));
  }
  const w = word.toLowerCase();
  suggestions = items.filter((i) => i.text.toLowerCase().startsWith(w) && i.text.toLowerCase() !== w).slice(0, 8);
  suggestIndex = 0;
  renderSuggestions();
}
function renderSuggestions() {
  const ul = $('suggest');
  if (!suggestions.length) {
    ul.classList.add('hidden');
    queryBox.removeAttribute('aria-activedescendant');
    return;
  }
  ul.replaceChildren(...suggestions.map((s, i) => el('li', {
    id: 'suggest-' + i, role: 'option', 'aria-selected': String(i === suggestIndex),
    onmousedown: (ev) => { ev.preventDefault(); acceptSuggestion(i); },
  }, el('span', {}, s.text.trim()), el('span', { class: 'kind' }, s.kind))));
  queryBox.setAttribute('aria-activedescendant', 'suggest-' + suggestIndex);
  ul.classList.remove('hidden');
  placeSuggestions();
}
// placeSuggestions opens the list under the line being typed, near the
// cursor.
const measureCtx = document.createElement('canvas').getContext('2d');
function placeSuggestions() {
  const ul = $('suggest');
  const text = queryBox.value.slice(0, queryBox.selectionStart);
  const line = (text.match(/\n/g) || []).length;
  const src = $('query-hl').children[line * 2 + 1];
  if (!src) return;
  measureCtx.font = getComputedStyle(queryBox).font;
  const charWidth = measureCtx.measureText('x').width || 7.8;
  const col = text.length - text.lastIndexOf('\n') - 1;
  const usable = Math.max(1, src.clientWidth - 30);
  const perRow = Math.max(1, Math.floor(usable / charWidth));
  const row = Math.floor(col / perRow);
  const left = src.offsetLeft + 14 + (col % perRow) * charWidth - 8;
  const editor = $('editor');
  ul.style.top = (src.offsetTop + (row + 1) * 22 + 4) + 'px';
  ul.style.left = Math.max(8, Math.min(left, editor.clientWidth - ul.offsetWidth - 8)) + 'px';
}
function acceptSuggestion(i) {
  const s = suggestions[i];
  const ta = queryBox;
  const { start } = currentWord();
  const end = ta.selectionStart;
  ta.value = ta.value.slice(0, start) + s.text + ta.value.slice(end);
  ta.selectionStart = ta.selectionEnd = start + s.text.length;
  suggestions = [];
  renderSuggestions();
  ta.focus();
  onQueryInput();
}
queryBox.addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); suggestions = []; renderSuggestions(); runSearch(); return; }
  if (!suggestions.length) return;
  if (ev.key === 'ArrowDown') { ev.preventDefault(); suggestIndex = (suggestIndex + 1) % suggestions.length; renderSuggestions(); }
  else if (ev.key === 'ArrowUp') { ev.preventDefault(); suggestIndex = (suggestIndex + suggestions.length - 1) % suggestions.length; renderSuggestions(); }
  else if (ev.key === 'Tab' || ev.key === 'Enter') { ev.preventDefault(); acceptSuggestion(suggestIndex); }
  else if (ev.key === 'Escape') { ev.preventDefault(); suggestions = []; renderSuggestions(); }
});
queryBox.addEventListener('blur', () => setTimeout(() => { suggestions = []; renderSuggestions(); }, 100));

let parseTimer = null;
function onQueryInput() {
  clearQueryError();
  hideExplanation();
  saveDraft();
  clearTimeout(parseTimer);
  parseTimer = setTimeout(() => { parseIntoBuilder(); loadFields(); }, 300);
}
queryBox.addEventListener('input', () => { onQueryInput(); updateSuggestions(); });

// ---------- builder ----------
function filterRow(f = { field: '', op: '=', value: '' }) {
  const ops = ['=', '!=', '>', '>=', '<', '<='];
  const row = el('div', { class: 'b-filter-row' },
    el('input', { type: 'text', list: 'field-names', placeholder: 'Field', value: f.field, class: 'input bf-field', 'aria-label': 'Field' }),
    el('select', { class: 'select bf-op', 'aria-label': 'Comparison' }, ...ops.map((o) => {
      const opt = el('option', { value: o }, o);
      if (o === f.op) opt.selected = true;
      return opt;
    })),
    el('input', { type: 'text', placeholder: 'Value, * as a wildcard', value: f.value, class: 'input bf-value', 'aria-label': 'Value' }),
    el('button', {
      type: 'button', class: 'btn btn--ghost btn--icon btn--sm', title: 'Remove condition', 'aria-label': 'Remove condition',
      onclick: () => { row.remove(); builderChanged(); },
    }, icon('x')));
  row.addEventListener('input', builderChanged);
  row.addEventListener('change', builderChanged);
  return row;
}
$('b-add-filter').addEventListener('click', () => {
  const row = filterRow();
  $('b-filter-rows').append(row);
  row.querySelector('input').focus();
});

function readSpec() {
  const mode = $('b-mode').value;
  const spec = {
    datamodel: $('b-datamodel').value,
    text: $('b-text').value.trim(),
    filters: [...document.querySelectorAll('.b-filter-row')].map((r) => ({
      field: r.querySelector('.bf-field').value.trim(),
      op: r.querySelector('.bf-op').value,
      value: r.querySelector('.bf-value').value,
    })).filter((f) => f.field),
    mode,
    sort: $('b-sort').value.trim(),
    limit: parseInt($('b-limit').value, 10) || 0,
  };
  if (mode !== 'events') {
    spec.agg_func = $('b-agg').value;
    spec.agg_field = $('b-agg-field').value.trim();
    spec.by = $('b-by').value.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return spec;
}
function updateBuilderVisibility() {
  const mode = $('b-mode').value;
  $('b-agg-group').classList.toggle('hidden', mode === 'events');
  $('b-agg-field-wrap').classList.toggle('hidden', $('b-agg').value === 'count');
}
let buildTimer = null;
function builderChanged() {
  updateBuilderVisibility();
  if (syncingBuilder) return;
  clearTimeout(buildTimer);
  buildTimer = setTimeout(async () => {
    try {
      const { query } = await api('api/build', readSpec());
      setQuery(query, true);
      $('builder-note').textContent = '';
      loadFields();
    } catch (e) { /* the text editor keeps working */ }
  }, 150);
}
['b-datamodel', 'b-text', 'b-mode', 'b-agg', 'b-agg-field', 'b-by', 'b-sort', 'b-limit'].forEach((id) => {
  $(id).addEventListener('input', builderChanged);
  $(id).addEventListener('change', builderChanged);
});
// The builder stays as the analyst left it.
$('builder').addEventListener('toggle', () => {
  try { localStorage.setItem('signalith.builder', $('builder').open ? 'open' : ''); } catch (_) { /* ignore */ }
});

async function parseIntoBuilder() {
  const text = queryBox.value.trim();
  if (!text) return;
  try {
    const res = await api('api/parse', { query: text });
    if (queryBox.value.trim() !== text) return;
    clearQueryError();
    if (!res.builder_ok) {
      $('builder-note').textContent = 'The builder cannot show this query. Edit the text instead.';
      return;
    }
    $('builder-note').textContent = '';
    const s = res.spec;
    syncingBuilder = true;
    $('b-datamodel').value = s.datamodel || '';
    $('b-text').value = s.text || '';
    $('b-filter-rows').replaceChildren(...(s.filters || []).map(filterRow));
    $('b-mode').value = s.mode || 'events';
    $('b-agg').value = s.agg_func || 'count';
    $('b-agg-field').value = s.agg_field || '';
    $('b-by').value = (s.by || []).join(', ');
    $('b-sort').value = s.sort || '';
    $('b-limit').value = s.limit || '';
    updateBuilderVisibility();
    syncingBuilder = false;
  } catch (e) {
    // While typing, only mark the spot; Search shows the whole message.
    if (queryBox.value.trim() === text) markQueryError(e);
  }
}

// ---------- query errors ----------
// markQueryError underlines the spot the server pointed at;
// showQueryError also explains it under the query box.
function markQueryError(e) {
  queryErrorAt = typeof e.pos === 'number' ? e.pos : null;
  queryBox.setAttribute('aria-invalid', 'true');
  renderEditor();
}
function showQueryError(e) {
  markQueryError(e);
  const box = $('query-error');
  const body = [el('b', {}, e.message)];
  if (typeof e.pos === 'number') {
    const text = queryBox.value;
    const lineStart = text.lastIndexOf('\n', e.pos - 1) + 1;
    let lineEnd = text.indexOf('\n', e.pos);
    if (lineEnd < 0) lineEnd = text.length;
    // Keep the caret in view on long lines: show only the end before it.
    const from = e.pos - lineStart > 28 ? e.pos - 24 : lineStart;
    const lead = from > lineStart ? '…' : '';
    body.push(el('pre', {}, lead + text.slice(from, lineEnd) + '\n' + ' '.repeat(Math.max(0, lead.length + e.pos - from)) + '^'));
  }
  box.replaceChildren(icon('circle-alert'), el('div', {}, ...body));
  box.classList.remove('hidden');
}
function clearQueryError() {
  queryErrorAt = null;
  queryBox.removeAttribute('aria-invalid');
  $('query-error').classList.add('hidden');
  renderEditor();
}

// ---------- running searches ----------
// One results card: tabs for Statistics, Events and Visualize (only the
// ones the result has), an events-over-time histogram and the table.
let searchSeq = 0;
let lastSearch = null; // { query, earliest, res, tab, events, eventsQuery }
const timeEarliest = () => ($('time').value === '0' ? '' : $('time').value);

async function runSearch() {
  const query = queryBox.value.trim() || '*';
  const earliest = timeEarliest();
  const seq = ++searchSeq;
  $('query-error').classList.add('hidden');
  hideExplanation();
  hideCellMenu();
  $('starter').classList.add('hidden');
  showResultsLoading();
  try {
    const res = await api('api/search', { query, earliest });
    if (seq !== searchSeq) return;
    lastSearch = { query, earliest, res, events: res.kind === 'events' ? res : null, eventsQuery: res.kind === 'events' ? null : eventsPart(query) };
    lastSearch.tab = res.kind === 'timechart' && (res.rows || []).length ? 'viz' : res.kind === 'events' ? 'events' : 'stats';
    renderResult();
    // The histogram is a second, smaller search; run it once the query is
    // known to be valid and to match something.
    if (res.matched || (res.rows || []).length) loadHistogram(seq, query, earliest);
    else hideHistogram();
  } catch (e) {
    if (seq !== searchSeq) return;
    lastSearch = null;
    hideHistogram();
    if (typeof e.pos === 'number') {
      showQueryError(e);
      $('results-card').classList.add('hidden');
    } else {
      showResultsError(e);
    }
  } finally {
    if (seq === searchSeq) setSearching(false);
  }
}
$('run').addEventListener('click', runSearch);
$('time').addEventListener('change', () => { try { localStorage.setItem('signalith.time', $('time').value); } catch (_) { /* ignore */ } runSearch(); });

function setSearching(on) {
  $('run').disabled = on;
  if (on) $('results-card').setAttribute('aria-busy', 'true');
  else $('results-card').removeAttribute('aria-busy');
  if (on) $('histogram').classList.add('is-loading');
}

// skeletonTable keeps the card's shape while a search runs.
function skeletonTable(cols = 4, rows = 6) {
  const widths = [72, 48, 60, 36, 54, 42];
  return el('div', { class: 'table-wrap' }, el('table', { class: 'table', 'aria-busy': 'true', 'aria-label': 'Loading results' }, el('tbody', {},
    ...Array.from({ length: rows }, (_, r) => el('tr', {}, ...Array.from({ length: cols }, (__, c) => el('td', {},
      el('span', { class: 'skeleton', style: `width:${widths[(r + c * 2) % widths.length]}%` }))))))));
}

function showResultsLoading() {
  setSearching(true);
  const card = $('results-card');
  card.classList.remove('hidden');
  card.querySelector('.results-head').classList.remove('hidden');
  $('status').replaceChildren(el('span', {}, 'Searching…'));
  $('chart').classList.add('hidden');
  releaseCharts($('chart'));
  $('results').classList.remove('hidden');
  $('results').replaceChildren(skeletonTable());
}

// stateBox draws the .empty block used for no results and for errors.
function stateBox({ tone, iconName, title, text, action }) {
  const box = el('div', { class: 'empty' },
    el('span', { class: 'empty__icon' }, icon(iconName)), el('div', { class: 'empty__title' }, title),
    el('p', { class: 'empty__text' }, ...[].concat(text)),
    action ? el('div', { class: 'empty__actions' }, action) : null);
  if (tone) box.dataset.tone = tone;
  return box;
}
function retryButton(onclick) {
  return el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick }, icon('refresh-cw'), 'Try again');
}

function showResultsError(e) {
  $('result-tabs').replaceChildren();
  $('status').replaceChildren();
  $('results-card').querySelector('.results-head').classList.add('hidden');
  $('histogram').classList.add('hidden');
  $('chart').classList.add('hidden');
  $('results').classList.remove('hidden');
  $('results').replaceChildren(stateBox({ tone: 'danger', iconName: 'circle-alert', title: 'The search failed', text: e.message, action: retryButton(runSearch) }));
}

// searchRangeText says which time range a search covered, for messages.
function searchRangeText(query) {
  if (/\b(earliest|latest)\s*=/i.test(splitPipes(query)[0])) return 'in this time range';
  const opt = $('time').selectedOptions[0];
  return $('time').value === '0' ? 'at any time' : 'in the ' + opt.textContent.toLowerCase();
}
function noResults(query) {
  const opts = [...$('time').options];
  const next = /\b(earliest|latest)\s*=/i.test(splitPipes(query)[0]) ? null : opts[$('time').selectedIndex + 1];
  return stateBox({
    iconName: 'search', title: 'No matching events',
    text: ['Nothing matched ' + searchRangeText(query) + '. Try a longer range, or check on the ', el('a', { href: '#health', 'data-page': 'health' }, 'Health'), ' page that data is arriving.'],
    action: next ? el('button', {
      type: 'button', class: 'btn btn--secondary btn--sm',
      onclick: () => { $('time').value = next.value; $('time').dispatchEvent(new Event('change')); },
    }, 'Search ' + (next.value === '0' ? 'all time' : next.textContent.toLowerCase())) : null,
  });
}

// vizInfo says how a result can be charted: a timechart over time, or a
// table as bars of its first number column. Null when it cannot be.
function vizInfo(res) {
  const rows = res.rows || [];
  if (!rows.length) return null;
  if (res.kind === 'timechart') return { kind: 'time' };
  if (res.kind !== 'table') return null;
  const cols = res.columns || [];
  const value = cols.find((c) => c !== 'percent' && rows.every((r) => r[c] == null || typeof r[c] === 'number') && rows.some((r) => typeof r[c] === 'number'));
  if (!value) return null;
  const labels = cols.filter((c) => c !== value && c !== 'percent' && !rows.every((r) => typeof r[c] === 'number'));
  return { kind: 'bars', value, labels };
}

function renderResult() {
  const res = lastSearch.res;
  $('results-card').classList.remove('hidden');
  $('results-card').querySelector('.results-head').classList.remove('hidden');
  const n = res.matched || 0;
  const stats = [
    el('span', {}, el('b', {}, n.toLocaleString()), n === 1 ? ' event' : ' events', el('span', { class: 'hide-sm' }, ' matched')),
    el('span', { class: 'hide-sm', 'aria-hidden': 'true' }, '·'),
    el('span', { class: 'hide-sm' }, `${(res.took_ms || 0).toLocaleString()} ms`),
  ];
  if (res.truncated) stats.push(el('span', { class: 'badge badge--warning', title: 'The server stopped at its row limit, so some rows are missing. Narrow the search to see them all.' }, 'Truncated'));
  if ((res.rows || []).length) {
    stats.push(el('button', {
      type: 'button', class: 'btn btn--ghost btn--icon btn--sm', title: 'Download as CSV', 'aria-label': 'Download results as CSV', onclick: exportResults,
    }, icon('download')));
  }
  $('status').replaceChildren(...stats);
  renderTabs();
  showTab(lastSearch.tab);
}

function renderTabs() {
  const res = lastSearch.res;
  const tabs = [];
  if (res.kind !== 'events') tabs.push(['stats', 'Statistics', (res.rows || []).length]);
  if (res.kind === 'events' || lastSearch.eventsQuery) tabs.push(['events', 'Events', res.matched || 0]);
  if (vizInfo(res)) tabs.push(['viz', 'Visualize', null]);
  $('result-tabs').replaceChildren(...tabs.map(([id, label, count]) => el('button', {
    type: 'button', class: 'tab', role: 'tab', id: 'rtab-' + id, 'aria-selected': String(id === lastSearch.tab), tabindex: id === lastSearch.tab ? '0' : '-1',
    onclick: () => showTab(id),
  }, label, count == null ? null : el('span', { class: 'count' }, count.toLocaleString()))));
}
$('result-tabs').addEventListener('keydown', (ev) => {
  if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
  const tabs = [...$('result-tabs').children];
  const i = tabs.indexOf(document.activeElement);
  if (i < 0) return;
  const t = tabs[(i + (ev.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
  t.focus();
  t.click();
});

async function showTab(id) {
  const run = lastSearch;
  if (!run) return;
  run.tab = id;
  [...$('result-tabs').children].forEach((t) => {
    const on = t.id === 'rtab-' + id;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
  });
  const res = run.res;
  const chart = $('chart');
  const box = $('results');
  hideCellMenu();
  chart.setAttribute('aria-labelledby', 'rtab-' + id);
  box.setAttribute('aria-labelledby', 'rtab-' + id);
  if (id === 'viz') {
    box.classList.add('hidden');
    chart.classList.remove('hidden');
    const v = vizInfo(res);
    if (v.kind === 'time') {
      drawTimeChart(chart, res, { legend: true, label: 'Search results over time' });
    } else {
      drawBars(chart, res.rows.slice(0, 25).map((r) => ({
        label: v.labels.length ? v.labels.map((c) => fmtValue(r[c])).join(' · ') : v.value,
        value: Number(r[v.value]) || 0,
        filter: v.labels.length === 1 && r[v.labels[0]] != null ? v.labels[0] + '=' + quoteValue(r[v.labels[0]]) : null,
      })), v.value);
    }
    return;
  }
  releaseCharts(chart);
  chart.classList.add('hidden');
  box.classList.remove('hidden');
  if (id === 'stats') {
    renderTable(box, res, { kind: res.kind, sortable: true });
    return;
  }
  // Events: the result itself, or the events behind a summary, fetched
  // the first time the tab opens.
  if (run.events) {
    renderTable(box, run.events, { kind: 'events', sortable: res.kind === 'events', matched: res.matched });
    return;
  }
  box.replaceChildren(skeletonTable());
  try {
    run.events = await api('api/search', { query: run.eventsQuery, earliest: run.earliest });
  } catch (e) {
    if (lastSearch !== run || run.tab !== 'events') return;
    box.replaceChildren(stateBox({ tone: 'danger', iconName: 'circle-alert', title: 'Could not load the events', text: e.message, action: retryButton(() => showTab('events')) }));
    return;
  }
  if (lastSearch === run && run.tab === 'events') renderTable(box, run.events, { kind: 'events', sortable: false, matched: res.matched });
}

// Entity values read as chips, as everywhere else in Signalith.
const ENTITY_FIELDS = {
  user: 'user', src_user: 'user', dest_user: 'user', user_name: 'user', risk_object: null,
  host: 'host', dest_host: 'host', src_host: 'host', dvc: 'host',
  process_name: 'process', parent_process_name: 'process',
  file_name: 'file', file_path: 'file', domain: 'domain', url: 'domain', query: 'domain',
  hash: 'hash', file_hash: 'hash', md5: 'hash', sha1: 'hash', sha256: 'hash',
};
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]*:[0-9a-f:]+$/i;
function entityKind(col, v) {
  if (typeof v !== 'string' || !v || v.length > 80) return null;
  if (IP_RE.test(v)) return 'ip';
  if (ENTITY_FIELDS[col]) return ENTITY_FIELDS[col];
  const f = fields.find((x) => x.name === col);
  return f && f.type === 'ip' ? 'ip' : null;
}

// currentSort reads a trailing "| sort [-]field" so the header can show it.
function currentSort(q) {
  const m = q.match(/\n?\|\s*sort\s+(-?)([^\s|,]+)\s*$/);
  return m ? { col: m[2], desc: m[1] === '-' } : null;
}

// drawBars charts a summary as one row per value: label, a bar, the
// number. A row with a filter adds it to the search when clicked.
function drawBars(box, items, valueName) {
  const max = Math.max(...items.map((it) => it.value), 0) || 1;
  releaseCharts(box);
  box.replaceChildren(el('ol', { class: 'hbars', 'aria-label': 'Chart of ' + valueName }, ...items.map((it) => {
    const pct = Math.max(0.5, 100 * it.value / max).toFixed(1);
    const kids = [el('span', { class: 'hbar__label' }, it.label), el('span', { class: 'hbar__track', 'aria-hidden': 'true' }, el('span', { style: `--w:${pct}%` })), el('span', { class: 'hbar__value' }, fmtCompact(it.value))];
    const row = it.filter
      ? el('button', { type: 'button', class: 'hbar', title: `${it.label}: ${fmtValue(it.value)}. Click to filter on it.`, onclick: () => addSearchTerm(it.filter) }, ...kids)
      : el('div', { class: 'hbar', title: `${it.label}: ${fmtValue(it.value)}` }, ...kids);
    return el('li', {}, row);
  })));
}

// Events read best as a list: the time, then the raw text with the key
// fields under it. Columns added by | enrich follow the field they describe.
const EVENT_FIELDS = ['host', 'sourcetype', 'action', 'user', 'src', 'dest', 'process_name', 'signature'];
function renderEvents(box, res, opts) {
  const rows = res.rows || [];
  if (!rows.length) {
    box.replaceChildren(noResults(lastSearch.query));
    return;
  }
  const cols = res.columns || [];
  const enriched = (c) => cols.filter((x) => x.startsWith(c + '_') && /_(name|owner|priority|category|watchlist)$/.test(x));
  const keys = EVENT_FIELDS.filter((c) => cols.includes(c)).flatMap((c) => [c, ...enriched(c)]);
  const timeHead = el('th', { scope: 'col', class: 'time' });
  if (opts.sortable) {
    const sort = currentSort(lastSearch.query);
    const on = sort && sort.col === '_time';
    timeHead.setAttribute('aria-sort', on ? (sort.desc ? 'descending' : 'ascending') : 'none');
    timeHead.append(el('button', { type: 'button', class: 'th-sort', title: 'Sort by time', onclick: () => sortBy('_time') }, 'Time',
      icon(on ? (sort.desc ? 'arrow-down' : 'arrow-up') : 'arrow-up-down', on ? 'is-on' : '')));
  } else {
    timeHead.append('Time');
  }
  const body = rows.map((r) => {
    const d = new Date(r._time);
    const time = el('td', { class: 'time' });
    if (r._time != null) {
      time.append(...(isNaN(d) ? [fmtValue(r._time)] : [
        el('span', { class: 'ev-date' }, d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' })),
        el('span', { class: 'ev-clock' }, d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }))]));
      time.title = fmtTime(r._time);
      time.addEventListener('click', (ev) => showCellMenu(ev, '_time', r._time, 'events', r, opts.sortable));
    }
    const event = el('td', { class: 'event' });
    if (r._raw != null && r._raw !== '') {
      const raw = el('div', { class: 'ev-raw' }, fmtValue(r._raw));
      raw.addEventListener('click', (ev) => showCellMenu(ev, '_raw', r._raw, 'events', r));
      event.append(raw);
    }
    const chips = keys.filter((k) => r[k] != null && r[k] !== '').map((k) => {
      const v = fmtValue(r[k]);
      const b = el('button', { type: 'button', class: 'ev-field', title: `${k}=${v}` }, el('span', { class: 'ev-field__k' }, k + '='), el('span', { class: 'ev-field__v' }, v));
      b.addEventListener('click', (ev) => showCellMenu(ev, k, r[k], 'events', r, opts.sortable));
      return b;
    });
    if (chips.length) event.append(el('div', { class: 'ev-fields' }, ...chips));
    return el('tr', {}, time, event);
  });
  const kids = [el('div', { class: 'table-wrap' }, el('table', { class: 'table table--compact res-events' },
    el('thead', {}, el('tr', {}, timeHead, el('th', { scope: 'col' }, 'Event'))), el('tbody', {}, ...body)))];
  const matched = opts.matched || res.matched || 0;
  if (matched > rows.length) {
    kids.push(el('div', { class: 'table-foot' }, `Showing the first ${rows.length.toLocaleString()} of ${matched.toLocaleString()} matching events. Narrow the search, or add | head to choose how many.`));
  }
  box.replaceChildren(...kids);
}

function renderTable(box, res, opts) {
  releaseCharts($('chart'));
  if (opts.kind === 'events') {
    renderEvents(box, res, opts);
    return;
  }
  const rows = res.rows || [];
  const cols = res.columns || [];
  if (!rows.length) {
    box.replaceChildren(noResults(lastSearch.query));
    return;
  }
  const isNum = (c) => rows.every((r) => r[c] == null || typeof r[c] === 'number') && rows.some((r) => typeof r[c] === 'number');
  const numCols = new Set(cols.filter(isNum));
  // A short bar beside the first count of a summary table, so the big
  // values stand out.
  const barCol = opts.kind === 'table' && rows.length > 1 ? cols.find((c) => numCols.has(c) && c !== 'percent') : null;
  const barMax = barCol ? Math.max(...rows.map((r) => Number(r[barCol]) || 0)) || 1 : 1;
  const sort = opts.sortable ? currentSort(lastSearch.query) : null;
  const head = cols.map((c) => {
    const th = el('th', { scope: 'col' });
    if (numCols.has(c)) th.className = 'num';
    if (!opts.sortable) { th.append(c); return th; }
    const on = sort && sort.col === c;
    th.setAttribute('aria-sort', on ? (sort.desc ? 'descending' : 'ascending') : 'none');
    th.append(
      el('button', { type: 'button', class: 'th-sort', title: `Sort by ${c}`, onclick: () => sortBy(c) }, c,
        icon(on ? (sort.desc ? 'arrow-down' : 'arrow-up') : 'arrow-up-down', on ? 'is-on' : '')));
    return th;
  });
  const body = rows.map((r) => el('tr', {}, ...cols.map((c) => {
    const v = r[c];
    const td = el('td', { 'data-label': c });
    if (numCols.has(c)) td.className = 'num';
    if (c === '_raw') td.className = 'raw';
    if (c === '_time') td.className = 'time';
    td.addEventListener('click', (ev) => showCellMenu(ev, c, v, opts.kind, r));
    if (v == null || v === '') return td;
    const text = c === '_time' ? fmtTime(v) : fmtValue(v);
    const kind = entityKind(c, v);
    if (c === barCol) {
      td.append(el('div', { class: 'bar-cell' }, el('span', {}, text), el('span', { class: 'bar', 'aria-hidden': 'true' }, el('span', { style: `--w:${Math.max(1, 100 * (Number(v) || 0) / barMax).toFixed(1)}%` }))));
    } else if (kind) {
      td.append(el('span', { class: 'chip', 'data-kind': kind, title: text }, el('span', {}, text)));
    } else {
      td.append(text);
    }
    return td;
  })));
  const table = el('table', { class: 'table' + (cols.length > 3 ? ' res-stack' : '') },
    el('thead', {}, el('tr', {}, ...head)), el('tbody', {}, ...body));
  box.replaceChildren(el('div', { class: 'table-wrap' }, table));
}

function sortBy(col) {
  const q = queryBox.value.trim();
  const m = q.match(/\n?\|\s*sort\s+(-?)([^\s|]+)\s*$/);
  let desc = true;
  let base = q;
  if (m && m[2] === col) { desc = m[1] !== '-'; base = q.slice(0, m.index); }
  else if (m) base = q.slice(0, m.index);
  setQuery(base + '\n| sort ' + (desc ? '-' : '') + col);
  runSearch();
}

function fmtValue(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'number' && !Number.isInteger(v)) return v.toLocaleString(undefined, { maximumFractionDigits: 2 });
  if (Array.isArray(v)) return v.join(', ');
  return String(v);
}

function fmtTime(v) {
  const d = new Date(v);
  if (isNaN(d)) return fmtValue(v);
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ---------- export ----------
// exportResults downloads what the open tab shows as CSV. Cells that a
// spreadsheet would run as a formula get a leading quote.
function exportResults() {
  const run = lastSearch;
  if (!run) return;
  const res = run.tab === 'events' && run.events ? run.events : run.res;
  const cols = res.columns || [];
  const cell = (v) => {
    let s = v == null ? '' : Array.isArray(v) ? v.join(', ') : String(v);
    if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const csv = [cols.map(cell).join(','), ...(res.rows || []).map((r) => cols.map((c) => cell(r[c])).join(','))].join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  const a = el('a', { href: url, download: `signalith-search-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}.csv` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ---------- histogram ----------
// Events over time for the search part of the query, as a strip of bars
// above the results. Skipped when a command before any summary drops
// events (where, threatmatch, head), since the bars would overcount.
const HIST_SPAN = { '-15m': '30s', '-1h': '1m', '-4h': '5m', '-24h': '30m', '-7d': '3h', '-30d': '12h' };
function hideHistogram() {
  const box = $('histogram');
  box.classList.add('hidden');
  box.classList.remove('is-loading');
  box.replaceChildren();
}
async function loadHistogram(seq, query, earliest) {
  const box = $('histogram');
  const segs = pipeSegments(query);
  if (['where', 'threatmatch', 'head'].includes(commandOf(segs[1]))) { hideHistogram(); return; }
  const search = segs[0].trim() || '*';
  const ownTime = /\b(earliest|latest)\s*=/i.test(search);
  const fetchHist = (span) => api('api/search', { query: search + '\n| timechart ' + (span ? 'span=' + span + ' ' : '') + 'count', earliest });
  let res;
  try {
    res = await fetchHist(ownTime ? '' : HIST_SPAN[$('time').value] || '1d');
    if (!ownTime && !earliest && (res.rows || []).length < 3) res = await fetchHist('1h');
  } catch (_) {
    if (seq === searchSeq) hideHistogram();
    return;
  }
  if (seq !== searchSeq) return;
  box.classList.remove('is-loading');
  const dur = { m: 60e3, h: 3600e3, d: 86400e3 };
  const m = !ownTime && earliest.match(/^-(\d+)([mhd])$/);
  drawHistogram(box, res.rows || [], m ? [Date.now() - m[1] * dur[m[2]], Date.now()] : null);
}

function drawHistogram(box, rows, range) {
  const pts = rows.map((r) => [Date.parse(r._time), Number(r.count) || 0]).filter((p) => isFinite(p[0])).sort((a, b) => a[0] - b[0]);
  if (!pts.some((p) => p[1] > 0)) { hideHistogram(); return; }
  let step = Infinity;
  for (let k = 1; k < pts.length; k++) if (pts[k][0] > pts[k - 1][0]) step = Math.min(step, pts[k][0] - pts[k - 1][0]);
  if (!isFinite(step)) step = range ? Math.max(60e3, (range[1] - range[0]) / 24) : 3600e3;
  // Fill the gaps and stretch to the chosen range, so quiet hours show.
  let start = pts[0][0];
  let end = pts[pts.length - 1][0];
  if (range && (range[1] - range[0]) / step <= 2000) {
    start -= Math.max(0, Math.ceil((start - range[0]) / step)) * step;
    end += Math.max(0, Math.floor((range[1] - end) / step)) * step;
  }
  const n = Math.min(4000, Math.round((end - start) / step) + 1);
  const counts = new Array(n).fill(0);
  for (const [t, c] of pts) {
    const i = Math.round((t - start) / step);
    if (i >= 0 && i < n) counts[i] += c;
  }
  // Merge neighbours so bars stay at least a few pixels wide.
  const width = $('results-card').clientWidth - 32;
  const maxBars = width > 0 ? Math.max(12, Math.min(72, Math.floor(width / 10))) : 60;
  const group = Math.ceil(n / maxBars);
  const bars = [];
  for (let i = 0; i < n; i += group) {
    bars.push({ t0: start + i * step, t1: start + Math.min(n, i + group) * step, c: counts.slice(i, i + group).reduce((a, b) => a + b, 0) });
  }
  const max = Math.max(...bars.map((b) => b.c)) || 1;
  const total = bars.reduce((a, b) => a + b.c, 0);
  const t0 = bars[0].t0;
  const t1 = bars[bars.length - 1].t1;
  const long = t1 - t0 > 3 * 86400e3;
  const day = (d) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const hm = (d) => d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  const tip = (b) => {
    const a = new Date(b.t0);
    const z = new Date(b.t1);
    const same = a.toDateString() === z.toDateString();
    return `${day(a)}, ${hm(a)} – ${same ? '' : day(z) + ', '}${hm(z)} · ${b.c.toLocaleString()} event${b.c === 1 ? '' : 's'}`;
  };
  const label = (f, i) => {
    const d = new Date(t0 + f * (t1 - t0));
    const text = long ? day(d) : (i === 0 || i === 4 || d.getHours() + d.getMinutes() === 0) && t1 - t0 >= 12 * 3600e3 ? `${day(d)}, ${hm(d)}` : hm(d);
    return el('span', i % 2 ? { class: 'hide-sm' } : {}, text);
  };
  box.replaceChildren(
    el('div', { class: 'histogram__bars', role: 'img', 'aria-label': `Events over time: ${total.toLocaleString()} events from ${new Date(t0).toLocaleString()} to ${new Date(t1).toLocaleString()}` },
      ...bars.map((b) => el('span', b.c ? { title: tip(b), style: `--h:${Math.max(4, 100 * b.c / max).toFixed(1)}%` } : { title: tip(b), 'data-zero': '' }))),
    el('div', { class: 'histogram__axis', 'aria-hidden': 'true' }, ...[0, 0.25, 0.5, 0.75, 1].map(label)));
  box.classList.remove('hidden');
}

// ---------- cell actions ----------
function showCellMenu(ev, col, value, kind, row, canSort) {
  hideCellMenu();
  const item = (iconName, label, act) => el('button', {
    type: 'button', class: 'menu__item', role: 'menuitem', title: label,
    onclick: (e) => { e.stopPropagation(); hideCellMenu(); act(); },
  }, icon(iconName), el('span', {}, label));
  const pin = kind === 'events' && row && typeof pinEventToCase === 'function' ? item('pin', 'Pin this event to a case', () => pinEventToCase(row)) : null;
  if (value === null || value === undefined || col === 'count' || col === 'percent' || (col === '_raw' && !pin)) return;
  if (col === '_raw') {
    openCellMenu(ev, [pin]);
    return;
  }
  const field = col === '_time' ? null : col;
  const items = [];
  if (field && kind !== 'timechart') {
    items.push(item('filter', `Filter to ${field}=${fmtValue(value)}`, () => addSearchTerm(field + '=' + quoteValue(value))));
    items.push(item('filter-x', `Exclude ${field}=${fmtValue(value)}`, () => addSearchTerm(field + '!=' + quoteValue(value))));
    items.push(item('chart-bar', `Count events by ${field}`, () => {
      setQuery(splitPipes(queryBox.value)[0].trim() + '\n| stats count by ' + field + '\n| sort -count');
      runSearch();
    }));
    items.push(item('chart-line', `Chart ${field} over time`, () => {
      setQuery(splitPipes(queryBox.value)[0].trim() + '\n| timechart count by ' + field);
      runSearch();
    }));
    if (canSort) items.push(item('arrow-up-down', `Sort events by ${field}`, () => sortBy(field)));
  }
  if (col === '_time' && canSort) items.push(item('arrow-up-down', 'Sort events by time', () => sortBy('_time')));
  items.push(item('copy', 'Copy value', () => {
    navigator.clipboard.writeText(fmtValue(value)).then(() => { if (typeof toast === 'function') toast('Copied to the clipboard.'); }, () => {});
  }));
  if (pin) items.push(pin);
  openCellMenu(ev, items);
}
// openCellMenu shows the menu where the click was, or under the control
// when it was opened from the keyboard (then focus moves into the menu).
let cellMenuFrom = null;
function openCellMenu(ev, items) {
  const menu = $('cell-menu');
  menu.replaceChildren(...items);
  menu.classList.remove('hidden');
  const keyboard = ev.detail === 0;
  const r = ev.target.getBoundingClientRect();
  const x = keyboard ? r.left + window.scrollX : ev.pageX;
  const y = keyboard ? r.bottom + window.scrollY + 4 : ev.pageY;
  const maxLeft = window.scrollX + document.documentElement.clientWidth - menu.offsetWidth - 8;
  menu.style.left = Math.max(window.scrollX + 8, Math.min(x, maxLeft)) + 'px';
  menu.style.top = y + 'px';
  cellMenuFrom = keyboard ? ev.target.closest('button') : null;
  if (keyboard) menu.querySelector('button').focus();
  ev.stopPropagation();
}
function hideCellMenu() { $('cell-menu').classList.add('hidden'); }
document.addEventListener('click', hideCellMenu);
$('cell-menu').addEventListener('keydown', (ev) => {
  const items = [...$('cell-menu').querySelectorAll('button')];
  const i = items.indexOf(document.activeElement);
  if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
    ev.preventDefault();
    items[(i + (ev.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length].focus();
  } else if (ev.key === 'Tab') {
    hideCellMenu();
  }
});
document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Escape' || $('cell-menu').classList.contains('hidden')) return;
  hideCellMenu();
  if (cellMenuFrom && document.contains(cellMenuFrom)) cellMenuFrom.focus();
});

// ---------- charts ----------
// Charts are plain SVG drawn at the container's pixel width, so text stays
// crisp at any size; they redraw when the container is resized. Colors
// come from CSS variables so they follow the light or dark theme.
const SERIES = 8;
const seriesColor = (i) => `var(--series-${(i % SERIES) + 1})`;
const SVGNS = 'http://www.w3.org/2000/svg';

function svgEl(parent, tag, attrs, text) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  if (parent) parent.append(n);
  return n;
}

// fmtCompact shortens big numbers: 12.3k, 4.5M.
function fmtCompact(v) {
  const n = Number(v);
  if (!isFinite(n)) return fmtValue(v);
  const a = Math.abs(n);
  if (a >= 1e9) return (n / 1e9).toFixed(a >= 1e10 ? 0 : 1) + 'B';
  if (a >= 1e6) return (n / 1e6).toFixed(a >= 1e7 ? 0 : 1) + 'M';
  if (a >= 1e4) return (n / 1e3).toFixed(a >= 1e5 ? 0 : 1) + 'k';
  return Number.isInteger(n) ? n.toLocaleString() : n.toLocaleString(undefined, { maximumFractionDigits: 2 });
}

// niceMax rounds a maximum up to 1, 2 or 5 times a power of ten.
function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p;
  return 10 * p;
}

const chartObserver = typeof ResizeObserver === 'function' ? new ResizeObserver((entries) => {
  for (const e of entries) {
    const box = e.target;
    const w = Math.round(e.contentRect.width);
    if (box._draw && w && w !== box._drawnWidth) box._draw();
  }
}) : null;

// releaseCharts stops watching the charts inside a box that is about to be
// replaced.
function releaseCharts(box) {
  if (chartObserver) box.querySelectorAll('.chart-holder').forEach((h) => chartObserver.unobserve(h));
}

// keepDrawn draws now and again whenever the box changes width.
function keepDrawn(box, draw) {
  box._draw = () => { box._drawnWidth = Math.round(box.clientWidth); draw(box._drawnWidth || 600); };
  box._draw();
  if (chartObserver) chartObserver.observe(box);
}

// drawTimeChart draws a timechart result as lines (or filled areas) in box.
// opts: area, height, colorFor(name, index), emptyText.
function drawTimeChart(box, res, opts = {}) {
  releaseCharts(box);
  const rows = res.rows || [];
  const series = (res.columns || []).filter((c) => c !== '_time').slice(0, SERIES);
  if (!rows.length || !series.length) {
    box.replaceChildren(el('div', { class: 'muted chart-empty' }, opts.emptyText || 'No data in this time range.'));
    return;
  }
  const colorFor = opts.colorFor || ((_, i) => seriesColor(i));
  const times = rows.map((r) => new Date(r._time));
  const spanMs = times.length > 1 ? times[times.length - 1] - times[0] : 0;
  const fmtX = (d) => (isNaN(d) ? '' : spanMs >= 2 * 86400e3
    ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }));
  const fmtTip = (d) => (isNaN(d) ? '' : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));
  const values = rows.flatMap((r) => series.map((s) => Number(r[s]) || 0));
  // Whole-number data (counts) gets whole-number ticks.
  const whole = values.every(Number.isInteger);
  const max = whole ? Math.max(4, Math.ceil(niceMax(Math.max(0, ...values)) / 4) * 4) : niceMax(Math.max(0, ...values));
  const legend = el('div', { class: 'legend' }, ...series.map((s, si) => el('span', {},
    el('span', { class: 'swatch', style: `background:${colorFor(s, si)}` }), s)));
  const holder = el('div', { class: 'chart-holder' });
  box.replaceChildren(holder, series.length > 1 || opts.legend ? legend : '');
  keepDrawn(holder, (W) => {
    const H = opts.height || 220;
    const T = 10, B = 22, R = 10;
    const L = Math.max(28, fmtCompact(max).length * 7 + 10);
    const pw = Math.max(10, W - L - R), ph = H - T - B;
    const x = (i) => L + (rows.length === 1 ? pw / 2 : i * pw / (rows.length - 1));
    const y = (v) => T + ph * (1 - v / max);
    const svg = svgEl(null, 'svg', { class: 'chart-svg', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': (opts.label || 'Chart') + ': ' + series.join(', ') });
    for (let i = 0; i <= 4; i++) {
      const v = max * i / 4;
      svgEl(svg, 'line', { x1: L, x2: W - R, y1: y(v), y2: y(v), class: 'grid-line' });
      svgEl(svg, 'text', { x: L - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'axis' }, fmtCompact(v));
    }
    const labels = Math.max(2, Math.floor(pw / 80));
    const step = Math.max(1, Math.ceil(rows.length / labels));
    for (let i = 0; i < rows.length; i += step) {
      const anchor = i === 0 && rows.length > 1 ? 'start' : x(i) > W - R - 30 ? 'end' : 'middle';
      svgEl(svg, 'text', { x: x(i), y: H - 6, 'text-anchor': anchor, class: 'axis' }, fmtX(times[i]));
    }
    series.forEach((s, si) => {
      const pts = rows.map((r, i) => [x(i), y(Number(r[s]) || 0)]);
      const color = colorFor(s, si);
      if (opts.area) {
        const d = `M${pts[0][0]},${y(0)} ` + pts.map((p) => `L${p[0]},${p[1]}`).join(' ') + ` L${pts[pts.length - 1][0]},${y(0)} Z`;
        svgEl(svg, 'path', { d, style: `fill:${color}`, 'fill-opacity': series.length > 1 ? 0.12 : 0.2 });
      }
      svgEl(svg, 'polyline', { points: pts.map((p) => p.join(',')).join(' '), fill: 'none', style: `stroke:${color}`, 'stroke-width': 2, 'stroke-linejoin': 'round' });
      if (rows.length === 1) svgEl(svg, 'circle', { cx: pts[0][0], cy: pts[0][1], r: 3, style: `fill:${color}` });
    });
    // Hover a column to see every value at that time.
    const colW = rows.length > 1 ? pw / (rows.length - 1) : pw;
    rows.forEach((r, i) => {
      const hit = svgEl(svg, 'rect', { x: x(i) - colW / 2, y: T, width: colW, height: ph, class: 'hit' });
      svgEl(hit, 'title', {}, fmtTip(times[i]) + '\n' + series.map((s) => `${s}: ${fmtValue(r[s] ?? 0)}`).join('\n'));
    });
    holder.replaceChildren(svg);
  });
}

// drawBarChart draws labeled horizontal bars, largest first as given.
// items: [{label, value, note, color, onclick}].
function drawBarChart(box, items, opts = {}) {
  releaseCharts(box);
  if (!items.length) {
    box.replaceChildren(el('div', { class: 'muted chart-empty' }, opts.emptyText || 'Nothing in this time range.'));
    return;
  }
  const holder = el('div', { class: 'chart-holder' });
  box.replaceChildren(holder);
  const max = Math.max(...items.map((it) => Number(it.value) || 0), 0) || 1;
  keepDrawn(holder, (W) => {
    const rowH = 34, H = items.length * rowH;
    const svg = svgEl(null, 'svg', { class: 'chart-svg bars', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': opts.label || 'Bar chart' });
    const fit = (t, px) => { const n = Math.max(4, Math.floor(px / 7)); return t.length > n ? t.slice(0, n - 1) + '…' : t; };
    items.forEach((it, i) => {
      const top = i * rowH;
      const g = svgEl(svg, 'g', { class: it.onclick ? 'bar-row clickable' : 'bar-row' });
      const valText = it.note || fmtCompact(it.value);
      const valW = valText.length * 7 + 6;
      svgEl(g, 'text', { x: 0, y: top + 13, class: 'bar-text' }, fit(String(it.label), W - valW - 8));
      svgEl(g, 'text', { x: W, y: top + 13, 'text-anchor': 'end', class: 'bar-value' }, valText);
      svgEl(g, 'rect', { x: 0, y: top + 18, width: W, height: 8, rx: 3, class: 'bar-track' });
      svgEl(g, 'rect', { x: 0, y: top + 18, width: Math.max(2, W * (Number(it.value) || 0) / max), height: 8, rx: 3, style: `fill:${it.color || opts.color || seriesColor(0)}` });
      svgEl(g, 'title', {}, `${it.label}: ${fmtValue(it.value)}${it.note ? ' (' + it.note + ')' : ''}`);
      if (it.onclick) g.addEventListener('click', it.onclick);
    });
    holder.replaceChildren(svg);
  });
}

// ---------- explain ----------
// Explain opens a plain-English reading of the query at the foot of the
// query card; pressing it again closes it.
function hideExplanation() {
  $('explanation').classList.add('hidden');
  $('explain').setAttribute('aria-pressed', 'false');
}
$('explain').addEventListener('click', async () => {
  const box = $('explanation');
  if (!box.classList.contains('hidden')) { hideExplanation(); return; }
  $('explain').disabled = true;
  try {
    const res = await api('api/explain', { query: queryBox.value || '*', earliest: timeEarliest() });
    box.replaceChildren(
      el('div', { class: 'explain__head' }, el('b', {}, 'What this query does'),
        el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm', title: 'Close', 'aria-label': 'Close the explanation', onclick: hideExplanation }, icon('x'))),
      el('ol', { class: 'explain__steps' }, ...res.steps.map((s) => el('li', {}, s))),
      el('details', { class: 'explain__req' }, el('summary', {}, icon('chevron-right', 'icon--sm chev'), 'OpenSearch request on ', el('code', {}, res.index)),
        el('pre', {}, JSON.stringify(res.body, null, 2))));
    box.classList.remove('hidden');
    $('explain').setAttribute('aria-pressed', 'true');
  } catch (e) {
    showQueryError(e);
  } finally {
    $('explain').disabled = false;
  }
});

// ---------- starter queries ----------
const starters = [
  ['Brute force: many failed logons from one source', 'datamodel=Authentication action=failure\n| stats count, dc(user) as users by src\n| where count > 10\n| sort -count'],
  ['Successful logon after failures (password spraying)', 'datamodel=Authentication\n| stats count by src, action\n| sort src'],
  ['New local accounts created', 'datamodel=Change object_category=user action=created\n| table _time, host, user, object'],
  ['Encoded PowerShell commands (T1059.001)', 'datamodel=Endpoint process_name=powershell.exe process="*-enc*"\n| table _time, host, user, process'],
  ['Rare processes across hosts', 'datamodel=Endpoint\n| stats dc(host) as hosts, count by process_name\n| where hosts < 2\n| sort count'],
  ['sudo to root by user', 'datamodel=Authentication app=sudo action=success\n| top limit=20 src_user'],
  ['Connections to uncommon ports', 'datamodel=Network_Traffic dest_port>1024\n| stats count by dest, dest_port, process_name\n| sort -count'],
  ['Authentication activity over time', 'datamodel=Authentication\n| timechart count by action'],
  ['Events matching threat intel', '* | threatmatch\n| table _time, threat_match_field, threat_match_value, threat_source, threat_target, user, sourcetype'],
];
$('starter-list').replaceChildren(...starters.map(([title, q]) => {
  const code = el('code', { class: 'hunt__query' }, q.replace(/\s*\n\s*/g, ' '));
  return el('li', {}, el('button', { type: 'button', class: 'hunt', onclick: () => { setQuery(q); runSearch(); } },
    el('span', { class: 'hunt__title' }, title), code, icon('arrow-right', 'hunt__go')));
}));

// ---------- ask in plain English ----------
// The Ask row writes a query from a question. "Try" chips fill it with an
// example; after asking, the same row says how the question was read.
let askInfo = { ai_available: false, examples: [] };
// lastAsk lets "Add to dashboard" title a panel with the question asked.
let lastAsk = null;

function showAskResult(...kids) {
  const box = $('ask-result');
  box.replaceChildren(...kids.filter((k) => k != null));
  box.classList.remove('hidden');
  $('ask-try').classList.add('hidden');
}
function hideAskResult() {
  $('ask-result').classList.add('hidden');
  $('ask-try').classList.toggle('hidden', !askInfo.examples.length);
  fitTryChips();
}
const askClose = () => el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm ask-read__close', title: 'Hide', 'aria-label': 'Hide how the question was read', onclick: hideAskResult }, icon('x'));

async function ask(question, mode) {
  question = question.trim();
  if (!question) return;
  $('ask').value = question;
  const useAI = mode === 'ai' || (!mode && $('ask-ai').checked);
  showAskResult(el('span', { class: 'ask-read__label' }, useAI ? 'Asking the AI model…' : 'Writing the query…'));
  $('ask-go').disabled = true;
  let res;
  try {
    res = await api('api/ask', { question, mode: mode || (useAI ? 'ai' : 'auto') });
  } catch (e) {
    showAskResult(el('span', { class: 'ask-read__error' }, icon('circle-alert'), e.message), askClose());
    return;
  } finally {
    $('ask-go').disabled = false;
  }
  setQuery(res.query);
  lastAsk = { question, query: res.query };
  const kids = [];
  if (res.source === 'ai') {
    kids.push(el('span', { class: 'ask-read__label' }, 'Written by ', el('b', {}, res.ai_model || 'the AI model'), '. Check it before relying on the results.'));
  } else {
    const steps = (res.steps || []).filter((s) => s.meaning);
    if (steps.length) {
      kids.push(el('span', { class: 'ask-read__label' }, 'Read as'), ...steps.map((s) => el('span', { class: 'ask-step' },
        s.phrase ? el('b', {}, s.phrase) : null, s.phrase ? el('span', { class: 'ask-step__arrow', 'aria-hidden': 'true' }, '→') : null, s.phrase ? el('span', { class: 'sr-only' }, ' means ') : null, s.meaning)));
    }
    if ((res.unknown || []).length) {
      kids.push(el('span', { class: 'ask-read__label' }, 'Not understood:'), el('span', { class: 'ask-unknown' }, ...res.unknown.map((w) => el('code', {}, w))));
      if (!askInfo.ai_available) kids.push(el('span', { class: 'ask-read__label' }, 'Try field names from the Fields list, or edit the query.'));
    }
  }
  if (res.ai_error) kids.push(el('span', { class: 'ask-read__warn' }, icon('triangle-alert'), 'The AI model failed, so this is the built-in translation: ' + res.ai_error));
  const switchTo = res.source !== 'ai' && askInfo.ai_available ? ['Ask the AI model instead', 'ai'] : res.source === 'ai' ? ['Use the built-in translator instead', 'rules'] : null;
  kids.push(el('span', { class: 'ask-read__actions' },
    switchTo ? el('button', { type: 'button', class: 'link-btn', onclick: () => ask(question, switchTo[1]) }, switchTo[0]) : null, askClose()));
  showAskResult(...kids);
  if (res.source === 'ai' || res.confidence > 0) runSearch();
}
$('ask-form').addEventListener('submit', (ev) => { ev.preventDefault(); ask($('ask').value); });

// fitTryChips shows only the example chips that fit on the Try row (two
// rows on phones), so none is cut off or hidden from view but focusable.
function fitTryChips() {
  const chips = [...$('ask-examples').children];
  chips.forEach((c) => c.classList.remove('hidden'));
  if (!chips.length || !chips[0].offsetParent) return;
  const rows = matchMedia('(max-width: 720px)').matches ? 2 : 1;
  const tops = [...new Set(chips.map((c) => c.offsetTop))].sort((a, b) => a - b);
  const limit = tops[rows - 1] === undefined ? Infinity : tops[rows - 1];
  chips.forEach((c) => c.classList.toggle('hidden', c.offsetTop > limit));
}
let tryFrame = 0;
window.addEventListener('resize', () => { cancelAnimationFrame(tryFrame); tryFrame = requestAnimationFrame(fitTryChips); });

async function loadAskInfo() {
  try { askInfo = await api('api/ask'); } catch (_) { return; }
  $('ask-ai-wrap').classList.toggle('hidden', !askInfo.ai_available);
  if (askInfo.ai_model) $('ask-ai-wrap').title += ' (' + askInfo.ai_model + ')';
  $('ask-examples').replaceChildren(...(askInfo.examples || []).map((q) => el('button', { type: 'button', onclick: () => ask(q) }, q)));
  if ($('ask-result').classList.contains('hidden')) hideAskResult();
}

// ---------- query guide ----------
// Examples on the Query guide page use the same colouring as the editor;
// the worked example opens in Search.
function renderGuide() {
  document.querySelectorAll('#page-help [data-query]').forEach((n) => {
    if (n.classList.contains('editor')) {
      renderQuery(n, n.dataset.query, { lines: true });
    } else {
      const code = el('code', { class: 'qcode' });
      renderQuery(code, n.dataset.query);
      n.replaceChildren(code);
    }
  });
  $('guide-try').addEventListener('click', () => {
    setQuery(document.querySelector('#page-help .guide__example .editor').dataset.query);
    showPage('search');
    runSearch();
  });
}

// ---------- add data ----------
document.querySelectorAll('input[name=os]').forEach((r) => r.addEventListener('change', loadAgentConfig));
$('linux-source').addEventListener('change', loadAgentConfig);
$('sysmon').addEventListener('change', loadAgentConfig);
async function loadAgentConfig() {
  const os = document.querySelector('input[name=os]:checked').value;
  $('linux-opts').classList.toggle('hidden', os !== 'linux');
  $('windows-opts').classList.toggle('hidden', os !== 'windows');
  const q = new URLSearchParams({ os, source: $('linux-source').value, sysmon: $('sysmon').checked });
  try {
    const a = await api('api/agents/config?' + q);
    $('agent-steps').replaceChildren(...a.steps.map((s) => el('li', {}, s)));
    $('agent-path').textContent = a.config_path;
    $('agent-config').textContent = a.config;
  } catch (e) {
    $('agent-steps').replaceChildren(el('li', { class: 'error' }, e.message));
    $('agent-config').textContent = '';
  }
}
$('copy-config').addEventListener('click', () => navigator.clipboard.writeText($('agent-config').textContent));

// ---------- health ----------
async function loadHealth() {
  const box = $('health');
  try {
    const h = await api('api/health');
    const os = h.opensearch || {};
    const cls = os.status === 'green' ? 'ok' : os.status === 'yellow' ? 'warn' : 'bad';
    const ing = h.ingest || {};
    const last = ing.last_seen ? new Date(ing.last_seen).toLocaleString() : 'never';
    const cards = [
      el('div', { class: 'card' }, el('h4', {}, 'OpenSearch'), el('div', { class: 'big ' + cls }, os.status || 'unknown'),
        el('div', { class: 'muted' }, os.url || ''), os.error ? el('div', { class: 'error' }, os.error) : null,
        os.status === 'yellow' ? el('div', { class: 'muted' }, 'Yellow is normal on a single node: replicas have nowhere to go.') : null),
      el('div', { class: 'card' }, el('h4', {}, 'Events received since start'), el('div', { class: 'big' }, (ing.received || 0).toLocaleString()),
        el('div', { class: 'muted' }, `${(ing.indexed || 0).toLocaleString()} indexed, ${(ing.failed || 0).toLocaleString()} failed`),
        el('div', { class: 'muted' }, 'Last event: ' + last)),
      el('div', { class: 'card' }, el('h4', {}, 'Server'), el('div', {}, 'Version ' + h.version), el('div', { class: 'muted' }, 'Config: ' + (h.config_file || ''))),
    ];
    for (const w of h.warnings || []) cards.push(el('div', { class: 'card' }, el('h4', { class: 'warn' }, 'Needs attention'), el('div', {}, w)));
    box.replaceChildren(...cards);
  } catch (e) {
    box.replaceChildren(el('div', { class: 'error' }, e.message));
  }
}

// ---------- startup ----------
(async function init() {
  document.querySelectorAll('.mod-key').forEach((k) => { k.textContent = isMac ? '⌘' : 'Ctrl'; });
  $('run').title = `Search (${isMac ? '⌘' : 'Ctrl'}+Enter)`;
  renderGuide();
  renderEditor();
  try { if (localStorage.getItem('signalith.builder') === 'open') $('builder').open = true; } catch (_) { /* ignore */ }
  // The Try row measures itself, so it refits when Search is shown.
  document.addEventListener('DOMContentLoaded', () => {
    if (typeof pageHooks !== 'undefined') pageHooks.push((name) => { if (name === 'search') fitTryChips(); });
  });
  try {
    const models = await api('api/datamodels');
    $('b-datamodel').append(...models.map((m) => el('option', { value: m.name, title: m.description }, m.name.replace('_', ' '))));
  } catch (_) { /* shown on search */ }
  let saved = null, savedTime = null;
  try {
    saved = localStorage.getItem('signalith.query');
    savedTime = localStorage.getItem('signalith.time');
  } catch (_) { /* ignore */ }
  if (savedTime) $('time').value = savedTime;
  if (saved) setQuery(saved);
  updateBuilderVisibility();
  loadFields();
  loadAskInfo();
})();
