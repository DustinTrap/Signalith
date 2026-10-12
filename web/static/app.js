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

// ---------- state ----------
let fields = [];
let fieldsFor = null;
let syncingBuilder = false;

function setQuery(text, fromBuilder) {
  $('query').value = text;
  if (!fromBuilder) parseIntoBuilder();
  saveDraft();
}
function saveDraft() {
  try { localStorage.setItem('signalith.query', $('query').value); } catch (_) { /* ignore */ }
}

// ---------- fields sidebar ----------
async function loadFields() {
  const dm = currentDatamodel();
  if (dm === fieldsFor) return;
  fieldsFor = dm;
  try {
    fields = await api('api/fields?datamodel=' + encodeURIComponent(dm));
  } catch (e) {
    fields = [];
  }
  renderFields();
  const dl = $('field-names');
  dl.replaceChildren(...fields.map((f) => el('option', { value: f.name })));
}
function renderFields() {
  const filter = $('field-filter').value.toLowerCase();
  const list = $('field-list');
  list.replaceChildren(...fields
    .filter((f) => !filter || f.name.toLowerCase().includes(filter))
    .map((f) => el('li', {
      class: f.indexed ? '' : 'unindexed',
      title: f.description + (f.indexed ? '' : ' (not seen in your data yet)'),
      onclick: (ev) => showFieldValues(f, ev.currentTarget),
    }, el('span', {}, f.name), el('span', { class: 'type' }, f.type))));
}
$('field-filter').addEventListener('input', renderFields);

async function showFieldValues(f, li) {
  document.querySelectorAll('.field-list li').forEach((n) => n.classList.remove('selected'));
  li.classList.add('selected');
  const box = $('field-values');
  box.classList.remove('hidden');
  box.replaceChildren(el('div', { class: 'muted' }, f.description || f.name), el('div', { class: 'muted' }, 'Loading top values...'));
  try {
    const q = new URLSearchParams({ field: f.name, datamodel: currentDatamodel(), earliest: $('time').value });
    const rows = await api('api/fields/values?' + q);
    const items = rows.map((r) => el('div', { class: 'fv', title: 'Filter on this value', onclick: () => addSearchTerm(f.name + '=' + quoteValue(r[f.name])) },
      el('span', {}, String(r[f.name])), el('span', { class: 'muted' }, r.count)));
    box.replaceChildren(el('div', { class: 'muted' }, f.description || f.name),
      items.length ? el('div', {}, ...items) : el('div', { class: 'muted' }, 'No values in this time range.'),
      el('button', { class: 'link', onclick: () => { setQuery(splitPipes($('query').value)[0].trim() + '\n| top limit=20 ' + f.name); runSearch(); } }, 'Top values as a table'));
  } catch (e) {
    box.replaceChildren(el('div', { class: 'error' }, e.message));
  }
}

// ---------- autocomplete ----------
const lang = { commands: ['stats', 'timechart', 'top', 'where', 'sort', 'head', 'table', 'rename', 'enrich', 'threatmatch', 'intel'], functions: ['count', 'dc', 'sum', 'avg', 'min', 'max'] };
let suggestions = [];
let suggestIndex = 0;

function currentWord() {
  const ta = $('query');
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
  if (!suggestions.length) { ul.classList.add('hidden'); return; }
  ul.replaceChildren(...suggestions.map((s, i) => el('li', {
    class: i === suggestIndex ? 'active' : '',
    onmousedown: (ev) => { ev.preventDefault(); acceptSuggestion(i); },
  }, el('span', {}, s.text.trim()), el('span', { class: 'kind' }, s.kind))));
  ul.classList.remove('hidden');
}
function acceptSuggestion(i) {
  const s = suggestions[i];
  const ta = $('query');
  const { start } = currentWord();
  const end = ta.selectionStart;
  ta.value = ta.value.slice(0, start) + s.text + ta.value.slice(end);
  ta.selectionStart = ta.selectionEnd = start + s.text.length;
  suggestions = [];
  renderSuggestions();
  ta.focus();
  onQueryInput();
}
$('query').addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); runSearch(); return; }
  if (!suggestions.length) return;
  if (ev.key === 'ArrowDown') { ev.preventDefault(); suggestIndex = (suggestIndex + 1) % suggestions.length; renderSuggestions(); }
  else if (ev.key === 'ArrowUp') { ev.preventDefault(); suggestIndex = (suggestIndex + suggestions.length - 1) % suggestions.length; renderSuggestions(); }
  else if (ev.key === 'Tab' || ev.key === 'Enter') { ev.preventDefault(); acceptSuggestion(suggestIndex); }
  else if (ev.key === 'Escape') { suggestions = []; renderSuggestions(); }
});
$('query').addEventListener('blur', () => setTimeout(() => { suggestions = []; renderSuggestions(); }, 100));

let parseTimer = null;
function onQueryInput() {
  saveDraft();
  clearTimeout(parseTimer);
  parseTimer = setTimeout(() => { parseIntoBuilder(); loadFields(); }, 300);
}
$('query').addEventListener('input', () => { updateSuggestions(); onQueryInput(); });

// ---------- builder ----------
function filterRow(f = { field: '', op: '=', value: '' }) {
  const ops = ['=', '!=', '>', '>=', '<', '<='];
  const row = el('div', { class: 'b-filter-row' },
    el('input', { type: 'text', list: 'field-names', placeholder: 'field', value: f.field, class: 'bf-field' }),
    el('select', { class: 'bf-op' }, ...ops.map((o) => {
      const opt = el('option', { value: o }, o);
      if (o === f.op) opt.selected = true;
      return opt;
    })),
    el('input', { type: 'text', placeholder: 'value (* for wildcard)', value: f.value, class: 'bf-value' }),
    el('button', { class: 'link', title: 'Remove', onclick: () => { row.remove(); builderChanged(); } }, 'Remove'));
  row.addEventListener('input', builderChanged);
  row.addEventListener('change', builderChanged);
  return row;
}
$('b-add-filter').addEventListener('click', () => { $('b-filter-rows').append(filterRow()); });

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
  $('b-agg-field').classList.toggle('hidden', $('b-agg').value === 'count');
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

async function parseIntoBuilder() {
  const text = $('query').value.trim();
  if (!text) return;
  try {
    const res = await api('api/parse', { query: text });
    $('query-error').classList.add('hidden');
    if (!res.builder_ok) {
      $('builder-note').textContent = ' (this query uses features the builder cannot show; edit the text instead)';
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
    showQueryError(e);
  }
}

function showQueryError(e) {
  const box = $('query-error');
  if (typeof e.pos === 'number') {
    const text = $('query').value;
    const lineStart = text.lastIndexOf('\n', e.pos - 1) + 1;
    let lineEnd = text.indexOf('\n', e.pos);
    if (lineEnd < 0) lineEnd = text.length;
    box.textContent = e.message + '\n' + text.slice(lineStart, lineEnd) + '\n' + ' '.repeat(e.pos - lineStart) + '^';
  } else {
    box.textContent = e.message;
  }
  box.classList.remove('hidden');
}

// ---------- running searches ----------
async function runSearch() {
  const query = $('query').value.trim() || '*';
  $('query-error').classList.add('hidden');
  $('starter').classList.add('hidden');
  $('status').textContent = 'Searching...';
  $('explanation').classList.add('hidden');
  hideCellMenu();
  try {
    const res = await api('api/search', { query, earliest: $('time').value === '0' ? '' : $('time').value });
    renderResult(res);
  } catch (e) {
    $('status').textContent = '';
    showQueryError(e);
  }
}
$('run').addEventListener('click', runSearch);
$('time').addEventListener('change', () => { try { localStorage.setItem('signalith.time', $('time').value); } catch (_) { /* ignore */ } runSearch(); });

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

function renderResult(res) {
  const rows = res.rows || [];
  const parts = [`${rows.length.toLocaleString()} row${rows.length === 1 ? '' : 's'}`];
  if (res.kind === 'events' || res.matched) parts.push(`${(res.matched || 0).toLocaleString()} matching events`);
  parts.push(`${res.took_ms} ms`);
  if (res.truncated) parts.push('results were truncated');
  $('status').textContent = parts.join(' · ');
  releaseCharts($('chart'));
  $('chart').replaceChildren();
  if (res.kind === 'timechart') renderChart(res);
  let cols = res.columns || [];
  if (res.kind === 'events') {
    // Events read best as time, a few key fields, then the raw text.
    const preferred = ['_time', 'host', 'sourcetype', 'action', 'user', 'src', 'dest', 'process_name', 'signature'];
    // Columns added by | enrich follow the field they describe.
    const enriched = (c) => cols.filter((x) => x.startsWith(c + '_') && /_(name|owner|priority|category|watchlist)$/.test(x));
    cols = preferred.filter((c) => cols.includes(c)).flatMap((c) => [c, ...enriched(c)]).concat(cols.includes('_raw') ? ['_raw'] : []);
  }
  if (!rows.length) {
    $('results').replaceChildren(el('div', { class: 'muted', style: 'padding:12px' }, 'No results. Try a longer time range, or check the Health page to confirm data is arriving.'));
    return;
  }
  const table = el('table', { class: 'grid' },
    el('thead', {}, el('tr', {}, ...cols.map((c) => el('th', { title: 'Sort by ' + c, onclick: () => sortBy(c) }, c)))),
    el('tbody', {}, ...rows.map((r) => el('tr', {}, ...cols.map((c) => {
      const v = r[c];
      const cls = c === '_raw' ? 'raw' : (typeof v === 'number' ? 'num' : '');
      return el('td', { class: cls, onclick: (ev) => showCellMenu(ev, c, v, res.kind, r) }, c === '_time' ? fmtTime(v) : fmtValue(v));
    })))));
  $('results').replaceChildren(table);
}

function sortBy(col) {
  const q = $('query').value.trim();
  const m = q.match(/\n?\|\s*sort\s+(-?)([^\s|]+)\s*$/);
  let desc = true;
  let base = q;
  if (m && m[2] === col) { desc = m[1] !== '-'; base = q.slice(0, m.index); }
  else if (m) base = q.slice(0, m.index);
  setQuery(base + '\n| sort ' + (desc ? '-' : '') + col);
  runSearch();
}

// ---------- cell actions ----------
function showCellMenu(ev, col, value, kind, row) {
  hideCellMenu();
  const pin = kind === 'events' && row && typeof pinEventToCase === 'function'
    ? el('button', { onclick: () => { hideCellMenu(); pinEventToCase(row); } }, 'Pin this event to a case') : null;
  if (value === null || value === undefined || col === 'count' || col === 'percent' || (col === '_raw' && !pin)) return;
  if (col === '_raw') {
    $('cell-menu').replaceChildren(pin);
    placeCellMenu(ev);
    return;
  }
  const menu = $('cell-menu');
  const field = col === '_time' ? null : col;
  const items = [];
  if (field && kind !== 'timechart') {
    items.push(el('button', { onclick: () => { hideCellMenu(); addSearchTerm(field + '=' + quoteValue(value)); } }, `Filter to ${field}=${fmtValue(value)}`));
    items.push(el('button', { onclick: () => { hideCellMenu(); addSearchTerm(field + '!=' + quoteValue(value)); } }, `Exclude ${field}=${fmtValue(value)}`));
    items.push(el('button', { onclick: () => {
      hideCellMenu();
      setQuery(splitPipes($('query').value)[0].trim() + '\n| stats count by ' + field + '\n| sort -count');
      runSearch();
    } }, `Count events by ${field}`));
    items.push(el('button', { onclick: () => {
      hideCellMenu();
      setQuery(splitPipes($('query').value)[0].trim() + '\n| timechart count by ' + field);
      runSearch();
    } }, `Chart ${field} over time`));
  }
  items.push(el('button', { onclick: () => { hideCellMenu(); navigator.clipboard.writeText(fmtValue(value)); } }, 'Copy value'));
  if (pin) items.push(pin);
  menu.replaceChildren(...items);
  placeCellMenu(ev);
}
function placeCellMenu(ev) {
  const menu = $('cell-menu');
  menu.style.left = ev.pageX + 'px';
  menu.style.top = ev.pageY + 'px';
  menu.classList.remove('hidden');
  ev.stopPropagation();
}
function hideCellMenu() { $('cell-menu').classList.add('hidden'); }
document.addEventListener('click', hideCellMenu);

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

function renderChart(res) {
  drawTimeChart($('chart'), res, { legend: true, label: 'Search results over time' });
}

// ---------- explain ----------
$('explain').addEventListener('click', async () => {
  const box = $('explanation');
  try {
    const res = await api('api/explain', { query: $('query').value || '*', earliest: $('time').value === '0' ? '' : $('time').value });
    box.replaceChildren(
      el('strong', {}, 'What this query does'),
      el('ol', {}, ...res.steps.map((s) => el('li', {}, s))),
      el('details', {}, el('summary', { class: 'muted' }, `OpenSearch request on ${res.index}`), el('pre', { class: 'code' }, JSON.stringify(res.body, null, 2))),
      el('button', { class: 'link', onclick: () => box.classList.add('hidden') }, 'Hide'));
    box.classList.remove('hidden');
  } catch (e) {
    showQueryError(e);
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
$('starter-list').replaceChildren(...starters.map(([title, q]) => el('li', {},
  el('a', { onclick: () => { setQuery(q); runSearch(); } }, title))));

// ---------- ask in plain English ----------
let askInfo = { ai_available: false, examples: [] };
// lastAsk lets "Add to dashboard" title a panel with the question asked.
let lastAsk = null;

async function ask(question, mode) {
  question = question.trim();
  if (!question) return;
  $('ask').value = question;
  const box = $('ask-result');
  box.classList.remove('hidden');
  box.replaceChildren(el('span', { class: 'muted' }, mode === 'ai' || $('ask-ai').checked ? 'Asking the AI model...' : 'Writing the query...'));
  let res;
  try {
    res = await api('api/ask', { question, mode: mode || ($('ask-ai').checked ? 'ai' : 'auto') });
  } catch (e) {
    box.replaceChildren(el('div', { class: 'error' }, e.message));
    return;
  }
  setQuery(res.query);
  lastAsk = { question, query: res.query };
  const steps = (res.steps || []).filter((s) => s.meaning);
  const head = res.source === 'ai'
    ? el('div', {}, el('b', {}, 'Query written by ' + (res.ai_model || 'the AI model')), el('span', { class: 'muted' }, '. Check it before relying on the results.'))
    : el('div', {}, el('b', {}, 'Here is how I read that:'));
  const understood = res.source === 'ai' ? null : el('ul', { class: 'ask-steps' }, ...steps.map((s) => el('li', {},
    s.phrase ? el('span', { class: 'ask-phrase' }, s.phrase) : null, s.phrase ? ' → ' : '', s.meaning)));
  const unknown = res.source !== 'ai' && (res.unknown || []).length
    ? el('div', { class: 'muted' }, 'Not understood: ', ...res.unknown.map((w) => el('code', {}, w + ' ')), askInfo.ai_available ? null : '. Try field names from the list on the left, or edit the query.')
    : null;
  const actions = el('div', { class: 'row' },
    res.source !== 'ai' && askInfo.ai_available ? el('button', { class: 'link', onclick: () => ask(question, 'ai') }, 'Ask the AI model instead') : null,
    res.source === 'ai' ? el('button', { class: 'link', onclick: () => ask(question, 'rules') }, 'Use the built-in translator instead') : null,
    el('button', { class: 'link', onclick: () => box.classList.add('hidden') }, 'Hide'));
  fill(box, head, understood, unknown,
    res.ai_error ? el('div', { class: 'error' }, 'The AI model failed, so this is the built-in translation: ' + res.ai_error) : null, actions);
  if (res.source === 'ai' || res.confidence > 0) runSearch();
}
$('ask-form').addEventListener('submit', (ev) => { ev.preventDefault(); ask($('ask').value); });

async function loadAskInfo() {
  try { askInfo = await api('api/ask'); } catch (_) { return; }
  $('ask-ai-wrap').classList.toggle('hidden', !askInfo.ai_available);
  if (askInfo.ai_model) $('ask-ai-wrap').title += ' (' + askInfo.ai_model + ')';
  $('ask-examples').replaceChildren(...askInfo.examples.map((q) => el('li', {}, el('a', { onclick: () => ask(q) }, q))));
}

// ---------- add data ----------
// The server writes the Fluent Bit setup for the chosen OS: plain-sentence
// steps and the config file. A step written as "Do this: command" shows the
// command in a copyable well, and the step that saves the config file
// carries the file itself.
const agentFileEl = $('agent-file');
let agentSetupSeq = 0;
let agentSetupConfig = '';
let agentSetupErrEl = null;
document.querySelectorAll('input[name=os]').forEach((r) => r.addEventListener('change', loadAgentConfig));
$('linux-source').addEventListener('change', loadAgentConfig);
$('sysmon').addEventListener('change', loadAgentConfig);

async function loadAgentConfig() {
  const os = document.querySelector('input[name=os]:checked').value;
  $('linux-opts').classList.toggle('hidden', os !== 'linux');
  $('windows-opts').classList.toggle('hidden', os !== 'windows');
  $('agent-title').textContent = 'Set up Fluent Bit on ' + (os === 'windows' ? 'Windows' : 'Linux');
  const steps = $('agent-steps');
  const seq = ++agentSetupSeq;
  steps.setAttribute('aria-busy', 'true');
  if (!agentSetupConfig) agentSetupSkeleton();
  const q = new URLSearchParams({ os, source: $('linux-source').value, sysmon: $('sysmon').checked });
  try {
    const a = await api('api/agents/config?' + q);
    if (seq === agentSetupSeq) agentSetupRender(a);
  } catch (e) {
    if (seq === agentSetupSeq) agentSetupError(e);
  } finally {
    if (seq === agentSetupSeq) steps.removeAttribute('aria-busy');
  }
}

function agentSetupRender(a) {
  if (agentSetupErrEl) agentSetupErrEl.remove();
  agentSetupConfig = a.config || '';
  $('agent-steps').classList.remove('hidden');
  const path = a.config_path || '';
  // The step names the full path; the file bar shows the file name.
  const pathEl = agentFileEl.querySelector('#agent-path');
  pathEl.textContent = path.split(/[\\/]/).pop();
  pathEl.title = path;
  agentSetupEditor(agentSetupConfig);
  let fileStep = null;
  const items = (a.steps || []).map((s, i) => {
    const li = agentSetupStep(s, i + 1, path);
    if (!fileStep && path && s.includes(path)) fileStep = li;
    return li;
  });
  $('agent-steps').replaceChildren(...items);
  // The config file sits under the step that saves it, else after the list.
  (fileStep ? fileStep.querySelector('.agent-step__body') : $('agent-body')).append(agentFileEl);
  agentFileEl.classList.toggle('hidden', !agentSetupConfig);
}

// agentSetupStep renders one numbered step. "Label: command" becomes the
// label plus a command well.
function agentSetupStep(text, n, path) {
  const body = el('div', { class: 'agent-step__body' });
  const cut = text.indexOf(': ');
  if (cut > 0 && cut < text.length - 2) {
    body.append(el('p', { class: 'agent-step__text' }, ...agentSetupInline(text.slice(0, cut), path)),
      agentSetupCommand(text.slice(cut + 2)));
  } else {
    body.append(el('p', { class: 'agent-step__text' }, ...agentSetupInline(text, path)));
  }
  return el('li', { class: 'agent-step' }, el('span', { class: 'agent-step__num' }, n), body);
}

// agentSetupInline turns URLs into links, the config path into code and
// "Health page" into a link to that page.
function agentSetupInline(text, path) {
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('(https?://[^\\s,;]*[^\\s,;.)])|(Health page)' + (path ? '|(' + esc(path) + ')' : ''), 'g');
  const parts = [];
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    if (m[1]) parts.push(el('a', { href: m[1], target: '_blank', rel: 'noopener noreferrer' }, m[1], icon('external-link', 'icon--xs')));
    else if (m[2]) parts.push(el('a', { href: '#health', 'data-page': 'health' }, m[2]));
    else parts.push(el('code', {}, m[3]));
    last = re.lastIndex;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

function agentSetupCommand(cmd) {
  const btn = el('button', { class: 'btn btn--ghost btn--icon btn--sm', type: 'button', 'aria-label': 'Copy command', title: 'Copy command' }, icon('copy'));
  btn.addEventListener('click', () => agentSetupCopy(cmd, btn));
  return el('div', { class: 'agent-cmd' }, el('code', {}, cmd), btn);
}

// agentSetupEditor shows the config with line numbers and quiet colours:
// section headers in the accent, keys secondary, comments muted.
function agentSetupEditor(config) {
  const lines = config.replace(/\n$/, '').split('\n');
  const out = [];
  lines.forEach((line, i) => {
    let src;
    if (/^\s*#/.test(line)) src = [el('span', { class: 'agent-c' }, line)];
    else if (/^\s*\[[^\]]+\]\s*$/.test(line)) src = [el('span', { class: 'agent-s' }, line)];
    else {
      const m = line.match(/^(\s*)(\S+)(\s+)(.*)$/);
      src = m ? [m[1], el('span', { class: 'agent-k' }, m[2]), m[3], m[4]] : [line];
    }
    out.push(el('span', { class: 'ln', 'aria-hidden': 'true' }, i + 1), el('span', { class: 'src' }, ...src));
  });
  agentFileEl.querySelector('#agent-config').replaceChildren(...out);
}

function agentSetupSkeleton() {
  const bar = (w, cls) => el('span', { class: 'skeleton' + (cls ? ' ' + cls : ''), style: 'width:' + w });
  $('agent-steps').replaceChildren(...['52%', '64%', '44%'].map((w) => el('li', { class: 'agent-step' },
    el('span', { class: 'agent-step__num' }), el('div', { class: 'agent-step__body' }, bar(w), bar('100%', 'agent-skel-well')))));
  agentFileEl.classList.add('hidden');
}

function agentSetupError(e) {
  agentSetupConfig = '';
  agentFileEl.classList.add('hidden');
  $('agent-steps').replaceChildren();
  $('agent-steps').classList.add('hidden');
  if (agentSetupErrEl) agentSetupErrEl.remove();
  agentSetupErrEl = el('div', { class: 'empty empty--compact', 'data-tone': 'danger', role: 'alert' },
    el('span', { class: 'empty__icon' }, icon('circle-alert')),
    el('div', { class: 'empty__title' }, 'Couldn’t build the agent setup'),
    el('p', { class: 'empty__text' }, e.message || 'The Signalith server did not respond.'),
    el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: loadAgentConfig }, icon('refresh-cw'), 'Try again')));
  $('agent-body').prepend(agentSetupErrEl);
}

// agentSetupCopy copies text. navigator.clipboard needs HTTPS or localhost,
// so plain-HTTP servers fall back to a hidden textarea.
async function agentSetupCopy(text, btn) {
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (_) {
    const ta = el('textarea', { class: 'sr-only', readonly: '', 'aria-hidden': 'true' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
    ta.remove();
    btn.focus();
  }
  const use = btn.querySelector('use');
  const label = btn.querySelector('span');
  use.setAttribute('href', ok ? '#i-check' : '#i-circle-alert');
  if (label) label.textContent = ok ? 'Copied' : 'Copy failed';
  btn.classList.toggle('is-copied', ok);
  $('agent-status').textContent = ok ? 'Copied.' : 'Couldn’t copy. Select the text and press Ctrl+C.';
  clearTimeout(btn.copyTimer);
  btn.copyTimer = setTimeout(() => {
    use.setAttribute('href', '#i-copy');
    if (label) label.textContent = 'Copy';
    btn.classList.remove('is-copied');
  }, 1800);
}
$('copy-config').addEventListener('click', () => agentSetupCopy(agentSetupConfig, $('copy-config')));
$('agent-download').addEventListener('click', () => {
  if (!agentSetupConfig) return;
  const url = URL.createObjectURL(new Blob([agentSetupConfig], { type: 'text/plain' }));
  const a = el('a', { href: url, download: 'fluent-bit.conf', class: 'hidden' });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// ---------- health ----------
// Live while the page is open: it re-reads api/health every 10 seconds and
// the components card says when it last updated.
const healthPageState = { data: null, key: '', at: 0, tried: 0, busy: false, failed: false, ticker: null };

async function loadHealth(quiet) {
  const st = healthPageState;
  if (!st.ticker) st.ticker = setInterval(healthPageTick, 1000);
  if (st.busy) return;
  if (!st.data && quiet !== true) healthPageSkeleton();
  st.busy = true;
  st.tried = Date.now();
  try {
    const h = await api('api/health');
    st.data = h;
    st.at = Date.now();
    st.failed = false;
    healthPageRender(h);
  } catch (e) {
    st.failed = true;
    if (st.data) healthPageFoot();
    else healthPageError(e);
  } finally {
    st.busy = false;
  }
}

// healthPageTick updates the "updated Ns ago" line and refreshes every 10
// seconds; it stops when another page is open.
function healthPageTick() {
  const st = healthPageState;
  if (currentPage !== 'health') {
    clearInterval(st.ticker);
    st.ticker = null;
    return;
  }
  if (document.hidden) return;
  healthPageFoot();
  if (st.data && Date.now() - st.tried >= 10000) loadHealth(true);
}

const healthPageNum = (n) => (n || 0).toLocaleString();

function healthPageAlert(tone, name, title, text) {
  const attrs = { class: 'alert', 'data-tone': tone };
  if (tone === 'danger') attrs.role = 'alert';
  return el('div', attrs, icon(name), el('div', {}, el('b', {}, title), text ? el('p', {}, text) : null));
}

function healthPageKpi(name, label, value, foot, tone) {
  const attrs = { class: 'card kpi' };
  if (tone) attrs['data-tone'] = tone;
  return el('div', attrs, el('div', { class: 'kpi__label' }, icon(name), label),
    el('div', { class: 'kpi__value num' }, value), el('div', { class: 'kpi__foot' }, foot));
}

// healthPageRow is one component: name and a mono meta line (URL, path,
// version), a pulse and state, and details.
function healthPageRow(name, title, meta, state, label, details) {
  const pulse = el('span', { class: 'pulse', 'aria-hidden': 'true' });
  if (state) pulse.dataset.state = state;
  return el('tr', {},
    el('td', { 'data-col': 'name' }, el('div', { class: 'hp-comp' }, el('span', { class: 'hp-comp__icon' }, icon(name)),
      el('div', { class: 'hp-comp__text' }, el('div', { class: 'cell-title' }, title), meta ? el('div', { class: 'hp-comp__meta mono', title: meta }, meta) : null))),
    el('td', { 'data-col': 'state' }, el('span', { class: 'hp-state' }, pulse, label)),
    el('td', { 'data-col': 'details', class: 'muted' }, ...[].concat(details)));
}

function healthPageRender(h) {
  const os = h.opensearch || {};
  const ing = h.ingest || {};
  const received = ing.received || 0;
  const indexed = ing.indexed || 0;
  const failed = ing.failed || 0;
  const lastAgo = ing.last_seen ? ago(ing.last_seen) : '';
  // Re-render only when something visible changed, so focus and hover survive the refresh.
  const key = JSON.stringify(h) + lastAgo;
  if (key === healthPageState.key) { healthPageFoot(); return; }
  healthPageState.key = key;

  const status = os.status || 'unknown';
  const alerts = [];
  // The alert says what it means for you; the OpenSearch row gives the cause.
  if (status === 'unreachable') alerts.push(healthPageAlert('danger', 'circle-alert', 'Signalith can’t reach OpenSearch.', 'Searches and new events fail until it is back.'));
  else if (status === 'red') alerts.push(healthPageAlert('danger', 'circle-alert', 'OpenSearch is red.', 'Some data cannot be searched or stored until it recovers.'));
  if (failed) alerts.push(healthPageAlert('warning', 'triangle-alert', `${healthPageNum(failed)} ${failed === 1 ? 'event' : 'events'} could not be stored.`, 'Counted since the server started. OpenSearch rejected them or did not answer.'));
  for (const w of h.warnings || []) {
    const cut = w.indexOf('. ');
    alerts.push(cut > 0 ? healthPageAlert('warning', 'triangle-alert', w.slice(0, cut + 1), w.slice(cut + 2)) : healthPageAlert('warning', 'triangle-alert', w));
  }

  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const kpis = el('div', { class: 'kpis hp-kpis' },
    healthPageKpi('inbox', 'Events received', healthPageNum(received), 'Since the server started'),
    healthPageKpi('database', 'Indexed', healthPageNum(indexed), received ? Math.floor((indexed / received) * 1000) / 10 + '% of received' : 'Stored in OpenSearch'),
    healthPageKpi('circle-x', 'Failed', healthPageNum(failed), failed ? 'Not stored' : 'None since start', failed ? 'warning' : ''),
    healthPageKpi('clock', 'Last event', lastAgo ? cap(lastAgo) : 'None', ing.last_seen ? new Date(ing.last_seen).toLocaleString() : 'No events since start'));

  const osRow = {
    green: ['', 'Healthy', 'Cluster status green.'],
    yellow: ['', 'Healthy', 'Cluster status yellow, which is normal on a single node: replicas have nowhere to go.'],
    red: ['down', 'Red', 'Some primary shards are not assigned.'],
    unreachable: ['down', 'Unreachable', os.error || 'No answer.'],
  }[status] || ['down', cap(status), os.error || 'Unexpected cluster status.'];
  // "Receiving" while an event arrived in the last 15 minutes; older is
  // shown as quiet (grey), not as a fault, since some sites are quiet.
  let ingRow;
  const recent = ing.last_seen && Date.now() - new Date(ing.last_seen).getTime() < 15 * 60 * 1000;
  if (failed) ingRow = ['warn', 'Some events failed', `${healthPageNum(failed)} of ${healthPageNum(received)} events since start could not be stored.`];
  else if (recent) ingRow = ['', 'Receiving', `Last event ${lastAgo}.`];
  else if (ing.last_seen) ingRow = ['idle', 'Quiet', `Last event ${lastAgo}.`];
  else ingRow = ['idle', 'Waiting', ['No events since the server started. ', el('a', { href: '#data', 'data-page': 'data' }, 'Add data')]];

  const table = el('table', { class: 'table hp-table' },
    el('thead', {}, el('tr', {}, el('th', { scope: 'col', 'data-col': 'name' }, 'Component'), el('th', { scope: 'col', 'data-col': 'state' }, 'Status'), el('th', { scope: 'col' }, 'Details'))),
    el('tbody', {},
      healthPageRow('database', 'OpenSearch', os.url || '', osRow[0], osRow[1], osRow[2]),
      healthPageRow('inbox', 'Ingest', 'api/ingest', ingRow[0], ingRow[1], ingRow[2]),
      healthPageRow('server', 'Signalith server', h.version ? 'Version ' + h.version : '', '', 'Running',
        h.config_file ? ['Config file ', el('code', {}, h.config_file)] : 'No config file.')));
  const card = el('div', { class: 'card' },
    el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Components'))),
    el('div', { class: 'table-wrap' }, table),
    el('div', { class: 'table-foot' }, el('span', { class: 'live', id: 'health-live' })));
  const box = $('health');
  box.removeAttribute('aria-busy');
  box.replaceChildren(...(alerts.length ? [el('div', { class: 'hp-alerts' }, ...alerts)] : []), kpis, card);
  healthPageFoot();
}

// healthPageFoot says when the numbers were last read.
function healthPageFoot() {
  const live = $('health-live');
  const st = healthPageState;
  if (!live || !st.at) return;
  const s = Math.max(0, Math.round((Date.now() - st.at) / 1000));
  const when = s < 5 ? 'just now' : s < 60 ? s + 's ago' : ago(st.at);
  const pulse = el('span', { class: 'pulse', 'aria-hidden': 'true' });
  if (st.failed) pulse.dataset.state = 'warn';
  live.replaceChildren(pulse, st.failed ? `Couldn’t refresh, retrying · updated ${when}` : `Live · updated ${when}`);
}

function healthPageSkeleton() {
  const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
  const kpi = () => el('div', { class: 'card kpi' }, bar('56%'), el('span', { class: 'skeleton hp-skel-value' }), bar('70%'));
  const row = () => el('tr', {}, el('td', {}, bar('60%')), el('td', {}, bar('50%')), el('td', {}, bar('80%')));
  const box = $('health');
  healthPageState.key = '';
  box.setAttribute('aria-busy', 'true');
  box.replaceChildren(el('div', { class: 'kpis hp-kpis' }, kpi(), kpi(), kpi(), kpi()),
    el('div', { class: 'card' }, el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Components'))),
      el('div', { class: 'table-wrap' }, el('table', { class: 'table hp-table', 'aria-busy': 'true' }, el('tbody', {}, row(), row(), row())))));
}

function healthPageError(e) {
  const box = $('health');
  healthPageState.key = '';
  box.removeAttribute('aria-busy');
  box.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger', role: 'alert' },
    el('span', { class: 'empty__icon' }, icon('circle-alert')),
    el('div', { class: 'empty__title' }, 'Couldn’t load health'),
    el('p', { class: 'empty__text' }, e.message || 'The Signalith server did not respond.'),
    el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => loadHealth() }, icon('refresh-cw'), 'Try again')))));
}

// ---------- startup ----------
(async function init() {
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
