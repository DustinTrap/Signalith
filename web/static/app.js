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

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  };
  const resp = await fetch(path, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const err = new Error(data.error || resp.statusText);
    err.pos = data.pos;
    throw err;
  }
  return data;
}

// ---------- navigation ----------
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => showPage(t.dataset.page)));
function showPage(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.page === name));
  document.querySelectorAll('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + name));
  if (name === 'data') loadAgentConfig();
  if (name === 'health') loadHealth();
  try { localStorage.setItem('signalith.page', name); } catch (_) { /* storage may be blocked */ }
}

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
    fields = await api('/api/fields?datamodel=' + encodeURIComponent(dm));
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
    const rows = await api('/api/fields/values?' + q);
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
const lang = { commands: ['stats', 'timechart', 'top', 'where', 'sort', 'head', 'table', 'rename'], functions: ['count', 'dc', 'sum', 'avg', 'min', 'max'] };
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
      const { query } = await api('/api/build', readSpec());
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
    const res = await api('/api/parse', { query: text });
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
    const res = await api('/api/search', { query, earliest: $('time').value === '0' ? '' : $('time').value });
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
  $('chart').replaceChildren();
  if (res.kind === 'timechart') renderChart(res);
  let cols = res.columns || [];
  if (res.kind === 'events') {
    // Events read best as time, a few key fields, then the raw text.
    const preferred = ['_time', 'host', 'sourcetype', 'action', 'user', 'src', 'dest', 'process_name', 'signature'];
    cols = preferred.filter((c) => cols.includes(c)).concat(cols.includes('_raw') ? ['_raw'] : []);
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
      return el('td', { class: cls, onclick: (ev) => showCellMenu(ev, c, v, res.kind) }, c === '_time' ? fmtTime(v) : fmtValue(v));
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
function showCellMenu(ev, col, value, kind) {
  hideCellMenu();
  if (value === null || value === undefined || col === '_raw' || col === 'count' || col === 'percent') return;
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
  menu.replaceChildren(...items);
  menu.style.left = ev.pageX + 'px';
  menu.style.top = ev.pageY + 'px';
  menu.classList.remove('hidden');
  ev.stopPropagation();
}
function hideCellMenu() { $('cell-menu').classList.add('hidden'); }
document.addEventListener('click', hideCellMenu);

// ---------- chart ----------
const palette = ['#1f6feb', '#2da44e', '#d97706', '#cf222e', '#8250df', '#0891b2', '#bf3989', '#57606a'];
function renderChart(res) {
  const rows = res.rows || [];
  const series = (res.columns || []).filter((c) => c !== '_time').slice(0, 8);
  if (!rows.length || !series.length) return;
  const W = 1000, H = 220, L = 50, R = 10, T = 12, B = 26;
  const max = Math.max(1, ...rows.flatMap((r) => series.map((s) => Number(r[s]) || 0)));
  const x = (i) => L + (rows.length === 1 ? (W - L - R) / 2 : i * (W - L - R) / (rows.length - 1));
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('preserveAspectRatio', 'none');
  const mk = (tag, attrs, text) => {
    const n = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text !== undefined) n.textContent = text;
    svg.append(n);
    return n;
  };
  for (let i = 0; i <= 4; i++) {
    const v = max * i / 4;
    mk('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: 'currentColor', 'stroke-opacity': '0.12' });
    mk('text', { x: L - 6, y: y(v) + 4, 'text-anchor': 'end', 'font-size': 11, fill: 'currentColor', 'fill-opacity': '0.6' }, Math.round(v).toLocaleString());
  }
  const step = Math.max(1, Math.ceil(rows.length / 8));
  rows.forEach((r, i) => {
    if (i % step) return;
    const d = new Date(r._time);
    mk('text', { x: x(i), y: H - 8, 'text-anchor': 'middle', 'font-size': 11, fill: 'currentColor', 'fill-opacity': '0.6' },
      isNaN(d) ? r._time : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));
  });
  series.forEach((s, si) => {
    const pts = rows.map((r, i) => `${x(i)},${y(Number(r[s]) || 0)}`).join(' ');
    mk('polyline', { points: pts, fill: 'none', stroke: palette[si % palette.length], 'stroke-width': 2, 'vector-effect': 'non-scaling-stroke' });
  });
  const legend = el('div', { class: 'legend' }, ...series.map((s, si) => el('span', {},
    el('span', { class: 'swatch', style: `background:${palette[si % palette.length]}` }), s)));
  $('chart').replaceChildren(svg, legend);
}

// ---------- explain ----------
$('explain').addEventListener('click', async () => {
  const box = $('explanation');
  try {
    const res = await api('/api/explain', { query: $('query').value || '*', earliest: $('time').value === '0' ? '' : $('time').value });
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
];
$('starter-list').replaceChildren(...starters.map(([title, q]) => el('li', {},
  el('a', { onclick: () => { setQuery(q); runSearch(); } }, title))));

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
    const a = await api('/api/agents/config?' + q);
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
    const h = await api('/api/health');
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
  try {
    const models = await api('/api/datamodels');
    $('b-datamodel').append(...models.map((m) => el('option', { value: m.name, title: m.description }, m.name.replace('_', ' '))));
  } catch (_) { /* shown on search */ }
  let saved = null, savedTime = null, page = null;
  try {
    saved = localStorage.getItem('signalith.query');
    savedTime = localStorage.getItem('signalith.time');
    page = localStorage.getItem('signalith.page');
  } catch (_) { /* ignore */ }
  if (savedTime) $('time').value = savedTime;
  if (saved) setQuery(saved);
  updateBuilderVisibility();
  loadFields();
  if (page && page !== 'search') showPage(page);
})();
