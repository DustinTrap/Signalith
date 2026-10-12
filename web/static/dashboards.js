// Dashboards: the built-in security posture summary and custom dashboards
// of query panels.
'use strict';

const URGENCIES = ['critical', 'high', 'medium', 'low', 'informational'];
const urgencyColor = (u) => `var(--urg-${URGENCIES.includes(u) ? u : 'informational'})`;
const VIZ_LABEL = { single: 'Single value', table: 'Table', bar: 'Bar chart', line: 'Line chart', area: 'Area chart' };
const WIDTH_LABEL = { third: 'Third', half: 'Half', full: 'Full width' };
const RANGE_LABEL = { '15m': '15 minutes', '1h': 'hour', '4h': '4 hours', '24h': '24 hours', '7d': '7 days', '30d': '30 days' };

const dash = {
  list: [], // [{id, title, builtin, ...}]
  current: 'posture',
  def: null, // the selected custom dashboard
  editing: false, // reorder and delete controls shown
  seq: 0, // ignores responses to superseded loads
  timer: null,
  loaded: false,
};

const rangeText = (r) => 'previous ' + (RANGE_LABEL[r] || r);

// fmtDuration renders seconds as 45s, 12m, 3.5h or 2.1d.
function fmtDuration(sec) {
  if (sec == null || !isFinite(sec)) return '–';
  if (sec < 60) return Math.round(sec) + 's';
  if (sec < 3600) return Math.round(sec / 60) + 'm';
  if (sec < 86400) return (sec / 3600).toFixed(sec < 36000 ? 1 : 0) + 'h';
  return (sec / 86400).toFixed(1) + 'd';
}

// deltaLine describes a change from the previous period, colored by
// whether up is good.
function deltaLine(cur, prev, better, range, unit) {
  if (prev == null || cur == null) return null;
  const fmt = unit === 'seconds' ? fmtDuration : fmtCompact;
  let text, dir = Math.sign(cur - prev);
  if (dir === 0) text = 'No change';
  else if (prev === 0) text = '▲ up from 0';
  else {
    const pct = Math.abs((cur - prev) / prev * 100);
    text = (dir > 0 ? '▲ ' : '▼ ') + (pct >= 10 ? Math.round(pct) : pct.toFixed(1)) + '%';
  }
  let cls = 'flat';
  if (dir !== 0 && better) cls = (dir > 0) === (better === 'up') ? 'good' : 'bad';
  return el('div', { class: 'delta ' + cls, title: `${rangeText(range)}: ${fmt(prev)}` }, text, el('span', { class: 'muted' }, ` vs ${rangeText(range)} (${fmt(prev)})`));
}

// card is one dashboard tile with a title and optional actions.
function dcard(title, width, body, actions = []) {
  return el('div', { class: 'dcard w-' + (width || 'half') },
    el('div', { class: 'dcard-head' }, el('h3', {}, title), actions.length ? el('div', { class: 'dcard-actions' }, ...actions) : null),
    body);
}
// showDetection opens the Detections page filtered to one rule.
function showDetection(id) {
  $('d-filter').value = id;
  $('d-show').value = '';
  showPage('detections');
}
const linkButton = (text, onclick, title) => el('button', { class: 'link small', type: 'button', onclick, title: title || text }, text);
const searchLink = (q, earliest) => linkButton('Open in Search', () => openSearch(q, earliest), 'Run this query on the Search page');

// ---------- loading ----------
async function loadDashboardList() {
  let res;
  try {
    res = await api('api/dashboards');
  } catch (e) {
    res = { dashboards: [{ id: 'posture', title: 'Security posture', builtin: true }], error: e.message };
  }
  dash.list = res.dashboards || [];
  const sel = $('db-select');
  sel.replaceChildren(...dash.list.map((d) => el('option', { value: d.id }, d.title + (d.builtin ? ' (built in)' : ''))));
  if (!dash.list.some((d) => d.id === dash.current)) dash.current = 'posture';
  sel.value = dash.current;
  const notes = [];
  if (res.error) notes.push(el('div', {}, res.error));
  for (const p of res.problems || []) notes.push(el('div', {}, `${p.file}: ${p.error}`));
  fill($('db-problems'), notes.length ? el('b', {}, 'Some dashboard files could not be loaded:') : null, ...notes);
  $('db-problems').classList.toggle('hidden', !notes.length);
}

async function showDashboard(id) {
  dash.current = id;
  dash.editing = false;
  $('db-select').value = id;
  $('db-editor').classList.add('hidden');
  const custom = id !== 'posture';
  $('db-tools').classList.toggle('hidden', !custom);
  $('db-edit').textContent = 'Edit dashboard';
  if (!custom) {
    dash.def = null;
    $('db-desc').textContent = 'Findings and triage times, what is firing, risk, ATT&CK tactics seen, data volume and detection health. Each number compares with the previous period of the same length.';
    setAutoRefresh();
    return loadPosture();
  }
  const seq = ++dash.seq;
  try {
    dash.def = await api('api/dashboards/' + encodeURIComponent(id));
  } catch (e) {
    if (seq === dash.seq) $('db-body').replaceChildren(el('div', { class: 'error dcard w-full' }, e.message));
    return;
  }
  if (seq !== dash.seq) return;
  $('db-desc').textContent = dash.def.description || '';
  $('db-yaml').href = 'api/dashboards/' + encodeURIComponent(id) + '/yaml';
  setRange(dash.def.time_range);
  if (dash.def.refresh) setRefresh(dash.def.refresh);
  setAutoRefresh();
  return runDashboard();
}

function setRange(r) {
  if (!r) return;
  const sel = $('db-range');
  if (![...sel.options].some((o) => o.value === r)) sel.append(el('option', { value: r }, 'Last ' + (RANGE_LABEL[r] || r)));
  sel.value = r;
}

function setRefresh(r) {
  const m = /^(\d+)\s*([smhd])$/.exec(r || '');
  if (!m) return;
  const sec = Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2]];
  const sel = $('db-refresh');
  if (![...sel.options].some((o) => o.value === String(sec))) sel.append(el('option', { value: String(sec) }, 'Every ' + r));
  sel.value = String(sec);
}

function reloadDashboard() {
  return dash.current === 'posture' ? loadPosture() : runDashboard();
}

function stamp() {
  $('db-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
}

// ---------- security posture ----------
async function loadPosture() {
  const seq = ++dash.seq;
  const range = $('db-range').value;
  const body = $('db-body');
  if (!body.children.length || body.dataset.view !== 'posture') {
    releaseCharts(body);
    body.dataset.view = 'posture';
    body.replaceChildren(el('div', { class: 'dcard w-full muted' }, 'Loading the security posture...'));
  }
  let rep;
  try {
    rep = await api('api/posture?range=' + encodeURIComponent(range));
  } catch (e) {
    if (seq === dash.seq) body.replaceChildren(el('div', { class: 'dcard w-full error' }, e.message));
    return;
  }
  if (seq !== dash.seq) return;
  renderPosture(rep);
  stamp();
}

function sectionError(rep, ...names) {
  const errs = names.map((n) => (rep.errors || {})[n]).filter(Boolean);
  return errs.length ? el('div', { class: 'error' }, errs.join('\n')) : null;
}

function renderPosture(rep) {
  const body = $('db-body');
  releaseCharts(body);
  const range = rep.range;
  const earliest = '-' + range;
  const q = rep.queries || {};

  const kpis = el('div', { class: 'kpis' }, ...rep.indicators.map((ind) => {
    const v = ind.unit === 'seconds' ? fmtDuration(ind.value) : ind.value == null ? '–' : fmtCompact(ind.value);
    let extra = null;
    if (ind.id === 'open_findings' && !ind.error) {
      const chips = URGENCIES.filter((u) => rep.open_by_urgency[u]).map((u) => el('span', { class: 'sev', 'data-sev': u, title: `${rep.open_by_urgency[u]} open ${u}` }, `${rep.open_by_urgency[u]} ${u === 'informational' ? 'info' : u}`));
      extra = el('div', { class: 'kpi-chips' }, ...(chips.length ? chips : [el('span', { class: 'muted small' }, 'Queue is clear')]));
    }
    const tile = el('div', { class: 'kpi', title: ind.help || '' },
      el('div', { class: 'kpi-label' }, ind.label),
      el('div', { class: 'kpi-value' }, ind.error ? '–' : v),
      ind.error ? el('div', { class: 'error small' }, ind.error) : deltaLine(ind.value, ind.previous, ind.better, range, ind.unit),
      ind.value == null && !ind.error && ind.unit === 'seconds' ? el('div', { class: 'muted small' }, 'Nothing in this period') : null,
      extra);
    if (ind.id === 'open_findings' || ind.id === 'new_findings') {
      tile.classList.add('clickable');
      tile.addEventListener('click', () => showPage('findings'));
    }
    return tile;
  }));

  // Findings over time by urgency.
  const fot = el('div', {});
  if (rep.findings_over_time) {
    drawTimeChart(fot, rep.findings_over_time, { area: true, legend: true, colorFor: urgencyColor, label: 'Findings over time by urgency', emptyText: 'No findings were raised in this period.' });
  }

  // Top detections.
  const det = el('div', {});
  drawBarChart(det, rep.top_detections.map((d) => ({
    label: d.title, value: d.findings + d.risk_events,
    note: [d.findings ? `${d.findings} finding${d.findings === 1 ? '' : 's'}` : '', d.risk_events ? `${d.risk_events} risk event${d.risk_events === 1 ? '' : 's'}` : ''].filter(Boolean).join(' · '),
    onclick: () => showDetection(d.id),
  })), { label: 'Top detections firing', emptyText: 'No detection fired in this period.' });

  // Top risk objects.
  const risk = el('div', {});
  drawBarChart(risk, (rep.top_risk_objects || []).map((r) => ({
    label: `${r.risk_object} (${r.risk_object_type})`, value: r.risk_score, color: Number(r.risk_score) >= 100 ? 'var(--danger)' : 'var(--series-3)',
    onclick: () => { showPage('risk'); showRiskObject(r.risk_object, r.risk_object_type); },
  })), { label: 'Top risk objects', emptyText: 'No risk in this period.' });

  // ATT&CK tactics.
  const tac = el('div', {});
  drawBarChart(tac, (rep.tactics || []).map((t) => ({
    label: t.name, value: t.findings + t.risk_events, color: 'var(--series-5)',
    note: [t.findings ? `${t.findings} finding${t.findings === 1 ? '' : 's'}` : '', t.risk_events ? `${t.risk_events} risk event${t.risk_events === 1 ? '' : 's'}` : ''].filter(Boolean).join(' · '),
  })), { label: 'ATT&CK tactics seen', emptyText: 'No ATT&CK-mapped activity in this period.' });

  const dm = el('div', {});
  if (rep.events_by_datamodel) drawTimeChart(dm, rep.events_by_datamodel, { area: true, legend: true, label: 'Events by data model' });
  const st = el('div', {});
  if (rep.events_by_sourcetype) drawTimeChart(st, rep.events_by_sourcetype, { legend: true, label: 'Events by source type' });

  body.dataset.view = 'posture';
  fill(body,
    el('div', { class: 'w-full' }, kpis),
    rep.findings_truncated ? el('div', { class: 'notice w-full' }, 'There are more findings in this period than one request returns, so finding counts are approximate.') : null,
    dcard('Findings over time by urgency', 'full', el('div', {}, sectionError(rep, 'findings'), fot), [linkButton('Open queue', () => showPage('findings'))]),
    dcard('Top detections firing', 'half', el('div', {}, sectionError(rep, 'findings', 'top_detections'), det)),
    dcard('Top risk objects', 'half', el('div', {}, sectionError(rep, 'risk_objects'), risk), [searchLink(q.risk_objects, earliest)]),
    dcard('ATT&CK tactics seen', 'half', el('div', {}, sectionError(rep, 'tactics'), tac), [linkButton('Coverage', () => showPage('coverage'))]),
    dcard('Detection health', 'half', healthView(rep)),
    dcard('Events by data model', 'half', el('div', {}, sectionError(rep, 'events_by_datamodel'), dm), [searchLink(q.events_by_datamodel, earliest)]),
    dcard('Events by source type', 'half', el('div', {}, sectionError(rep, 'events_by_sourcetype'), st), [searchLink(q.events_by_sourcetype, earliest)]));
}

function healthView(rep) {
  const h = rep.health;
  if (!h) return sectionError(rep, 'health') || el('div', { class: 'muted' }, 'Not available.');
  const stat = (label, value, cls, title) => el('div', { class: 'hstat', title: title || '' }, el('div', { class: 'hstat-value ' + (cls || '') }, value), el('div', { class: 'muted small' }, label));
  const erroring = h.erroring || [], silent = h.silent || [], stale = h.stale_sources || [];
  const list = (title, items, render, open) => (items.length ? el('details', open ? { open: '' } : {}, el('summary', {}, title), el('ul', { class: 'hlist' }, ...items.map(render))) : null);
  const detLink = (d) => el('a', { class: 'link', onclick: () => showDetection(d.id) }, d.title || d.id);
  return el('div', {},
    sectionError(rep, 'health', 'sources'),
    h.scheduler_on ? null : el('div', { class: 'notice small' }, 'The scheduler is off on this server, so detections only run when you click Run now.'),
    el('div', { class: 'hstats' },
      stat('enabled detections', `${h.enabled} of ${h.total}`, '', h.not_run ? `${h.not_run} enabled detections have not run since the server started` : ''),
      stat('erroring', String(erroring.length), erroring.length ? 'bad' : 'ok'),
      stat(`no match in ${h.silent_window}`, String(silent.length), silent.length ? 'warn' : 'ok', 'Enabled detections with no findings and no risk events. They may need tuning, or the data they need may be missing.'),
      stat('data sources stopped', `${stale.length} of ${h.sources}`, stale.length ? 'warn' : 'ok', `Hosts and source types seen in the last ${h.source_lookback} with nothing in the last ${h.stale_after}`)),
    list(`Erroring detections (${erroring.length})`, erroring, (d) => el('li', {}, detLink(d), el('div', { class: 'error small' }, d.error)), true),
    list(`Stopped sending for more than ${h.stale_after} (${stale.length})`, stale, (s) => el('li', {},
      el('span', {}, s.host), el('span', { class: 'muted' }, ' · ' + s.sourcetype + ' · last event ' + ago(s.last_seen))), true),
    list(`No match in ${h.silent_window} (${silent.length})`, silent, (d) => el('li', {}, detLink(d))));
}

// ---------- custom dashboards ----------
function panelQuery(p, pr) {
  return [p.query, pr && pr.earliest ? pr.earliest : '-' + $('db-range').value];
}

function renderPanels() {
  const body = $('db-body');
  releaseCharts(body);
  body.dataset.view = dash.current;
  const d = dash.def;
  if (!d.panels.length) {
    body.replaceChildren(el('div', { class: 'dcard w-full empty' },
      el('h3', {}, 'This dashboard has no panels yet'),
      el('p', { class: 'muted' }, 'A panel is a query and a chart. Ask a question in plain English, write a query, or run a search on the Search page and click Add to dashboard.'),
      el('div', { class: 'row' }, el('button', { class: 'primary', onclick: () => openPanelEditor({}) }, 'Add panel'))));
    return [];
  }
  return d.panels.map((p, i) => {
    const content = el('div', { class: 'panel-body' }, el('div', { class: 'muted' }, 'Loading...'));
    const actions = [
      linkButton('Search', () => openSearch(...panelQuery(p, content._result)), 'Open this panel\'s query on the Search page'),
      linkButton('Edit', () => openPanelEditor({ index: i, panel: p })),
    ];
    if (dash.editing) {
      actions.push(
        el('button', { class: 'link small', title: 'Move earlier', 'aria-label': 'Move earlier', onclick: () => movePanel(i, -1) }, '↑'),
        el('button', { class: 'link small', title: 'Move later', 'aria-label': 'Move later', onclick: () => movePanel(i, 1) }, '↓'),
        el('button', { class: 'link small danger-text', onclick: () => removePanel(i) }, 'Remove'));
    }
    const card = dcard(p.title, p.width, content, actions);
    card.dataset.index = i;
    body.append(card);
    return content;
  });
}

async function runDashboard() {
  const d = dash.def;
  if (!d) return;
  const seq = ++dash.seq;
  $('db-body').replaceChildren();
  const boxes = renderPanels();
  if (!boxes.length) return;
  let res;
  try {
    res = await api('api/dashboards/' + encodeURIComponent(d.id) + '/run', { range: $('db-range').value });
  } catch (e) {
    if (seq === dash.seq) boxes.forEach((b) => b.replaceChildren(el('div', { class: 'error' }, e.message)));
    return;
  }
  if (seq !== dash.seq) return;
  res.panels.forEach((pr, i) => {
    if (boxes[i]) {
      boxes[i]._result = pr;
      renderPanelBody(boxes[i], d.panels[i], pr, res.range);
    }
  });
  stamp();
}

// columnsOf splits a result's columns into labels and numbers using the
// first row.
function columnsOf(res) {
  const row = (res.rows || [])[0] || {};
  const cols = (res.columns || []).filter((c) => c !== '_raw');
  const nums = cols.filter((c) => typeof row[c] === 'number' && c !== 'percent');
  return { labels: cols.filter((c) => !nums.includes(c) && c !== 'percent' && c !== '_time'), nums };
}

function renderPanelBody(box, p, pr, range) {
  releaseCharts(box);
  if (pr.error) {
    box.replaceChildren(el('div', { class: 'error' }, pr.error),
      el('div', { class: 'muted small' }, 'The other panels are not affected. ', linkButton('Fix it in Search', () => openSearch(p.query, pr.earliest))));
    return;
  }
  const res = pr.result || { rows: [], columns: [] };
  const rows = res.rows || [];
  const notes = [];
  if (res.truncated) notes.push(el('div', { class: 'muted small' }, 'Showing the first ' + rows.length + ' rows.'));
  switch (p.viz) {
    case 'single': {
      const delta = pr.previous != null ? deltaLine(Number(pr.value) || 0, Number(pr.previous) || 0, '', range) : null;
      fill(box, el('div', { class: 'single-value' }, pr.value == null ? '–' : fmtCompact(pr.value)),
        el('div', { class: 'muted small' }, pr.field || ''), delta,
        pr.compare_note ? el('div', { class: 'muted small' }, pr.compare_note) : null);
      return;
    }
    case 'line':
    case 'area':
      if (res.kind === 'timechart') {
        drawTimeChart(box, res, { area: p.viz === 'area', label: p.title });
        return;
      }
      notes.push(el('div', { class: 'muted small' }, 'Line and area charts need a query ending in | timechart, for example | timechart count by action. Showing bars instead.'));
    // fall through
    case 'bar': {
      if (res.kind === 'timechart') {
        // Total each series over the period.
        const items = (res.columns || []).filter((c) => c !== '_time').map((c) => ({ label: c, value: rows.reduce((a, r) => a + (Number(r[c]) || 0), 0) }));
        const holder = el('div', {});
        drawBarChart(holder, items, { label: p.title });
        box.replaceChildren(holder, ...notes);
        return;
      }
      const { labels, nums } = columnsOf(res);
      const vcol = pr.field && nums.includes(pr.field) ? pr.field : p.field && nums.includes(p.field) ? p.field : nums[0];
      const holder = el('div', {});
      if (!vcol) {
        notes.push(el('div', { class: 'muted small' }, 'Bars need a number column; try | stats count by <field>.'));
        renderPanelTable(holder, res);
      } else {
        drawBarChart(holder, rows.slice(0, 20).map((r) => ({
          label: labels.length ? labels.map((c) => fmtValue(r[c])).join(' · ') : vcol, value: Number(r[vcol]) || 0,
        })), { label: p.title, emptyText: 'No results in this time range.' });
      }
      box.replaceChildren(holder, ...notes);
      return;
    }
    default: {
      const holder = el('div', {});
      renderPanelTable(holder, res);
      box.replaceChildren(holder, ...notes);
    }
  }
}

function renderPanelTable(box, res) {
  const rows = res.rows || [];
  if (!rows.length) {
    box.replaceChildren(el('div', { class: 'muted' }, 'No results in this time range.'));
    return;
  }
  let cols = res.columns || [];
  if (res.kind === 'events') {
    const preferred = ['_time', 'host', 'sourcetype', 'action', 'user', 'src', 'dest', 'process_name', 'signature'];
    cols = preferred.filter((c) => cols.includes(c));
  }
  cols = cols.slice(0, 8);
  box.replaceChildren(el('div', { class: 'results panel-table' }, el('table', { class: 'grid' },
    el('thead', {}, el('tr', {}, ...cols.map((c) => el('th', {}, c)))),
    el('tbody', {}, ...rows.slice(0, 100).map((r) => el('tr', {}, ...cols.map((c) => {
      const v = r[c];
      return el('td', { class: typeof v === 'number' ? 'num' : '' }, c === '_time' ? fmtTime(v) : fmtValue(v));
    })))))));
}

// ---------- saving ----------
async function saveDashboard(d) {
  const saved = await api('api/dashboards/' + encodeURIComponent(d.id), d, 'PUT');
  dash.def = saved;
  return saved;
}

async function movePanel(i, dir) {
  const d = structuredClone(dash.def);
  const j = i + dir;
  if (j < 0 || j >= d.panels.length) return;
  [d.panels[i], d.panels[j]] = [d.panels[j], d.panels[i]];
  try { await saveDashboard(d); } catch (e) { alert(e.message); return; }
  runDashboard();
}

async function removePanel(i) {
  if (!confirm(`Remove the panel "${dash.def.panels[i].title}"?`)) return;
  const d = structuredClone(dash.def);
  d.panels.splice(i, 1);
  try { await saveDashboard(d); } catch (e) { alert(e.message); return; }
  runDashboard();
}

// ---------- dashboard details editor ----------
function rangeSelect(value) {
  const opts = ['15m', '1h', '4h', '24h', '7d', '30d'];
  if (value && !opts.includes(value)) opts.push(value);
  const s = el('select', { name: 'time_range' }, ...opts.map((o) => el('option', { value: o }, 'Last ' + (RANGE_LABEL[o] || o))));
  s.value = value || '24h';
  return s;
}

function refreshSelect(value) {
  const opts = [['', 'Off'], ['1m', 'Every minute'], ['5m', 'Every 5 minutes'], ['15m', 'Every 15 minutes'], ['1h', 'Every hour']];
  if (value && !opts.some((o) => o[0] === value)) opts.push([value, 'Every ' + value]);
  const s = el('select', { name: 'refresh' }, ...opts.map(([v, t]) => el('option', { value: v }, t)));
  s.value = value || '';
  return s;
}

function problemsBox(e) {
  return el('div', { class: 'error' }, e.problems ? el('ul', {}, ...e.problems.map((p) => el('li', {}, p))) : e.message);
}

function openDashboardEditor(isNew) {
  const box = $('db-editor');
  const d = isNew ? { title: '', description: '', time_range: $('db-range').value, refresh: '', panels: [] } : dash.def;
  const title = el('input', { type: 'text', value: d.title || '', placeholder: 'For example: Authentication overview', maxlength: '200' });
  const desc = el('input', { type: 'text', value: d.description || '', placeholder: 'Optional: what this dashboard is for' });
  const range = rangeSelect(d.time_range);
  const refresh = refreshSelect(d.refresh);
  const msg = el('div', {});
  const save = async () => {
    const body = { ...structuredClone(d), title: title.value.trim(), description: desc.value.trim(), time_range: range.value, refresh: refresh.value };
    try {
      const saved = isNew ? await api('api/dashboards', body) : await saveDashboard(body);
      box.classList.add('hidden');
      await loadDashboardList();
      await showDashboard(saved.id);
      if (isNew) openPanelEditor({});
    } catch (e) {
      msg.replaceChildren(problemsBox(e));
    }
  };
  fill(box,
    el('h3', {}, isNew ? 'New dashboard' : 'Dashboard settings'),
    el('div', { class: 'form-grid' },
      el('label', {}, 'Title', title),
      el('label', {}, 'Description', desc),
      el('label', {}, 'Default time range', range),
      el('label', {}, 'Auto-refresh', refresh)),
    isNew ? el('p', { class: 'muted small' }, 'Dashboards are saved as YAML files in the dashboards folder on the server (dashboards.dir), so you can also keep them in Git.') : null,
    msg,
    el('div', { class: 'row' },
      el('button', { class: 'primary', onclick: save }, isNew ? 'Create dashboard' : 'Save'),
      el('button', { onclick: () => box.classList.add('hidden') }, 'Cancel'),
      isNew ? null : el('button', { class: 'danger', onclick: deleteDashboard }, 'Delete dashboard')));
  box.classList.remove('hidden');
  title.focus();
}

async function deleteDashboard() {
  if (!confirm(`Delete the dashboard "${dash.def.title}"? Its YAML file is removed from the server.`)) return;
  try { await api('api/dashboards/' + encodeURIComponent(dash.def.id), undefined, 'DELETE'); } catch (e) { alert(e.message); return; }
  $('db-editor').classList.add('hidden');
  await loadDashboardList();
  showDashboard('posture');
}

// ---------- panel editor ----------
// suggestViz mirrors the server: timechart is a line, stats without "by" a
// single value, other stats and top bars, anything else a table.
function suggestViz(q) {
  const cmds = q.split('|').slice(1).map((c) => c.trim());
  let viz = 'table';
  for (const c of cmds) {
    if (/^timechart\b/i.test(c)) return 'line';
    if (/^stats\b/i.test(c)) viz = /\bby\b/i.test(c) ? 'bar' : 'single';
    else if (/^top\b/i.test(c)) viz = 'bar';
    else if (/^table\b/i.test(c)) viz = 'table';
  }
  return viz;
}

// defaultTitle names a panel from its query when the user gave no title:
// "Authentication: timechart count by action".
function defaultTitle(q) {
  const parts = q.split('|').map((x) => x.trim()).filter(Boolean);
  const dm = (/datamodel\s*=\s*"?([\w-]+)/i.exec(parts[0] || '') || [])[1];
  const last = parts.length > 1 ? parts[parts.length - 1] : parts[0] || 'Panel';
  const t = (dm && parts.length > 1 ? dm.replace('_', ' ') + ': ' : '') + last;
  return t.length > 80 ? t.slice(0, 79) + '…' : t;
}

// openPanelEditor edits panel `index` of the current dashboard, or adds a
// new one. With target, the user also picks which dashboard to add it to
// (from the Search page).
async function openPanelEditor({ index, panel, pickTarget }) {
  const box = $('db-editor');
  const p = { title: '', query: '', viz: '', width: '', field: '', compare: false, ...(panel || {}) };
  const isNew = index == null;
  let vizTouched = !!p.viz;
  const custom = dash.list.filter((d) => !d.builtin);

  const target = el('select', {}, ...custom.map((d) => el('option', { value: d.id }, d.title)), el('option', { value: '' }, 'New dashboard...'));
  if (dash.def && custom.some((d) => d.id === dash.def.id)) target.value = dash.def.id;
  else target.value = custom.length ? custom[0].id : '';
  const newTitle = el('input', { type: 'text', placeholder: 'New dashboard title' });
  const syncTarget = () => newTitle.classList.toggle('hidden', target.value !== '');
  target.addEventListener('change', syncTarget);

  const ask = el('input', { type: 'search', placeholder: 'Ask in plain English, for example: failed logins by source ip' });
  const askMsg = el('div', { class: 'muted small' });
  const title = el('input', { type: 'text', value: p.title, placeholder: 'Panel title (optional)' });
  const qtext = el('textarea', { rows: '4', spellcheck: 'false', class: 'mono', placeholder: 'datamodel=Authentication action=failure | stats count by src' });
  qtext.value = p.query;
  const viz = el('select', {}, ...Object.entries(VIZ_LABEL).map(([v, t]) => el('option', { value: v }, t)));
  viz.value = p.viz || suggestViz(p.query);
  const width = el('select', {}, el('option', { value: '' }, 'Automatic'), ...Object.entries(WIDTH_LABEL).map(([v, t]) => el('option', { value: v }, t)));
  width.value = p.width || '';
  const field = el('input', { type: 'text', value: p.field || '', placeholder: 'first number', list: 'field-names' });
  const compare = el('input', { type: 'checkbox' });
  compare.checked = !!p.compare;
  const singleOpts = el('div', { class: 'form-grid' },
    el('label', {}, 'Value column', field),
    el('label', { class: 'inline' }, compare, ' Compare with the previous period'));
  const syncViz = () => singleOpts.classList.toggle('hidden', viz.value !== 'single');
  viz.addEventListener('change', () => { vizTouched = true; syncViz(); });
  qtext.addEventListener('input', () => { if (!vizTouched) { viz.value = suggestViz(qtext.value); syncViz(); } });
  const preview = el('div', { class: 'dash-grid preview-grid' });
  const msg = el('div', {});

  const current = () => ({
    title: title.value.trim() || defaultTitle(qtext.value), query: qtext.value.trim(), viz: viz.value, width: width.value,
    field: viz.value === 'single' ? field.value.trim() : '', compare: viz.value === 'single' && compare.checked,
  });

  const doAsk = async (ev) => {
    if (ev) ev.preventDefault();
    const question = ask.value.trim();
    if (!question) return;
    askMsg.textContent = 'Writing the query...';
    try {
      const res = await api('api/ask', { question, mode: 'auto' });
      qtext.value = res.query;
      if (!title.value.trim()) title.value = question.charAt(0).toUpperCase() + question.slice(1);
      if (!vizTouched) { viz.value = suggestViz(res.query); syncViz(); }
      const unknown = (res.unknown || []).length ? ' Not understood: ' + res.unknown.join(', ') + '.' : '';
      askMsg.textContent = (res.source === 'ai' ? 'Written by the AI model; check it.' : 'Check the query below, then preview.') + unknown + (res.ai_error ? ' (AI model failed: ' + res.ai_error + ')' : '');
      doPreview();
    } catch (e) {
      askMsg.textContent = e.message;
    }
  };

  const doPreview = async () => {
    const pn = current();
    if (!pn.query) { msg.replaceChildren(el('div', { class: 'error' }, 'Write a query first.')); return; }
    msg.replaceChildren();
    const content = el('div', { class: 'panel-body' }, el('div', { class: 'muted' }, 'Running...'));
    releaseCharts(preview);
    preview.replaceChildren(dcard(pn.title || 'Preview', pn.width || 'full', content));
    try {
      const res = await api('api/panels/run', { range: $('db-range').value, panel: pn });
      preview.firstChild.className = 'dcard w-' + (res.panel.width || 'full');
      renderPanelBody(content, res.panel, res.result, res.range);
    } catch (e) {
      content.replaceChildren(el('div', { class: 'error' }, e.message));
    }
  };

  const doSave = async () => {
    const pn = current();
    try {
      let id = dash.def && !pickTarget ? dash.def.id : target.value;
      if (pickTarget && !id) {
        const created = await api('api/dashboards', { title: newTitle.value.trim() || pn.title || 'My dashboard', time_range: $('db-range').value, panels: [pn] });
        id = created.id;
      } else if (isNew) {
        await api('api/dashboards/' + encodeURIComponent(id) + '/panels', pn);
      } else {
        const d = structuredClone(dash.def);
        d.panels[index] = pn;
        await saveDashboard(d);
      }
      box.classList.add('hidden');
      await loadDashboardList();
      await showDashboard(id);
    } catch (e) {
      msg.replaceChildren(problemsBox(e));
    }
  };

  fill(box,
    el('h3', {}, isNew ? 'Add a panel' : 'Edit panel'),
    pickTarget ? el('div', { class: 'form-grid' }, el('label', {}, 'Dashboard', target), el('label', { class: 'nt' }, ' ', newTitle)) : null,
    el('form', { class: 'ask-row', onsubmit: doAsk }, ask, el('button', { type: 'submit' }, 'Write query')),
    askMsg,
    el('label', {}, 'Query', qtext),
    el('div', { class: 'form-grid' },
      el('label', {}, 'Title', title),
      el('label', {}, 'Show as', viz),
      el('label', {}, 'Width', width)),
    singleOpts,
    msg,
    el('div', { class: 'row' },
      el('button', { class: 'primary', onclick: doSave }, isNew ? 'Add to dashboard' : 'Save panel'),
      el('button', { onclick: doPreview }, 'Preview'),
      el('button', { onclick: () => { box.classList.add('hidden'); releaseCharts(preview); } }, 'Cancel'),
      el('span', { class: 'muted small' }, 'Preview uses the time range above.')),
    preview);
  syncTarget();
  syncViz();
  box.classList.remove('hidden');
  box.scrollIntoView({ block: 'nearest' });
  (p.query ? title : ask).focus();
  if (p.query) doPreview();
}

// ---------- auto-refresh ----------
function setAutoRefresh() {
  clearInterval(dash.timer);
  const sec = Number($('db-refresh').value);
  if (!sec) return;
  dash.timer = setInterval(() => {
    if (document.hidden || !$('page-dashboards').classList.contains('active')) return;
    reloadDashboard();
  }, sec * 1000);
}

// ---------- wiring ----------
$('db-select').addEventListener('change', () => showDashboard($('db-select').value));
$('db-range').addEventListener('change', () => {
  try { localStorage.setItem('signalith.dashRange', $('db-range').value); } catch (_) { /* ignore */ }
  reloadDashboard();
});
$('db-refresh').addEventListener('change', () => {
  try { localStorage.setItem('signalith.dashRefresh', $('db-refresh').value); } catch (_) { /* ignore */ }
  setAutoRefresh();
});
$('db-reload').addEventListener('click', reloadDashboard);
$('db-new').addEventListener('click', () => openDashboardEditor(true));
$('db-add').addEventListener('click', () => openPanelEditor({}));
$('db-edit').addEventListener('click', () => {
  dash.editing = !dash.editing;
  $('db-edit').textContent = dash.editing ? 'Done editing' : 'Edit dashboard';
  if (dash.editing) openDashboardEditor(false); else $('db-editor').classList.add('hidden');
  runDashboard();
});

// "Add to dashboard" on the Search page.
$('add-to-dashboard').addEventListener('click', async () => {
  const query = $('query').value.trim();
  if (!query) { showQueryError(new Error('Write or ask for a query first.')); return; }
  const title = lastAsk && lastAsk.query.trim() === query ? lastAsk.question.charAt(0).toUpperCase() + lastAsk.question.slice(1) : '';
  showPage('dashboards');
  await dashReady;
  openPanelEditor({ panel: { query, title }, pickTarget: true });
});

let dashReady = null;
pageHooks.push((name) => {
  if (name !== 'dashboards') return;
  if (!dash.loaded) {
    dash.loaded = true;
    try {
      const r = localStorage.getItem('signalith.dashRange');
      const f = localStorage.getItem('signalith.dashRefresh');
      if (r) setRange(r);
      if (f) $('db-refresh').value = f;
    } catch (_) { /* ignore */ }
    dashReady = loadDashboardList().then(() => showDashboard(dash.current));
  } else {
    dashReady = reloadDashboard();
  }
});
