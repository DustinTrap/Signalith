// Findings queue, detection management and ATT&CK coverage.
'use strict';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const STATUS_LABEL = { new: 'New', in_progress: 'In progress', pending: 'Pending', resolved: 'Resolved', closed: 'Closed' };
const DISPOSITION_LABEL = {
  '': 'None', true_positive: 'True positive', benign_true_positive: 'Benign true positive',
  false_positive: 'False positive', undetermined: 'Undetermined',
};

// Other scripts add page hooks here.
const pageHooks = [];
function onPageShown(name) {
  if (name === 'findings') loadFindings();
  if (name === 'detections') loadDetections();
  if (name === 'coverage') loadCoverage();
  pageHooks.forEach((h) => h(name));
}

// fill replaces a node's children, skipping null placeholders.
const fill = (n, ...kids) => n.replaceChildren(...kids.filter((k) => k != null));
const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' };
// sevBadge and statusBadge draw the .sev and .status components keyed by the API value.
const sevBadge = (s) => el('span', { class: 'sev', 'data-sev': s }, SEVERITY_LABEL[s] || s);
const statusBadge = (s) => el('span', { class: 'status', 'data-status': s }, STATUS_LABEL[s] || s);
const techLink = (id) => el('a', {
  class: 'tech', target: '_blank', rel: 'noopener',
  href: 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/',
}, id);

// Opens the Search page on a query and time window.
function openSearch(query, earliest, latest) {
  let q = query || '*';
  const [search, rest] = splitPipes(q);
  const times = [];
  if (earliest) times.push('earliest=' + quoteValue(earliest));
  if (latest) times.push('latest=' + quoteValue(latest));
  if (times.length) q = search.trim() + ' ' + times.join(' ') + (rest ? '\n' + rest.trim() : '');
  setQuery(q);
  showPage('search');
  runSearch();
}

// ---------- findings ----------
let currentUser = '';
api('api/me').then((m) => { currentUser = m.user; }).catch(() => {});
let findingsList = [];
const selected = new Set();
let openFinding = null;

async function refreshOpenCount() {
  try {
    const s = await api('api/findings/summary');
    const b = $('open-count');
    const crit = s.by_urgency.critical || 0;
    b.textContent = s.open;
    b.classList.toggle('hidden', !s.open);
    // A small dot marks open critical findings; the count stays neutral.
    b.toggleAttribute('data-critical', crit > 0);
    b.title = crit ? `${s.open} open, ${crit} critical` : `${s.open} open`;
    return s;
  } catch (_) { return null; }
}

async function loadFindings() {
  const s = await refreshOpenCount();
  if (s) {
    $('f-summary').replaceChildren(el('span', { class: 'muted' }, `${s.open} open`),
      ...SEVERITIES.filter((sv) => s.by_urgency[sv]).map((sv) => el('button', {
        class: 'chip', title: 'Show open findings with ' + sv + ' urgency',
        onclick: () => { $('f-severity').value = ''; filterSeverity(sv); },
      }, sevBadge(sv), ' ' + s.by_urgency[sv])));
  }
  const p = new URLSearchParams();
  for (const [k, id] of [['status', 'f-status'], ['urgency', 'f-severity'], ['owner', 'f-owner'], ['q', 'f-text'], ['since', 'f-since']]) {
    const v = $(id).value.trim();
    if (v) p.set(k, v);
  }
  if (severityOverride) p.set('urgency', severityOverride);
  p.set('limit', '500');
  try {
    const res = await api('api/findings?' + p);
    findingsList = res.findings;
    renderFindings(res.total);
  } catch (e) {
    $('f-list').replaceChildren(el('div', { class: 'error', style: 'padding:12px' }, e.message));
  }
}
let severityOverride = '';
function filterSeverity(sv) { severityOverride = sv; loadFindings(); }

function renderFindings(total) {
  for (const id of [...selected]) if (!findingsList.some((f) => f.id === id)) selected.delete(id);
  updateBulk();
  if (!findingsList.length) {
    $('f-list').replaceChildren(el('div', { class: 'muted', style: 'padding:12px' },
      'No findings match. Detections raise findings when their query returns results; see the Detections page to enable or test them.'));
    return;
  }
  const all = el('input', { type: 'checkbox', title: 'Select all' });
  all.checked = findingsList.every((f) => selected.has(f.id));
  all.addEventListener('change', () => {
    findingsList.forEach((f) => (all.checked ? selected.add(f.id) : selected.delete(f.id)));
    renderFindings(total);
  });
  const rows = findingsList.map((f) => {
    const cb = el('input', { type: 'checkbox' });
    cb.checked = selected.has(f.id);
    cb.addEventListener('click', (ev) => ev.stopPropagation());
    cb.addEventListener('change', () => { cb.checked ? selected.add(f.id) : selected.delete(f.id); updateBulk(); });
    const ents = Object.entries(f.entities || {}).slice(0, 3).map(([k, v]) => el('span', { class: 'entity' }, `${k}: ${v}`));
    if (f.case_id) ents.unshift(el('span', { class: 'entity case-chip', title: 'Part of case ' + f.case_id }, 'in case'));
    return el('tr', { class: openFinding === f.id ? 'sel' : '', onclick: () => showFinding(f.id) },
      el('td', {}, cb),
      el('td', { title: new Date(f.created).toLocaleString() }, ago(f.created)),
      el('td', { title: (f.urgency || f.severity) !== f.severity ? `Severity ${f.severity}, adjusted for asset or user priority` : '' }, sevBadge(f.urgency || f.severity)),
      el('td', { class: 'wrap' }, el('div', {}, f.title), el('div', { class: 'entities' }, ...ents)),
      el('td', {}, statusBadge(f.status)),
      el('td', {}, f.owner || el('span', { class: 'muted' }, 'unassigned')),
      el('td', { class: 'muted' }, f.detection_id));
  });
  const table = el('table', { class: 'grid findings' },
    el('thead', {}, el('tr', {}, el('th', {}, all), el('th', {}, 'Created'), el('th', {}, 'Urgency'), el('th', {}, 'Finding'),
      el('th', {}, 'Status'), el('th', {}, 'Owner'), el('th', {}, 'Detection'))),
    el('tbody', {}, ...rows));
  const note = total > findingsList.length ? el('div', { class: 'muted', style: 'padding:6px 10px' }, `Showing ${findingsList.length} of ${total}; narrow the filters to see the rest.`) : null;
  $('f-list').replaceChildren(table, note || '');
}

function updateBulk() {
  $('f-bulk').classList.toggle('hidden', selected.size === 0);
  $('f-bulk-count').textContent = `${selected.size} selected`;
}

$('f-bulk-apply').addEventListener('click', async () => {
  const update = {};
  if ($('f-bulk-status').value) update.status = $('f-bulk-status').value;
  if ($('f-bulk-disposition').value) update.disposition = $('f-bulk-disposition').value;
  if ($('f-bulk-owner').value.trim()) update.owner = $('f-bulk-owner').value.trim();
  if ($('f-bulk-comment').value.trim()) update.comment = $('f-bulk-comment').value.trim();
  if (!Object.keys(update).length) return;
  try {
    const res = await api('api/findings/bulk', { ids: [...selected], update });
    const failed = Object.keys(res.failed || {}).length;
    if (failed) alert(`${failed} finding(s) could not be updated.`);
    selected.clear();
    for (const id of ['f-bulk-status', 'f-bulk-disposition', 'f-bulk-owner', 'f-bulk-comment']) $(id).value = '';
    loadFindings();
    if (openFinding) showFinding(openFinding);
  } catch (e) { alert(e.message); }
});

for (const id of ['f-status', 'f-severity', 'f-since']) $(id).addEventListener('change', () => { severityOverride = ''; loadFindings(); });
for (const id of ['f-owner', 'f-text']) $(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') loadFindings(); });
$('f-refresh').addEventListener('click', loadFindings);

function select(id, options, value) {
  const s = el('select', { id });
  for (const [v, label] of options) {
    const o = el('option', { value: v }, label);
    if (v === value) o.selected = true;
    s.append(o);
  }
  return s;
}

async function showFinding(id) {
  openFinding = id;
  document.querySelectorAll('table.findings tbody tr').forEach((tr, i) => tr.classList.toggle('sel', findingsList[i] && findingsList[i].id === id));
  const box = $('f-detail');
  box.classList.remove('hidden');
  box.replaceChildren(el('div', { class: 'muted' }, 'Loading...'));
  let data;
  try { data = await api('api/findings/' + encodeURIComponent(id)); } catch (e) {
    box.replaceChildren(el('div', { class: 'error' }, e.message));
    return;
  }
  const f = data.finding;
  const d = data.detection;
  const status = select('fd-status', Object.entries(STATUS_LABEL), f.status);
  const severity = select('fd-severity', SEVERITIES.map((s) => [s, s]), f.severity);
  const disposition = select('fd-disposition', Object.entries(DISPOSITION_LABEL), f.disposition || '');
  const owner = el('input', { id: 'fd-owner', type: 'text', value: f.owner || '', placeholder: 'unassigned' });
  const comment = el('textarea', { id: 'fd-comment', rows: 3, placeholder: 'Add a note: what you checked, what you found' });
  const save = el('button', { class: 'primary', onclick: async () => {
    const u = { status: status.value, severity: severity.value, disposition: disposition.value, owner: owner.value.trim(), comment: comment.value };
    try {
      await api('api/findings/' + encodeURIComponent(f.id), u, 'PATCH');
      await loadFindings();
      showFinding(f.id);
    } catch (e) { alert(e.message); }
  } }, 'Save');
  const mine = el('button', { onclick: () => { owner.value = currentUser; if (status.value === 'new') status.value = 'in_progress'; } }, 'Assign to me');

  const resultRows = Object.entries(f.result || {}).filter(([k]) => k !== '_raw').map(([k, v]) => el('tr', {}, el('th', {}, k), el('td', {}, k === '_time' ? fmtTime(v) : fmtValue(v))));
  const raw = f.result && f.result._raw ? el('pre', { class: 'code' }, f.result._raw) : null;

  const timeline = [
    ...(f.comments || []).map((c) => ({ t: c.time, node: el('li', {}, el('b', {}, c.author), ' ', el('span', { class: 'muted' }, new Date(c.time).toLocaleString()), el('div', { class: 'comment' }, c.text)) })),
    ...(f.history || []).map((h) => ({ t: h.time, node: el('li', { class: 'muted' }, `${h.author} changed ${h.field} from ${h.from ? (STATUS_LABEL[h.from] || h.from) : 'empty'} to ${STATUS_LABEL[h.to] || h.to || 'empty'} · ${new Date(h.time).toLocaleString()}`) })),
  ].sort((a, b) => new Date(b.t) - new Date(a.t)).map((x) => x.node);

  fill(box, 
    el('div', { class: 'detail-head' }, el('h3', {}, f.title), el('button', { class: 'link', onclick: () => { box.classList.add('hidden'); openFinding = null; } }, 'Close')),
    el('div', { class: 'meta' }, sevBadge(f.urgency || f.severity),
      (f.urgency || f.severity) !== f.severity ? el('span', { class: 'muted small' }, `urgency (severity ${f.severity}, adjusted for priority)`) : null,
      statusBadge(f.status), el('span', { class: 'muted' }, 'Created ' + new Date(f.created).toLocaleString()), el('span', { class: 'muted' }, 'ID ' + f.id),
      f.case_id ? el('a', { class: 'link', onclick: () => openCase(f.case_id) }, 'Case ' + f.case_id) : null),
    f.description ? el('p', {}, f.description) : null,
    d && d.guidance ? el('div', { class: 'notice' }, el('b', {}, 'How to triage: '), d.guidance) : null,
    (f.mitre || []).length ? el('div', { class: 'meta' }, 'ATT&CK: ', ...f.mitre.map(techLink)) : null,
    el('div', { class: 'form-grid' },
      el('label', {}, 'Status', status), el('label', {}, 'Owner', owner),
      el('label', {}, 'Severity', severity), el('label', {}, 'Disposition', disposition)),
    comment,
    el('div', { class: 'row' }, save, mine,
      el('button', { onclick: () => openSearch(f.query, f.earliest, f.latest), title: f.query }, 'View contributing events'),
      f.case_id ? el('button', { onclick: () => openCase(f.case_id), title: 'This finding is part of case ' + f.case_id }, 'Open case')
        : el('button', { onclick: () => addFindingsToCase([f.id], f.title), title: 'Group this finding into an investigation' }, 'Add to case')),
    Object.keys(f.entities || {}).length ? el('h4', {}, 'Entities') : null,
    el('table', { class: 'kv' }, el('tbody', {}, ...Object.entries(f.entities || {}).filter(([k]) => k !== 'risk_object_type').map(([k, v]) => el('tr', {},
      el('th', {}, k),
      el('td', {}, el('a', {
        class: 'entity link', title: 'Search all events for ' + k + '=' + v,
        onclick: () => openSearch((k === 'risk_object' ? 'datamodel=Risk ' : '') + k + '=' + quoteValue(String(v)), '-7d'),
      }, String(v)), ' ', (typeof contextLine === 'function' && f.context) ? contextLine(f.context[k]) : null))))),
    el('h4', {}, 'What the detection found'),
    el('table', { class: 'kv' }, el('tbody', {}, ...resultRows)),
    raw,
    el('h4', {}, 'Activity'),
    timeline.length ? el('ul', { class: 'timeline' }, ...timeline) : el('div', { class: 'muted' }, 'No activity yet.'));
}

// ---------- detections ----------
let detections = [];
let schedulerOn = true;

async function loadDetections() {
  try {
    const res = await api('api/detections');
    detections = res.detections;
    schedulerOn = res.scheduler;
    $('d-scheduler-note').classList.toggle('hidden', schedulerOn);
    renderDetections();
  } catch (e) {
    $('d-list').replaceChildren(el('div', { class: 'error', style: 'padding:12px' }, e.message));
  }
}

function renderDetections() {
  const term = $('d-filter').value.trim().toLowerCase();
  const show = $('d-show').value;
  const list = detections.filter((d) => {
    if (show === 'enabled' && !d.enabled) return false;
    if (show === 'disabled' && d.enabled) return false;
    if (show === 'custom' && d.source === 'builtin') return false;
    if (show === 'errors' && !d.state.last_error) return false;
    if (!term) return true;
    return [d.id, d.title, d.description, ...(d.mitre || []), ...(d.tags || [])].join(' ').toLowerCase().includes(term);
  });
  const enabled = detections.filter((d) => d.enabled).length;
  const rows = list.map((d) => {
    const toggle = el('input', { type: 'checkbox', title: d.enabled ? 'Disable' : 'Enable' });
    toggle.checked = d.enabled;
    toggle.addEventListener('click', (ev) => ev.stopPropagation());
    toggle.addEventListener('change', async () => {
      try {
        await api('api/detections/' + encodeURIComponent(d.id), { ...d, enabled: toggle.checked }, 'PUT');
        loadDetections();
      } catch (e) { alert(e.message); toggle.checked = !toggle.checked; }
    });
    const st = d.state || {};
    const last = st.last_run ? el('span', { title: new Date(st.last_run).toLocaleString() }, ago(st.last_run)) : el('span', { class: 'muted' }, 'not yet');
    return el('tr', { onclick: () => editDetection(d) },
      el('td', {}, toggle),
      el('td', { class: 'wrap' }, el('div', {}, d.title), el('div', { class: 'muted small' }, d.id + (d.source !== 'builtin' ? ' · ' + d.source : ''))),
      el('td', {}, sevBadge(d.severity)),
      el('td', {}, ...(d.mitre || []).map((t) => el('span', { class: 'tech' }, t))),
      el('td', {}, d.risk ? el('span', { title: 'Adds ' + d.risk.score + ' risk to ' + d.risk.objects.map((o) => o.field).join(', ') }, '+' + d.risk.score) : '',
        d.risk && d.risk.only ? el('div', { class: 'muted small' }, 'risk only') : null),
      el('td', {}, `every ${d.schedule}`, el('div', { class: 'muted small' }, `looks back ${d.lookback}`)),
      el('td', {}, last, st.last_error ? el('div', { class: 'bad small', title: st.last_error }, 'failed') : null),
      el('td', { class: 'num' }, st.last_run ? String(st.last_findings) : ''));
  });
  $('d-list').replaceChildren(
    el('div', { class: 'muted', style: 'padding:6px 10px' }, `${enabled} of ${detections.length} detections enabled`),
    el('table', { class: 'grid' },
      el('thead', {}, el('tr', {}, el('th', {}, 'On'), el('th', {}, 'Detection'), el('th', {}, 'Severity'), el('th', {}, 'ATT&CK'), el('th', {}, 'Risk'),
        el('th', {}, 'Schedule'), el('th', {}, 'Last run'), el('th', {}, 'Findings'))),
      el('tbody', {}, ...rows)));
}
$('d-filter').addEventListener('input', renderDetections);
$('d-show').addEventListener('change', renderDetections);

const blankDetection = () => ({
  id: '', title: '', description: '', query: '', schedule: '5m', lookback: '15m', severity: 'medium',
  mitre: [], throttle: { fields: [], window: '1h' }, enabled: true, guidance: '', tags: [], source: 'new',
});

function field(label, input, hint) {
  return el('label', {}, label, input, hint ? el('span', { class: 'hint' }, hint) : null);
}

function editDetection(d, opts = {}) {
  const isNew = d.source === 'new';
  const box = $('d-editor');
  const inp = (key, value, attrs = {}) => el('input', { type: 'text', 'data-k': key, value: value == null ? '' : value, ...attrs });
  const id = inp('id', d.id, isNew ? { placeholder: 'lowercase-with-dashes' } : { readonly: 'readonly' });
  const title = inp('title', d.title, { placeholder: 'Brute force from $src$' });
  const desc = el('textarea', { rows: 2 }); desc.value = d.description || '';
  const query = el('textarea', { rows: 5, spellcheck: 'false', class: 'mono' }); query.value = d.query || '';
  const schedule = inp('schedule', d.schedule);
  const lookback = inp('lookback', d.lookback);
  const severity = select('de-severity', SEVERITIES.map((s) => [s, s]), d.severity);
  const mitre = inp('mitre', (d.mitre || []).join(', '), { placeholder: 'T1110.003, T1078' });
  const tfields = inp('tfields', ((d.throttle || {}).fields || []).join(', '), { placeholder: 'src, user' });
  const twindow = inp('twindow', (d.throttle || {}).window || '', { placeholder: '1h' });
  const guidance = el('textarea', { rows: 2 }); guidance.value = d.guidance || '';
  const enabled = el('input', { type: 'checkbox' }); enabled.checked = !!d.enabled;
  const risk = d.risk || null;
  const riskScore = inp('riskscore', risk ? risk.score : '', { placeholder: 'none', type: 'number', min: 1, max: 1000 });
  const riskObjs = inp('riskobjs', risk ? risk.objects.map((o) => o.field + ':' + o.type).join(', ') : '', { placeholder: 'user:user, dest:system' });
  const riskOnly = el('input', { type: 'checkbox' }); riskOnly.checked = !!(risk && risk.only);
  const out = el('div', { class: 'preview' });
  const err = el('div', { class: 'error hidden' });
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  const read = () => ({
    id: id.value.trim(), title: title.value.trim(), description: desc.value.trim(), query: query.value.trim(),
    schedule: schedule.value.trim(), lookback: lookback.value.trim(), severity: severity.value,
    mitre: list(mitre.value), throttle: { fields: list(tfields.value), window: twindow.value.trim() },
    enabled: enabled.checked, guidance: guidance.value.trim(), tags: d.tags || [],
    risk: riskScore.value.trim() ? {
      score: parseInt(riskScore.value, 10),
      objects: list(riskObjs.value).map((x) => { const [field, type] = x.split(':').map((s) => s.trim()); return { field, type: type || 'other' }; }),
      only: riskOnly.checked,
    } : undefined,
  });
  const fail = (e) => {
    err.textContent = e.problems ? 'Please fix:\n- ' + e.problems.join('\n- ') : e.message;
    err.classList.remove('hidden');
  };
  const ok = () => err.classList.add('hidden');

  const test = el('button', { onclick: async () => {
    ok();
    out.replaceChildren(el('div', { class: 'muted' }, 'Running over the last ' + (lookback.value || '?') + '...'));
    try {
      const res = await api('api/detections/test', read());
      const r = res.result;
      const n = (r.rows || []).length;
      fill(out, 
        el('div', {}, n ? el('b', {}, `${n} finding${n === 1 ? '' : 's'} would be raised`) : 'No results in the lookback window, so no findings would be raised.',
          el('span', { class: 'muted' }, ` (${r.took_ms} ms, before throttling)`)),
        n ? el('ul', {}, ...res.titles.map((t) => el('li', {}, t))) : null);
    } catch (e) { out.replaceChildren(); fail(e); }
  } }, 'Test');
  const saveBtn = el('button', { class: 'primary', onclick: async () => {
    ok();
    try {
      const body = read();
      if (isNew) await api('api/detections', body);
      else await api('api/detections/' + encodeURIComponent(body.id), body, 'PUT');
      box.classList.add('hidden');
      loadDetections();
    } catch (e) { fail(e); }
  } }, isNew ? 'Create' : 'Save');
  const runNow = isNew ? null : el('button', { title: 'Run once now and raise findings', onclick: async () => {
    ok();
    out.replaceChildren(el('div', { class: 'muted' }, 'Running...'));
    try {
      const res = await api('api/detections/' + encodeURIComponent(d.id) + '/run', {});
      out.replaceChildren(el('div', {}, `${res.results} result(s), ${res.findings.length} new finding(s), ${res.throttled} throttled.`,
        res.findings.length ? el('button', { class: 'link', onclick: () => showPage('findings') }, ' Open findings') : null));
      loadDetections();
    } catch (e) { out.replaceChildren(); fail(e); }
  } }, 'Run now');
  const del = isNew || d.source === 'builtin' ? null : el('button', { class: 'danger', onclick: async () => {
    const msg = d.source === 'override' ? 'Discard your changes and go back to the built-in version?' : 'Delete this detection?';
    if (!confirm(msg)) return;
    try {
      await api('api/detections/' + encodeURIComponent(d.id), undefined, 'DELETE');
      box.classList.add('hidden');
      loadDetections();
    } catch (e) { fail(e); }
  } }, d.source === 'override' ? 'Revert to built-in' : 'Delete');
  const yaml = isNew ? null : el('a', { class: 'button-link', href: 'api/detections/' + encodeURIComponent(d.id) + '/yaml' }, 'Download YAML');

  fill(box, 
    el('div', { class: 'detail-head' }, el('h3', {}, isNew ? 'New detection' : 'Edit detection'),
      el('button', { class: 'link', onclick: () => box.classList.add('hidden') }, 'Close')),
    opts.warnings && opts.warnings.length ? el('div', { class: 'notice' }, el('b', {}, 'Review before enabling: '), el('ul', {}, ...opts.warnings.map((w) => el('li', {}, w)))) : null,
    d.source === 'builtin' ? el('div', { class: 'muted small' }, 'Built-in detection. Saving changes keeps your version and leaves the built-in available to revert to.') : null,
    el('div', { class: 'form-grid' },
      field('Title', title, 'Use $field$ to insert values from the result, like $src$'), field('ID', id),
      field('Severity', severity), field('ATT&CK techniques', mitre, 'Comma-separated IDs'),
      field('Run every', schedule, 'For example 5m, 1h, 1d'), field('Search back', lookback, 'Time window each run searches'),
      field('Group repeats by', tfields, 'One finding per value of these fields'), field('For', twindow, 'How long to suppress repeats'),
      field('Risk score', riskScore, 'Adds risk to each object in a result; empty for none'),
      field('Risk objects', riskObjs, 'field:type pairs; type is user, system or other')),
    el('label', { class: 'inline' }, riskOnly, ' Risk only: record risk without raising a finding per result'),
    field('Query', query, 'Each result row becomes a finding. Do not set earliest= or latest=; "Search back" sets the window.'),
    field('Description', desc), field('Triage guidance', guidance),
    el('label', { class: 'inline' }, enabled, ' Enabled'),
    err,
    el('div', { class: 'row' }, saveBtn, test, runNow,
      el('button', { onclick: () => openSearch(query.value, '-' + (lookback.value || '24h')) }, 'Open in Search'), yaml, del),
    out);
  box.classList.remove('hidden');
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

$('d-new').addEventListener('click', () => editDetection(blankDetection()));
$('d-sigma').addEventListener('click', () => { $('d-sigma-box').classList.remove('hidden'); $('d-sigma-text').focus(); });
$('d-sigma-cancel').addEventListener('click', () => $('d-sigma-box').classList.add('hidden'));
$('d-sigma-convert').addEventListener('click', async () => {
  $('d-sigma-error').classList.add('hidden');
  try {
    const res = await api('api/detections/sigma', { rule: $('d-sigma-text').value });
    $('d-sigma-box').classList.add('hidden');
    $('d-sigma-text').value = '';
    editDetection({ ...res.detection, source: 'new' }, { warnings: res.warnings });
  } catch (e) {
    $('d-sigma-error').textContent = e.problems ? e.problems.join('\n') : e.message;
    $('d-sigma-error').classList.remove('hidden');
  }
});

// "Save as detection" on the Search page.
$('save-detection').addEventListener('click', () => {
  const text = $('query').value.trim();
  const d = blankDetection();
  // The time picker becomes the lookback; earliest/latest in the text are dropped.
  const [search, rest] = splitPipes(text);
  const cleaned = search.replace(/\b(earliest|latest)=("[^"]*"|\S+)/g, '').replace(/\s+/g, ' ').trim();
  d.query = cleaned + (rest ? '\n' + rest.trim() : '');
  const t = $('time').value;
  if (t && t !== '0') d.lookback = t.replace(/^-/, '');
  d.enabled = false;
  showPage('detections');
  editDetection(d);
});

// ---------- coverage ----------
let coverage = null;
async function loadCoverage() {
  try {
    coverage = await api('api/coverage');
    renderCoverage();
  } catch (e) {
    $('c-matrix').replaceChildren(el('div', { class: 'error' }, e.message));
  }
}

function renderCoverage() {
  const c = coverage;
  const pct = (n) => c.summary.techniques ? Math.round(100 * n / c.summary.techniques) + '%' : '0%';
  $('c-summary').replaceChildren(
    el('div', { class: 'card' }, el('h4', {}, 'Techniques with an enabled detection'), el('div', { class: 'big ok' }, `${c.summary.enabled}`), el('div', { class: 'muted' }, `${pct(c.summary.enabled)} of ${c.summary.techniques} ATT&CK v${c.version} techniques`)),
    el('div', { class: 'card' }, el('h4', {}, 'More you could turn on'), el('div', { class: 'big warn' }, `${c.summary.available}`), el('div', { class: 'muted' }, 'Techniques covered only by disabled detections')),
    el('div', { class: 'card' }, el('h4', {}, 'Close a gap'), el('div', { class: 'muted' }, 'Write a detection from any search with "Save as detection", or import a Sigma rule on the Detections page.')));
  const only = $('c-only').checked;
  const cols = c.tactics.map((t) => {
    const techs = t.techniques.filter((x) => !only || (x.enabled || x.disabled));
    return el('div', { class: 'tactic' },
      el('div', { class: 'tactic-head' }, el('div', {}, t.name), el('div', { class: 'muted small' }, `${t.covered}/${t.techniques.length}`)),
      ...techs.map((x) => {
        const cls = x.enabled ? 'enabled' : x.disabled ? 'available' : '';
        const ids = [...(x.enabled || []), ...(x.disabled || [])];
        const tip = `${x.id} ${x.name}` + (ids.length ? '\nDetections: ' + ids.join(', ') : '') + ((x.subs || []).length ? '\nSub-techniques: ' + x.subs.join(', ') : '');
        return el('div', {
          class: 'cov-cell ' + cls, title: tip,
          onclick: () => {
            if (ids.length) { showPage('detections'); $('d-filter').value = x.id; $('d-show').value = ''; renderDetections(); }
            else window.open('https://attack.mitre.org/techniques/' + x.id + '/', '_blank', 'noopener');
          },
        }, el('span', { class: 'tid' }, x.id), ' ', x.name, ids.length > 1 ? el('span', { class: 'n' }, String(ids.length)) : null);
      }));
  });
  $('c-matrix').replaceChildren(...cols);
}
$('c-only').addEventListener('change', () => coverage && renderCoverage());

refreshOpenCount();
setInterval(refreshOpenCount, 60000);
