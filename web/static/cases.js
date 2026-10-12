// Investigations: cases that group findings with the analyst's notes, the
// searches they ran and the events they pinned.
'use strict';

const caseState = { list: [], open: null, data: null };

async function refreshCaseCount() {
  try {
    const s = await api('/api/cases/summary');
    const b = $('case-count');
    b.textContent = s.open;
    b.classList.toggle('hidden', !s.open);
  } catch (_) { /* cases may be off on this server */ }
}
refreshCaseCount();

let toastTimer = null;
function toast(msg, action) {
  const t = $('toast');
  fill(t, el('span', {}, msg),
    action ? el('button', { class: 'link', onclick: () => { t.classList.add('hidden'); action.run(); } }, action.label) : null);
  t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 8000);
}

// ---------- case list ----------
pageHooks.push((name) => {
  if (name !== 'cases') return;
  if (caseState.open) showCase(caseState.open);
  else loadCases();
});

function showCaseList() {
  caseState.open = null;
  caseState.data = null;
  $('c-view').classList.add('hidden');
  $('c-list-view').classList.remove('hidden');
  loadCases();
}

function openCase(id) {
  caseState.open = id;
  if ($('page-cases').classList.contains('active')) showCase(id);
  else showPage('cases');
}

async function loadCases() {
  refreshCaseCount();
  const p = new URLSearchParams({ limit: '500' });
  if ($('c-status').value) p.set('status', $('c-status').value);
  if ($('c-owner').value === 'me' && currentUser) p.set('owner', currentUser);
  if ($('c-text').value.trim()) p.set('q', $('c-text').value.trim());
  try {
    const res = await api('/api/cases?' + p);
    caseState.list = res.cases;
    renderCases(res.total);
  } catch (e) {
    $('c-list').replaceChildren(el('div', { class: 'error', style: 'padding:12px' }, e.message));
  }
}

function renderCases(total) {
  const list = caseState.list;
  if (!list.length) {
    $('c-list').replaceChildren(el('div', { class: 'muted', style: 'padding:12px' },
      'No cases match. Start one with New case, or select findings on the Findings page and choose Add to case.'));
    return;
  }
  const rows = list.map((c) => el('tr', { onclick: () => openCase(c.id) },
    el('td', {}, sevBadge(c.severity)),
    el('td', { class: 'wrap' }, el('div', {}, c.title),
      el('div', { class: 'entities' }, el('span', { class: 'muted small' }, c.id),
        ...(c.entities || []).slice(0, 4).map((e) => el('span', { class: 'entity' }, `${e.field}: ${e.value}`)))),
    el('td', {}, statusBadge(c.status)),
    el('td', {}, c.owner || el('span', { class: 'muted' }, 'unassigned')),
    el('td', { class: 'num' }, String((c.findings || []).length)),
    el('td', { title: new Date(c.updated).toLocaleString() }, ago(c.updated)),
    el('td', { title: new Date(c.created).toLocaleString() }, ago(c.created))));
  const note = total > list.length ? el('div', { class: 'muted', style: 'padding:6px 10px' }, `Showing ${list.length} of ${total}; narrow the filters to see the rest.`) : null;
  fill($('c-list'), el('table', { class: 'grid' },
    el('thead', {}, el('tr', {}, ...['Severity', 'Case', 'Status', 'Owner', 'Findings', 'Updated', 'Opened'].map((h) => el('th', {}, h)))),
    el('tbody', {}, ...rows)), note);
}

$('c-refresh').addEventListener('click', loadCases);
for (const id of ['c-status', 'c-owner']) $(id).addEventListener('change', loadCases);
$('c-text').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadCases(); });
$('c-new').addEventListener('click', async () => {
  const id = await pickCase({ only: 'new', heading: 'New case' });
  if (id) openCase(id);
});

// ---------- one case ----------
async function showCase(id) {
  caseState.open = id;
  $('c-list-view').classList.add('hidden');
  const box = $('c-view');
  box.classList.remove('hidden');
  if (!caseState.data || caseState.data.case.id !== id) box.replaceChildren(el('div', { class: 'muted' }, 'Loading...'));
  try {
    caseState.data = await api('/api/cases/' + encodeURIComponent(id));
  } catch (e) {
    fill(box, el('button', { class: 'link', onclick: showCaseList }, '← All cases'), el('div', { class: 'error' }, e.message));
    return;
  }
  renderCase();
}

// caseCall sends a change and redraws the case with the server's answer.
async function caseCall(path, body, method) {
  const c = caseState.data.case;
  try {
    const res = await api('/api/cases/' + encodeURIComponent(c.id) + path, body, method);
    refreshCaseCount();
    await showCase(c.id);
    return res;
  } catch (e) {
    alert(e.message);
    return null;
  }
}

function renderCase() {
  const { case: c, findings: linked, missing_findings: missing } = caseState.data;
  const box = $('c-view');

  const title = el('input', { type: 'text', value: c.title, class: 'case-title', 'aria-label': 'Case title' });
  const status = select('cd-status', Object.entries(STATUS_LABEL), c.status);
  const severity = select('cd-severity', SEVERITIES.map((s) => [s, s]), c.severity);
  const owner = el('input', { type: 'text', value: c.owner || '', placeholder: 'unassigned' });
  const desc = el('textarea', { rows: 3, placeholder: 'What is this investigation about?' });
  desc.value = c.description || '';
  const resolution = el('textarea', { rows: 2, placeholder: 'What happened and what was done about it' });
  resolution.value = c.resolution || '';
  const openLinked = (linked || []).filter((f) => !['resolved', 'closed'].includes(f.status));
  const closeFindings = el('input', { type: 'checkbox' });
  closeFindings.checked = openLinked.length > 0;
  const disposition = select('cd-disposition', Object.entries(DISPOSITION_LABEL), '');
  const closing = el('div', { class: 'case-closing' },
    el('label', {}, 'Resolution', resolution),
    openLinked.length ? el('div', { class: 'row' },
      el('label', { class: 'inline' }, closeFindings, ` Also set its ${openLinked.length} open finding${openLinked.length === 1 ? '' : 's'} to this status, as`),
      disposition) : null);
  const syncClosing = () => closing.classList.toggle('hidden', !['resolved', 'closed'].includes(status.value));
  status.addEventListener('change', syncClosing);
  syncClosing();

  const save = el('button', { class: 'primary', onclick: async () => {
    const body = { title: title.value, description: desc.value, status: status.value, severity: severity.value, owner: owner.value.trim(), resolution: resolution.value };
    if (['resolved', 'closed'].includes(status.value) && openLinked.length && closeFindings.checked) {
      body.close_findings = true;
      if (disposition.value) body.disposition = disposition.value;
    }
    const res = await caseCall('', body, 'PATCH');
    if (res && res.findings_closed) toast(`Case saved and ${res.findings_closed} finding${res.findings_closed === 1 ? '' : 's'} closed.`);
  } }, 'Save');
  const mine = el('button', { onclick: () => { owner.value = currentUser; if (status.value === 'new') status.value = 'in_progress'; syncClosing(); } }, 'Assign to me');

  // Timeline: newest first, with field changes mixed in.
  const items = [
    ...(c.entries || []).map((e) => ({ t: e.time, node: entryNode(c, e, linked) })),
    ...(c.history || []).filter((h) => h.field !== 'created').map((h) => ({ t: h.time, node: el('li', { class: 'muted small' }, historyText(h)) })),
  ].sort((a, b) => new Date(b.t) - new Date(a.t)).map((x) => x.node);
  items.push(el('li', { class: 'muted small' }, `Opened by ${c.created_by || 'unknown'} · ${new Date(c.created).toLocaleString()}`));

  const note = el('textarea', { rows: 3, placeholder: 'Add a note: what you checked, what you found, what is next' });
  const addNote = el('button', { class: 'primary', onclick: async () => {
    if (!note.value.trim()) return;
    if (await caseCall('/entries', { kind: 'note', text: note.value })) note.value = '';
  } }, 'Add note');

  const sq = el('textarea', { rows: 2, class: 'mono', spellcheck: 'false', placeholder: 'datamodel=Authentication user=bob | stats count by src' });
  const ents = c.entities || [];
  if (ents.length) sq.value = ents.slice(0, 3).map((e) => e.field + '=' + quoteValue(e.value)).join(' OR ');
  const stime = select('cd-stime', [['-1h', 'Last hour'], ['-24h', 'Last 24 hours'], ['-7d', 'Last 7 days'], ['-30d', 'Last 30 days'], ['', 'All time']], '-24h');
  const sNote = el('input', { type: 'text', placeholder: 'Why you ran it (optional)' });
  const addSearch = el('button', { onclick: async (ev) => {
    if (!sq.value.trim()) return;
    const btn = ev.target;
    btn.disabled = true;
    btn.textContent = 'Running...';
    if (!await caseCall('/entries', { kind: 'search', query: sq.value.trim(), earliest: stime.value, text: sNote.value })) {
      btn.disabled = false;
      btn.textContent = 'Run and add';
    }
  } }, 'Run and add');

  const entField = el('input', { type: 'text', placeholder: 'field, e.g. user', list: 'field-names', class: 'ent-field' });
  const entValue = el('input', { type: 'text', placeholder: 'value' });
  const addEnt = el('button', { onclick: () => {
    if (entField.value.trim() && entValue.value.trim()) caseCall('/entities', { field: entField.value.trim(), value: entValue.value.trim() });
  } }, 'Add');

  const findingRows = (linked || []).map((f) => el('li', {},
    el('div', { class: 'row tight' }, sevBadge(f.urgency || f.severity), statusBadge(f.status),
      el('a', { class: 'link', onclick: () => openFindingFromCase(f.id) }, f.title)),
    el('div', { class: 'muted small' }, ago(f.created), ' · ', f.detection_id, ' · ',
      el('button', { class: 'link small danger-link', onclick: () => { if (confirm('Remove this finding from the case?')) caseCall('/findings/' + encodeURIComponent(f.id), undefined, 'DELETE'); } }, 'Remove'))));
  (missing || []).forEach((id) => findingRows.push(el('li', { class: 'muted small' }, `Finding ${id} no longer exists.`)));

  fill(box,
    el('div', { class: 'row' }, el('button', { class: 'link', onclick: showCaseList }, '← All cases')),
    el('div', { class: 'case-head' }, title,
      el('div', { class: 'meta' }, sevBadge(c.severity), statusBadge(c.status), el('span', { class: 'muted' }, c.id),
        el('span', { class: 'muted' }, 'Updated ' + ago(c.updated)))),
    el('div', { class: 'case-layout' },
      el('div', { class: 'case-main' },
        el('div', { class: 'panel' },
          el('div', { class: 'form-grid' },
            el('label', {}, 'Status', status), el('label', {}, 'Severity', severity), el('label', {}, 'Owner', owner)),
          el('label', {}, 'Description', desc),
          closing,
          el('div', { class: 'row' }, save, mine)),
        el('div', { class: 'panel' },
          el('h3', {}, 'Timeline'),
          note, el('div', { class: 'row' }, addNote),
          el('ul', { class: 'timeline case-timeline' }, ...items))),
      el('aside', { class: 'case-side' },
        el('div', { class: 'panel' },
          el('h3', {}, `Findings (${(linked || []).length})`),
          findingRows.length ? el('ul', { class: 'case-findings' }, ...findingRows)
            : el('div', { class: 'muted small' }, 'No findings yet. On the Findings page, select findings and choose Add to case.')),
        el('div', { class: 'panel' },
          el('h3', {}, 'Entities'),
          ents.length ? el('ul', { class: 'case-entities' }, ...ents.map((e) => el('li', {},
            el('span', { class: 'muted' }, e.field + ' '),
            el('a', { class: 'entity link', title: `Search the last 7 days for ${e.field}=${e.value}`, onclick: () => openSearch(e.field + '=' + quoteValue(e.value), '-7d') }, e.value),
            ' ', (typeof contextLine === 'function') ? contextLineFor(e) : null)))
            : el('div', { class: 'muted small' }, 'Users, hosts and IPs from findings and pinned events appear here.'),
          el('div', { class: 'row' }, entField, entValue, addEnt)),
        el('div', { class: 'panel' },
          el('h3', {}, 'Add a search'),
          el('div', { class: 'muted small' }, 'The search runs now and its first 50 rows are saved on the timeline.'),
          sq, el('div', { class: 'row' }, stime, sNote), el('div', { class: 'row' }, addSearch)))));
}

// Entity context from the asset and identity lists, filled in lazily.
const ctxCache = new Map();
function contextLineFor(e) {
  const holder = el('span', {});
  const key = e.field + '\u0000' + e.value;
  const show = (c) => { if (c) fill(holder, contextLine(c)); };
  if (ctxCache.has(key)) show(ctxCache.get(key));
  else {
    api('/api/lookups/context?' + new URLSearchParams({ field: e.field, value: e.value }))
      .then((c) => { ctxCache.set(key, c); show(c); })
      .catch(() => ctxCache.set(key, null));
  }
  return holder;
}

function historyText(h) {
  const who = h.author;
  const when = new Date(h.time).toLocaleString();
  switch (h.field) {
    case 'finding': return `${who} ${h.to === 'removed' ? 'removed' : h.to} finding ${h.from} · ${when}`;
    case 'entity': return `${who} added entity ${h.to} · ${when}`;
    case 'timeline': return `${who} removed a ${h.from} from the timeline · ${when}`;
    case 'description': case 'resolution': return `${who} edited the ${h.field} · ${when}`;
    default: return `${who} changed ${h.field} from ${h.from ? (STATUS_LABEL[h.from] || h.from) : 'empty'} to ${STATUS_LABEL[h.to] || h.to || 'empty'} · ${when}`;
  }
}

function entryNode(c, e, linked) {
  const head = (what) => el('div', { class: 'entry-head' },
    el('span', {}, el('b', {}, e.author), ' ', what),
    el('span', { class: 'muted small' }, new Date(e.time).toLocaleString(),
      e.kind !== 'finding' ? el('button', { class: 'link small danger-link', title: 'Remove from the timeline', onclick: () => {
        if (confirm('Remove this from the timeline?')) caseCall('/entries/' + encodeURIComponent(e.id), undefined, 'DELETE');
      } }, 'Remove') : null));
  switch (e.kind) {
    case 'note':
      return el('li', { class: 'entry entry-note' }, head('added a note'), el('div', { class: 'comment' }, e.text));
    case 'finding': {
      const f = (linked || []).find((x) => x.id === e.finding_id);
      return el('li', { class: 'entry entry-finding' }, head('added a finding'),
        el('div', {}, f ? sevBadge(f.urgency || f.severity) : null, ' ',
          el('a', { class: 'link', onclick: () => openFindingFromCase(e.finding_id) }, e.text || e.finding_id)));
    }
    case 'event': {
      const ev = e.event || {};
      const keys = Object.keys(ev).filter((k) => k !== '_raw');
      return el('li', { class: 'entry entry-event' }, head('pinned an event'),
        e.text ? el('div', { class: 'comment' }, e.text) : null,
        el('table', { class: 'kv' }, el('tbody', {}, ...keys.map((k) => el('tr', {}, el('th', {}, k), el('td', {}, k === '_time' ? fmtTime(ev[k]) : fmtValue(ev[k])))))),
        ev._raw ? el('pre', { class: 'code small' }, ev._raw) : null);
    }
    case 'search':
      return el('li', { class: 'entry entry-search' }, head('ran a search'),
        e.text ? el('div', { class: 'comment' }, e.text) : null,
        el('pre', { class: 'code small' }, e.query),
        el('div', { class: 'row tight' },
          el('span', { class: 'muted small' }, searchSummary(e)),
          el('button', { class: 'link small', onclick: () => openSearch(e.query, e.earliest, e.latest) }, 'Run again in Search')),
        snapshotTable(e));
    default:
      return el('li', {}, head(e.kind));
  }
}

function searchSummary(e) {
  const n = (e.rows || []).length;
  const bits = [];
  bits.push(e.earliest ? `time ${e.earliest}${e.latest ? ' to ' + e.latest : ''}` : 'all time');
  if (e.result_kind === 'events') bits.push(`${(e.matched || 0).toLocaleString()} matching events`);
  else bits.push(`${n} row${n === 1 ? '' : 's'}`);
  if (e.truncated) bits.push(`first ${n} kept`);
  return bits.join(' · ');
}

function snapshotTable(e) {
  const rows = e.rows || [];
  if (!rows.length) return el('div', { class: 'muted small' }, 'No results when it ran.');
  let cols = e.columns || [];
  if (e.result_kind === 'events') {
    const pref = ['_time', 'host', 'action', 'user', 'src', 'dest', 'process_name', 'signature'];
    cols = pref.filter((c) => cols.includes(c));
    if (!cols.length) cols = (e.columns || []).filter((c) => c !== '_raw').slice(0, 6);
  }
  const shown = 8;
  const body = (list) => list.map((r) => el('tr', {}, ...cols.map((c) => el('td', { class: typeof r[c] === 'number' ? 'num' : '' }, c === '_time' ? fmtTime(r[c]) : fmtValue(r[c])))));
  const tbody = el('tbody', {}, ...body(rows.slice(0, shown)));
  const more = rows.length > shown ? el('button', { class: 'link small', onclick: (ev) => { tbody.replaceChildren(...body(rows)); ev.target.remove(); } }, `Show all ${rows.length} rows`) : null;
  return el('div', {}, el('div', { class: 'results snapshot' }, el('table', { class: 'grid' },
    el('thead', {}, el('tr', {}, ...cols.map((c) => el('th', {}, c)))), tbody)), more);
}

function openFindingFromCase(id) {
  showPage('findings');
  showFinding(id);
}

// ---------- picking a case ----------
// pickCase asks which case to use and returns its ID, creating a new case
// if the analyst chooses that. It resolves to null when cancelled.
function pickCase({ title = '', heading = 'Add to case', only = '' } = {}) {
  const dlg = $('case-picker');
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; dlg.close(); resolve(v); };
    const list = el('div', { class: 'picker-list' }, el('div', { class: 'muted small' }, 'Loading open cases...'));
    const newTitle = el('input', { type: 'text', value: title, placeholder: 'What is this investigation about?' });
    const newSev = select('cp-sev', SEVERITIES.map((s) => [s, s]), 'medium');
    const msg = el('div', { class: 'error' });
    let choice = only === 'new' ? 'new' : '';
    const newRadio = el('input', { type: 'radio', name: 'cp-case', value: 'new' });
    newRadio.checked = choice === 'new';
    const go = el('button', { class: 'primary' }, only === 'new' ? 'Create case' : 'Add');
    const newBox = el('label', { class: 'picker-new' + (only === 'new' ? ' only' : '') },
      only === 'new' ? null : newRadio, el('span', {}, 'New case'), newTitle,
      el('span', { class: 'inline-sev' }, 'Severity ', newSev));
    newTitle.addEventListener('focus', () => { newRadio.checked = true; choice = 'new'; });
    newRadio.addEventListener('change', () => { choice = 'new'; });

    fill(dlg, el('form', { method: 'dialog', class: 'picker' },
      el('h3', {}, heading),
      only === 'new' ? null : list,
      newBox, msg,
      el('div', { class: 'row' }, go, el('button', { type: 'button', onclick: () => finish(null) }, 'Cancel'))));
    dlg.onclose = () => finish(null);
    go.addEventListener('click', async (ev) => {
      ev.preventDefault();
      msg.textContent = '';
      if (choice !== 'new') {
        if (!choice) { msg.textContent = 'Choose a case or start a new one.'; return; }
        finish(choice);
        return;
      }
      if (!newTitle.value.trim()) { msg.textContent = 'Give the new case a title.'; newTitle.focus(); return; }
      try {
        const res = await api('/api/cases', { title: newTitle.value.trim(), severity: newSev.value, owner: currentUser });
        refreshCaseCount();
        finish(res.case.id);
      } catch (e) { msg.textContent = e.message; }
    });
    dlg.showModal();
    if (only === 'new') { newTitle.focus(); return; }
    api('/api/cases?' + new URLSearchParams({ status: 'new,in_progress,pending', limit: '50' })).then((res) => {
      if (!res.cases.length) {
        fill(list, el('div', { class: 'muted small' }, 'No open cases yet.'));
        newRadio.checked = true;
        choice = 'new';
        newTitle.focus();
        return;
      }
      fill(list, ...res.cases.map((c) => {
        const r = el('input', { type: 'radio', name: 'cp-case', value: c.id });
        r.addEventListener('change', () => { choice = c.id; });
        if (caseState.open === c.id) { r.checked = true; choice = c.id; }
        return el('label', { class: 'picker-item' }, r, sevBadge(c.severity), el('span', { class: 'picker-title' }, c.title),
          el('span', { class: 'muted small' }, c.owner || 'unassigned'));
      }));
    }).catch((e) => fill(list, el('div', { class: 'error' }, e.message)));
  });
}

// ---------- adding from other pages ----------
async function addFindingsToCase(ids, title) {
  const id = await pickCase({ title });
  if (!id) return;
  try {
    const res = await api('/api/cases/' + encodeURIComponent(id) + '/findings', { ids });
    const failed = Object.keys(res.failed || {}).length;
    refreshCaseCount();
    toast(`${ids.length - failed} finding${ids.length - failed === 1 ? '' : 's'} added to ${res.case.title}.` + (failed ? ` ${failed} could not be added.` : ''),
      { label: 'Open case', run: () => openCase(id) });
    if ($('page-findings').classList.contains('active')) {
      selected.clear();
      loadFindings();
      if (openFinding) showFinding(openFinding);
    }
  } catch (e) { alert(e.message); }
}

$('f-bulk-case').addEventListener('click', () => {
  const ids = [...selected];
  if (!ids.length) return;
  const first = findingsList.find((f) => f.id === ids[0]);
  addFindingsToCase(ids, first ? first.title : '');
});

$('search-to-case').addEventListener('click', async () => {
  const query = $('query').value.trim();
  if (!query) { showQueryError(new Error('Write or ask for a query first.')); return; }
  const id = await pickCase({ title: lastAsk && lastAsk.query.trim() === query ? lastAsk.question : '' });
  if (!id) return;
  const earliest = $('time').value === '0' ? '' : $('time').value;
  try {
    const res = await api('/api/cases/' + encodeURIComponent(id) + '/entries', { kind: 'search', query, earliest });
    toast(`Search saved to ${res.case.title}.`, { label: 'Open case', run: () => openCase(id) });
  } catch (e) { alert(e.message); }
});

// pinEventToCase is called from the search results cell menu.
async function pinEventToCase(row) {
  const id = await pickCase();
  if (!id) return;
  try {
    const res = await api('/api/cases/' + encodeURIComponent(id) + '/entries', { kind: 'event', event: row });
    toast(`Event pinned to ${res.case.title}.`, { label: 'Open case', run: () => openCase(id) });
  } catch (e) { alert(e.message); }
}
