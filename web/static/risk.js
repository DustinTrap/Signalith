// Risk analysis and the asset and identity lists.
'use strict';

const prioBadge = (p) => (p ? el('span', { class: 'prio prio-' + p }, p) : null);

// contextLine summarizes asset or identity context in a few words.
function contextLine(c) {
  if (!c) return null;
  const bits = [];
  if (c.name) bits.push(c.name);
  if (c.owner) bits.push((c.kind === 'identity' ? 'manager ' : 'owner ') + c.owner);
  if ((c.category || []).length) bits.push(c.category.join(', '));
  if (c.bunit) bits.push(c.bunit);
  return el('span', { class: 'ctx' }, prioBadge(c.priority), c.watchlist ? el('span', { class: 'prio prio-watch' }, 'watchlist') : null,
    bits.length ? ' ' + bits.join(' · ') : null);
}

// ---------- risk ----------
let riskOpen = null;

async function loadRisk() {
  const p = new URLSearchParams({ since: $('r-since').value });
  if ($('r-type').value) p.set('type', $('r-type').value);
  try {
    const res = await api('api/risk?' + p);
    renderRisk(res.objects || []);
  } catch (e) {
    $('r-list').replaceChildren(el('div', { class: 'error', style: 'padding:12px' }, e.message));
  }
}

function renderRisk(objs) {
  if (!objs.length) {
    $('r-list').replaceChildren(el('div', { class: 'muted', style: 'padding:12px' },
      'No risk in this period. Risk appears when detections with a risk score find something.'));
    return;
  }
  const top = Math.max(...objs.map((o) => o.risk_score || 0), 100);
  const rows = objs.map((o) => el('tr', {
    class: riskOpen && riskOpen.object === o.risk_object && riskOpen.type === o.risk_object_type ? 'sel' : '',
    onclick: () => showRiskObject(o.risk_object, o.risk_object_type),
  },
  el('td', { class: 'wrap' }, el('div', {}, o.risk_object), el('div', { class: 'muted small' }, o.risk_object_type)),
  el('td', {}, el('div', { class: 'bar-wrap' },
    el('div', { class: 'bar' + (o.risk_score >= 100 ? ' hot' : ''), style: `width:${Math.max(2, 100 * o.risk_score / top)}%` }),
    el('span', { class: 'bar-label' }, fmtValue(o.risk_score)))),
  el('td', { class: 'num' }, String(o.detections)),
  el('td', { class: 'num' }, String(o.tactics)),
  el('td', { class: 'num' }, String(o.events)),
  el('td', {}, o.last_seen ? ago(o.last_seen) : ''),
  el('td', { class: 'wrap' }, contextLine(o.context))));
  $('r-list').replaceChildren(el('table', { class: 'grid' },
    el('thead', {}, el('tr', {}, ...['Object', 'Risk score', 'Detections', 'ATT&CK tactics', 'Events', 'Last seen', 'Context'].map((h) => el('th', {}, h)))),
    el('tbody', {}, ...rows)));
}

async function showRiskObject(object, type) {
  riskOpen = { object, type };
  const box = $('r-detail');
  box.classList.remove('hidden');
  box.replaceChildren(el('div', { class: 'muted' }, 'Loading...'));
  let res;
  try {
    res = await api('api/risk/object?' + new URLSearchParams({ object, type, since: $('r-since').value }));
  } catch (e) {
    box.replaceChildren(el('div', { class: 'error' }, e.message));
    return;
  }
  const evs = res.events || [];
  const tactics = new Set();
  evs.forEach((e) => [].concat(e.mitre_tactic || []).forEach((t) => tactics.add(t)));
  fill(box,
    el('div', { class: 'detail-head' }, el('h3', {}, object), el('button', { class: 'link', onclick: () => { box.classList.add('hidden'); riskOpen = null; } }, 'Close')),
    el('div', { class: 'meta' }, el('span', { class: 'muted' }, type), el('b', {}, `Risk ${fmtValue(res.total)}`), el('span', { class: 'muted' }, `${evs.length} events`)),
    res.context ? el('div', { class: 'meta' }, contextLine(res.context)) : null,
    tactics.size ? el('div', { class: 'meta' }, 'Tactics: ', ...[...tactics].map((t) => el('span', { class: 'tech' }, t))) : null,
    el('div', { class: 'row' },
      el('button', { onclick: () => openSearch(res.query, '-' + $('r-since').value) }, 'Open in Search'),
      el('button', { onclick: () => { showPage('findings'); $('f-text').value = object; loadFindings(); } }, 'Related findings')),
    el('h4', {}, 'What added risk'),
    el('ul', { class: 'timeline' }, ...evs.map((e) => el('li', {},
      el('div', {}, el('b', {}, '+' + fmtValue(e.risk_score)), ' ', e.risk_message),
      el('div', { class: 'muted small' }, fmtTime(e._time), ' · ', e.detection_id,
        e.risk_priority ? ` · ${e.risk_priority} priority (base ${e.risk_base_score})` : '')))));
}

$('r-refresh').addEventListener('click', loadRisk);
$('r-since').addEventListener('change', () => { loadRisk(); if (riskOpen) showRiskObject(riskOpen.object, riskOpen.type); });
$('r-type').addEventListener('change', loadRisk);

// ---------- assets and identities ----------
async function loadLists() {
  for (const panel of document.querySelectorAll('#page-assets .panel')) {
    const kind = panel.dataset.kind;
    try {
      const res = await api('api/lookups/' + kind);
      panel.querySelector('.l-count').textContent = `(${res.count})`;
      const items = res.items || [];
      const cols = res.columns;
      const cell = (v) => (Array.isArray(v) ? v.join(' | ') : v === true ? 'yes' : v || '');
      panel.querySelector('.l-table').replaceChildren(items.length ? el('table', { class: 'grid' },
        el('thead', {}, el('tr', {}, ...cols.map((c) => el('th', {}, c)))),
        el('tbody', {}, ...items.slice(0, 200).map((it) => el('tr', {}, ...cols.map((c) => el('td', {}, c === 'priority' ? prioBadge(it[c]) || '' : cell(it[c]))))))) : '');
    } catch (e) {
      panel.querySelector('.l-msg').replaceChildren(el('div', { class: 'error' }, e.message));
    }
  }
}

for (const panel of document.querySelectorAll('#page-assets .panel')) {
  panel.querySelector('.l-upload').addEventListener('click', async () => {
    const msg = panel.querySelector('.l-msg');
    const file = panel.querySelector('.l-file').files[0];
    if (!file) { msg.replaceChildren(el('div', { class: 'error' }, 'Choose a CSV file first.')); return; }
    const text = await file.text();
    const resp = await fetch('api/lookups/' + panel.dataset.kind, { method: 'PUT', headers: { 'Content-Type': 'text/csv' }, body: text });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      msg.replaceChildren(el('div', { class: 'error' }, data.error || resp.statusText,
        ...(data.lines || []).slice(0, 20).map((l) => el('div', {}, `line ${l.line}: ${l.msg}`))));
      return;
    }
    msg.replaceChildren(el('div', { class: 'ok' }, `Saved ${data.count} entries. New findings and risk use them right away.`));
    loadLists();
  });
}

pageHooks.push((name) => {
  if (name === 'risk') loadRisk();
  if (name === 'assets') loadLists();
});
