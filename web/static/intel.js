// Threat intel: feed status, indicators, manual add and CSV upload.
'use strict';

const tiState = { offset: 0, limit: 100 };

// until describes a future time, like ago does a past one.
function until(t) {
  const s = (new Date(t).getTime() - Date.now()) / 1000;
  if (!isFinite(s)) return '';
  if (s <= 60) return 'now';
  if (s < 3600) return 'in ' + Math.round(s / 60) + 'm';
  if (s < 86400) return 'in ' + Math.round(s / 3600) + 'h';
  return 'in ' + Math.round(s / 86400) + 'd';
}

// huntQuery is a search for the events an indicator would match.
function huntQuery(ind) {
  const v = quoteValue(ind.value);
  if (ind.type === 'ip' || ind.type === 'cidr') return `src=${v} OR dest=${v}`;
  if (ind.type === 'domain') return `dest_host=${v} OR dest=${v} OR query=${v} OR url="*${ind.value}*"`;
  if (['md5', 'sha1', 'sha256'].includes(ind.type)) return `process_${ind.type}=${v} OR process_hash="*${ind.value}*"`;
  return '"' + ind.value.replace(/"/g, '\\"') + '"';
}

async function loadIntel() {
  let res;
  try {
    res = await api('api/intel');
  } catch (e) {
    $('ti-feeds').replaceChildren(el('div', { class: 'error' }, e.message));
    return;
  }
  const sum = res.summary || { total: 0, by_type: {}, by_source: {} };
  $('ti-summary').replaceChildren(
    el('span', { class: 'chip' }, el('b', {}, (sum.total || 0).toLocaleString()), ' indicators'),
    ...Object.entries(sum.by_type || {}).sort((a, b) => b[1] - a[1]).map(([t, n]) => el('span', { class: 'chip tech' }, `${t} ${n.toLocaleString()}`)));
  renderFeeds(res.feeds || [], res.downloads);
  const sources = Object.keys(sum.by_source || {}).sort();
  const sel = $('ti-source');
  const cur = sel.value;
  sel.replaceChildren(el('option', { value: '' }, 'Any source'), ...sources.map((s) => el('option', { value: s }, s)));
  if (sources.includes(cur)) sel.value = cur;
  loadIndicators();
}

function renderFeeds(feeds, downloads) {
  const box = $('ti-feeds');
  if (!feeds.length) {
    box.replaceChildren(el('div', { class: 'notice' },
      'No feeds are configured, so nothing is downloaded. Add feeds under ',
      el('code', {}, 'intel.feeds'), ' in signalith.yaml and restart. The examples below are free public feeds.'));
    $('ti-examples').open = true;
    return;
  }
  const rows = feeds.map((f) => {
    const st = f.status || {};
    let state;
    if (!f.enabled) state = el('span', { class: 'status-badge' }, 'disabled');
    else if (st.running) state = el('span', { class: 'status-badge st-new' }, 'downloading');
    else if (st.last_error) state = el('span', { class: 'status-badge bad' }, 'failing');
    else if (st.last_success) state = el('span', { class: 'status-badge ok' }, 'ok');
    else state = el('span', { class: 'status-badge' }, 'waiting');
    const refresh = el('button', {}, 'Refresh now');
    refresh.addEventListener('click', async () => {
      refresh.disabled = true;
      refresh.textContent = 'Downloading...';
      try {
        await api(`api/intel/feeds/${encodeURIComponent(f.name)}/refresh`, {}, 'POST');
      } catch (e) {
        alert(`${f.name}: ${e.message}`);
      }
      loadIntel();
    });
    const detail = [];
    if (st.last_error) detail.push(el('div', { class: 'error small' }, st.last_error));
    if (st.skipped) detail.push(el('div', { class: 'muted small' }, `${st.skipped.toLocaleString()} ${st.skipped === 1 ? 'line' : 'lines'} skipped as not valid${st.skipped_example ? ', such as ' + st.skipped_example : ''}`));
    return el('tr', {},
      el('td', { class: 'wrap' }, el('div', {}, el('b', {}, f.name)), el('div', { class: 'muted small ti-url' }, f.url),
        f.description ? el('div', { class: 'muted small' }, f.description) : null),
      el('td', {}, state, ...detail),
      el('td', {}, el('div', {}, f.format + (f.column ? ` (${f.column})` : '')), el('div', { class: 'muted small' }, f.type)),
      el('td', { class: 'num' }, (f.indicators || 0).toLocaleString(),
        st.last_success ? el('div', { class: 'muted small' }, `+${st.added || 0} / -${st.removed || 0}`) : null),
      el('td', {}, st.last_success ? ago(st.last_success) : 'never',
        el('div', { class: 'muted small' }, `every ${f.interval}`)),
      el('td', {}, f.enabled && st.next_run && downloads ? until(st.next_run) : ''),
      el('td', { class: 'num' }, String(f.weight)),
      el('td', {}, f.enabled ? refresh : null));
  });
  fill(box,
    downloads ? null : el('div', { class: 'notice' }, 'This server does not download feeds on a schedule (detections.scheduler: false). Refresh now still works.'),
    el('div', { class: 'results' }, el('table', { class: 'grid' },
      el('thead', {}, el('tr', {}, ...['Feed', 'Status', 'Format', 'Indicators', 'Last download', 'Next', 'Weight', ''].map((h) => el('th', {}, h)))),
      el('tbody', {}, ...rows))));
}

async function loadIndicators() {
  const p = new URLSearchParams({ limit: tiState.limit, offset: tiState.offset });
  if ($('ti-q').value.trim()) p.set('q', $('ti-q').value.trim());
  if ($('ti-type').value) p.set('type', $('ti-type').value);
  if ($('ti-source').value) p.set('source', $('ti-source').value);
  let res;
  try {
    res = await api('api/intel/indicators?' + p);
  } catch (e) {
    $('ti-list').replaceChildren(el('div', { class: 'error', style: 'padding:12px' }, e.message));
    return;
  }
  const list = res.indicators || [];
  const end = tiState.offset + list.length;
  $('ti-count').textContent = res.total ? `${tiState.offset + 1}-${end} of ${res.total.toLocaleString()}` : '';
  $('ti-prev').disabled = tiState.offset === 0;
  $('ti-next').disabled = end >= res.total;
  if (!list.length) {
    $('ti-list').replaceChildren(el('div', { class: 'muted', style: 'padding:12px' },
      res.total === 0 && !p.has('q') && !p.has('type') && !p.has('source')
        ? 'No indicators yet. Configure a feed, add one below, or upload a CSV.' : 'No indicators match.'));
    return;
  }
  const rows = list.map((ind) => {
    const actions = [el('button', { class: 'link', title: 'Search events for this indicator', onclick: () => openSearch(huntQuery(ind), '-7d') }, 'Search')];
    if (ind.source === 'manual') {
      actions.push(' ', el('button', { class: 'link danger-link', onclick: async () => {
        if (!confirm(`Delete ${ind.value}?`)) return;
        try {
          await api('api/intel/indicators/' + encodeURIComponent(ind.id), undefined, 'DELETE');
        } catch (e) {
          alert(e.message);
        }
        loadIntel();
      } }, 'Delete'));
    }
    return el('tr', {},
      el('td', { class: 'wrap mono-cell' }, ind.value),
      el('td', {}, ind.type),
      el('td', {}, ind.source),
      el('td', { class: 'num' }, String(ind.weight)),
      el('td', { class: 'wrap' }, ind.description || '', (ind.tags || []).length ? el('div', { class: 'entities' }, ...ind.tags.map((t) => el('span', { class: 'entity' }, t))) : null),
      el('td', { title: ind.first_seen ? 'First seen ' + fmtTime(ind.first_seen) : '' }, ago(ind.last_seen)),
      el('td', {}, ind.expires ? until(ind.expires) : 'never'),
      el('td', {}, ...actions));
  });
  $('ti-list').replaceChildren(el('table', { class: 'grid' },
    el('thead', {}, el('tr', {}, ...['Value', 'Type', 'Source', 'Weight', 'Description', 'Last seen', 'Expires', ''].map((h) => el('th', {}, h)))),
    el('tbody', {}, ...rows)));
}

let tiTimer = null;
$('ti-q').addEventListener('input', () => {
  clearTimeout(tiTimer);
  tiTimer = setTimeout(() => { tiState.offset = 0; loadIndicators(); }, 250);
});
for (const id of ['ti-type', 'ti-source']) $(id).addEventListener('change', () => { tiState.offset = 0; loadIndicators(); });
$('ti-prev').addEventListener('click', () => { tiState.offset = Math.max(0, tiState.offset - tiState.limit); loadIndicators(); });
$('ti-next').addEventListener('click', () => { tiState.offset += tiState.limit; loadIndicators(); });
$('ti-refresh').addEventListener('click', loadIntel);
$('ti-hunt').addEventListener('click', () => openSearch('* | threatmatch\n| table _time, threat_match_field, threat_match_value, threat_source, threat_target, user, sourcetype', '-24h'));

$('ti-add').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const msg = $('ti-add-msg');
  const body = {
    value: $('ti-value').value, type: $('ti-add-type').value, description: $('ti-desc').value,
    weight: $('ti-weight').value, expires: $('ti-expires').value,
    tags: $('ti-tags').value.split(',').map((t) => t.trim()).filter(Boolean),
  };
  try {
    const ind = await api('api/intel/indicators', body);
    msg.replaceChildren(el('div', { class: 'ok' }, `Added ${ind.type} ${ind.value}. Searches and the threat detection use it right away.`));
    $('ti-value').value = '';
    $('ti-desc').value = '';
    loadIntel();
  } catch (e) {
    msg.replaceChildren(el('div', { class: 'error' }, e.message));
  }
});

$('ti-upload').addEventListener('click', async () => {
  const msg = $('ti-upload-msg');
  const file = $('ti-file').files[0];
  if (!file) { msg.replaceChildren(el('div', { class: 'error' }, 'Choose a CSV or text file first.')); return; }
  const text = await file.text();
  const resp = await fetch('api/intel/upload', { method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: text });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const lines = data.lines || [];
    msg.replaceChildren(el('div', { class: 'error' }, data.error || resp.statusText,
      ...lines.slice(0, 20).map((l) => el('div', {}, `line ${l.line}: ${l.msg}`)),
      lines.length > 20 ? el('div', {}, `and ${lines.length - 20} more`) : null));
    return;
  }
  msg.replaceChildren(el('div', { class: 'ok' }, `Added ${data.count} indicators.`));
  $('ti-file').value = '';
  loadIntel();
});

pageHooks.push((name) => {
  if (name === 'intel') loadIntel();
});
