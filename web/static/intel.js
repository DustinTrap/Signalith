// Threat intel: feed status, indicators, manual add and CSV upload.
// Uses the ri* helpers (states, inspectors, alerts) from risk.js.
'use strict';

const tiState = { offset: 0, limit: 100, type: '', overview: null, list: [], total: 0, lookup: null, open: null, seq: 0, listSeq: 0, loaded: false, poll: null };

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

// Types group into the classes the API filters by (?type=ip covers cidr).
const TI_CLASS = { ip: 'ip', cidr: 'ip', domain: 'domain', url: 'url', md5: 'hash', sha1: 'hash', sha256: 'hash', email: 'email' };
const TI_CLASSES = [['ip', 'IPs', 'globe'], ['domain', 'Domains', 'link'], ['url', 'URLs', 'external-link'], ['hash', 'Hashes', 'hash'], ['email', 'Emails', 'mail']];
const TI_TYPE_LABEL = { ip: 'IP address', cidr: 'Network', domain: 'Domain', url: 'URL', md5: 'MD5 hash', sha1: 'SHA-1 hash', sha256: 'SHA-256 hash', email: 'Email address' };
const TI_TYPE_SHORT = { ip: 'IP', cidr: 'Network', domain: 'Domain', url: 'URL', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'Email' };
const TI_TYPE_ICON = { ip: 'globe', cidr: 'network', domain: 'link', url: 'external-link', md5: 'hash', sha1: 'hash', sha256: 'hash', email: 'mail' };
const TI_HUNT = '* | threatmatch\n| table _time, threat_match_field, threat_match_value, threat_source, threat_target, user, sourcetype';
const tiSourceLabel = (s) => (s === 'manual' ? 'Manual' : s);
const tiChip = (ind) => el('span', { class: 'chip', 'data-kind': TI_CLASS[ind.type] || 'hash', title: ind.value }, el('span', {}, ind.value));

// ---------- overview: errors, type pills, feeds ----------
async function loadIntel() {
  const seq = ++tiState.seq;
  clearTimeout(tiState.poll);
  if (!tiState.overview) {
    $('ti-feeds').replaceChildren(riSkeleton(TI_FEED_COLS, 3));
    $('ti-list').replaceChildren(riSkeleton(TI_IND_COLS));
  }
  $('ti-refresh').disabled = true;
  let res;
  try {
    res = await api('api/intel');
  } catch (e) {
    if (seq !== tiState.seq) return;
    $('ti-refresh').disabled = false;
    showIntelError(e);
    return;
  }
  if (seq !== tiState.seq) return;
  $('ti-refresh').disabled = false;
  tiState.overview = res;
  $('ti-error').classList.add('hidden');
  $('ti-main').classList.remove('hidden');
  $('ti-add-open').disabled = false;
  $('ti-hunt').disabled = false;
  renderTypePills();
  renderFeeds(res.feeds || [], res.downloads);
  const sources = Object.keys((res.summary || {}).by_source || {}).sort();
  const sel = $('ti-source');
  const cur = sel.value;
  sel.replaceChildren(el('option', { value: '' }, 'Any source'), ...sources.map((s) => el('option', { value: s }, tiSourceLabel(s))));
  if (sources.includes(cur)) sel.value = cur;
  else if (cur) { sel.value = ''; tiState.offset = 0; }
  // While a feed downloads, check again so its status settles by itself.
  if ((res.feeds || []).some((f) => f.status && f.status.running)) {
    tiState.poll = setTimeout(() => { if (currentPage === 'intel') loadIntel(); }, 3000);
  }
  loadIndicators();
}

// showIntelError replaces the page with what failed (threat intel may be
// off on this server); the buttons that need it are disabled meanwhile.
function showIntelError(e) {
  tiState.overview = null;
  closeIndicator();
  $('ti-main').classList.add('hidden');
  $('ti-add-open').disabled = true;
  $('ti-hunt').disabled = true;
  $('ti-error').replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load threat intel', text: riCap(e.message) + '.', action: riRetry(loadIntel) }));
  $('ti-error').classList.remove('hidden');
}

function renderTypePills() {
  const sum = (tiState.overview && tiState.overview.summary) || { total: 0, by_type: {} };
  const counts = {};
  for (const [t, n] of Object.entries(sum.by_type || {})) counts[TI_CLASS[t] || t] = (counts[TI_CLASS[t] || t] || 0) + n;
  const pill = (cls, label, name, n) => {
    const b = el('button', { class: 'pill', type: 'button', 'aria-pressed': String(tiState.type === cls) }, icon(name), label, el('span', { class: 'num' }, n.toLocaleString()));
    b.addEventListener('click', () => {
      if (tiState.type === cls) return;
      tiState.type = cls;
      tiState.offset = 0;
      renderTypePills();
      loadIndicators();
    });
    return b;
  };
  $('ti-type').replaceChildren(pill('', 'All', 'layers', sum.total || 0),
    ...TI_CLASSES.filter(([cls]) => counts[cls] || tiState.type === cls).map(([cls, label, name]) => pill(cls, label, name, counts[cls] || 0)));
}

const TI_FEED_COLS = [['Feed', 'ti-c-feed'], ['Status', 'ti-c-state'], ['Format', 'hide-md hide-sm'], ['Indicators', 'num hide-sm'],
  ['Last download', 'hide-sm'], ['Next', 'hide-md hide-sm'], ['Weight', 'num hide-md hide-sm', 'Multiplies the risk a match adds'], ['', 'ti-c-act']];

function feedState(f) {
  const st = f.status || {};
  if (!f.enabled) return ['off', 'Disabled'];
  if (st.running) return ['run', 'Downloading'];
  if (st.last_error) return ['bad', 'Failing'];
  if (st.last_success) return ['ok', 'OK'];
  return ['wait', 'Waiting'];
}

function renderFeeds(feeds, downloads) {
  const box = $('ti-feeds');
  const enabled = feeds.filter((f) => f.enabled).length;
  const failing = feeds.filter((f) => feedState(f)[0] === 'bad').length;
  $('ti-examples-open').classList.toggle('hidden', !feeds.length);
  if (!feeds.length) {
    $('ti-feeds-sub').textContent = 'Downloaded indicator lists';
    box.replaceChildren(can('admin') ? riEmpty({ icon: 'rss', title: 'No feeds yet',
      text: 'Add feeds under intel.feeds in signalith.yaml and restart. Nothing is downloaded until then.',
      action: { label: 'Show example settings', icon: 'file-code', run: openExamples } })
      : riEmpty({ icon: 'rss', title: 'No feeds yet', text: 'An admin sets up feeds. Nothing is downloaded until then.' }));
    return;
  }
  const sub = [`${enabled} of ${feeds.length} enabled`];
  if (failing) sub.push(`${failing} failing`);
  $('ti-feeds-sub').textContent = sub.join(' · ');
  const rows = feeds.map((f) => {
    const st = f.status || {};
    const [state, label] = feedState(f);
    const stateCell = el('td', { class: 'ti-c-state' }, el('span', { class: 'ti-state', 'data-state': state }, label));
    if (st.last_error && state !== 'off') stateCell.append(el('span', { class: 'ti-sub ti-sub--bad', title: st.last_error }, st.last_error));
    else if (st.skipped) {
      stateCell.append(el('span', { class: 'ti-sub', title: st.skipped_example ? 'Such as ' + st.skipped_example : '' },
        `${st.skipped.toLocaleString()} ${st.skipped === 1 ? 'line' : 'lines'} skipped as not valid`));
    }
    let action = null;
    if (f.enabled && can('admin')) {
      action = riIconBtn('cloud-download', `Download ${f.name} now`, async () => {
        action.disabled = true;
        stateCell.firstChild.dataset.state = 'run';
        stateCell.firstChild.textContent = 'Downloading';
        try {
          const r = await api(`api/intel/feeds/${encodeURIComponent(f.name)}/refresh`, {}, 'POST');
          const n = (r.status || {}).count || 0;
          toast(`Downloaded ${f.name}: ${n.toLocaleString()} ${n === 1 ? 'indicator' : 'indicators'}.`);
        } catch (e) {
          toast(`${f.name}: ${e.message}`, null, { tone: 'danger' });
        }
        loadIntel();
      }, st.running);
    }
    return el('tr', {},
      el('td', { class: 'ti-c-feed' },
        el('span', { class: 'cell-title', title: f.description || f.name }, f.name, f.description ? el('span', { class: 'ti-desc' }, f.description) : null),
        el('span', { class: 'ti-sub mono', title: f.url }, f.url)),
      stateCell,
      el('td', { class: 'hide-md hide-sm' }, el('span', { class: 'ti-line' }, f.format + (f.column ? ` (${f.column})` : '')), el('span', { class: 'ti-sub' }, f.type)),
      el('td', { class: 'num hide-sm' }, el('span', { class: 'ti-line' }, (f.indicators || 0).toLocaleString()),
        st.last_success ? el('span', { class: 'ti-sub', title: 'Added and removed in the last download' }, `+${(st.added || 0).toLocaleString()} / −${(st.removed || 0).toLocaleString()}`) : null),
      el('td', { class: 'hide-sm' }, el('span', { class: 'ti-line', title: st.last_success ? fmtTime(st.last_success) : '' }, st.last_success ? ago(st.last_success) : 'Never'),
        f.interval ? el('span', { class: 'ti-sub' }, `every ${f.interval}`) : null),
      el('td', { class: 'hide-md hide-sm' }, el('span', { class: 'age', title: st.next_run ? fmtTime(st.next_run) : '' }, f.enabled && st.next_run && downloads ? until(st.next_run) : '')),
      el('td', { class: 'num hide-md hide-sm' }, riNum(f.weight)),
      el('td', { class: 'ti-c-act' }, action));
  });
  fill(box,
    downloads ? null : el('div', { class: 'ti-note' }, riAlert('info', 'Feeds are not downloaded on a schedule on this server.',
      el('p', {}, 'The detection scheduler is off (detections.scheduler: false). Download now still works.'))),
    el('div', { class: 'table-wrap' }, el('table', { class: 'table ti-feed-table' }, riHead(TI_FEED_COLS), el('tbody', {}, ...rows))));
}

// ---------- indicators ----------
const TI_IND_COLS = [['Indicator', 'ti-c-ind'], ['Type', 'hide-sm ti-c-type'], ['Source', 'hide-sm ti-c-source'], ['Weight', 'num hide-sm ti-c-weight', 'Multiplies the risk a match adds'],
  ['Last seen', 'hide-sm ti-c-seen'], ['Expires', 'hide-sm ti-c-exp']];

async function loadIndicators() {
  const seq = ++tiState.listSeq;
  const q = $('ti-q').value.trim();
  const p = new URLSearchParams({ limit: tiState.limit, offset: tiState.offset });
  if (q) p.set('q', q);
  if (tiState.type) p.set('type', tiState.type);
  if ($('ti-source').value) p.set('source', $('ti-source').value);
  if (!tiState.loaded) $('ti-list').replaceChildren(riSkeleton(TI_IND_COLS));
  else $('ti-list').querySelector('table')?.setAttribute('aria-busy', 'true');
  let res;
  try {
    res = await api('api/intel/indicators?' + p);
  } catch (e) {
    if (seq !== tiState.listSeq) return;
    tiState.loaded = false;
    tiState.list = [];
    $('ti-count').textContent = '';
    $('ti-prev').disabled = true;
    $('ti-next').disabled = true;
    $('ti-list').replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load indicators', text: riCap(e.message) + '. Your filters are kept.', action: riRetry(loadIndicators) }));
    return;
  }
  let lookup = null;
  if (!(res.indicators || []).length && q) {
    // A value inside a listed network, or a URL on a listed domain, is not
    // a text match; ask the server the way a search would.
    try { lookup = (await api('api/intel/lookup?' + new URLSearchParams({ value: q }))).matches || []; } catch (_) { lookup = null; }
    if (lookup) lookup = lookup.filter((m) => (!tiState.type || TI_CLASS[m.type] === tiState.type) && (!$('ti-source').value || m.source === $('ti-source').value));
  }
  if (seq !== tiState.listSeq) return;
  tiState.loaded = true;
  tiState.list = res.indicators || [];
  tiState.total = res.total || 0;
  tiState.lookup = lookup && lookup.length ? lookup : null;
  renderIndicators();
}

const tiShown = () => tiState.lookup || tiState.list;
const tiFiltered = () => !!($('ti-q').value.trim() || tiState.type || $('ti-source').value);

function renderIndicators() {
  const box = $('ti-list');
  const list = tiState.list;
  const end = tiState.offset + list.length;
  $('ti-prev').disabled = tiState.offset === 0;
  $('ti-next').disabled = end >= tiState.total;
  $('ti-prev').classList.toggle('hidden', tiState.total <= tiState.limit);
  $('ti-next').classList.toggle('hidden', tiState.total <= tiState.limit);
  const shown = tiShown();
  if (tiState.lookup) {
    const n = tiState.lookup.length;
    $('ti-count').textContent = `${n} ${n === 1 ? 'indicator matches' : 'indicators match'} by network or host`;
  } else if (tiState.total) {
    $('ti-count').textContent = tiState.total > list.length || tiState.offset
      ? `${(tiState.offset + 1).toLocaleString()}–${end.toLocaleString()} of ${tiState.total.toLocaleString()}`
      : `${tiState.total.toLocaleString()} ${tiState.total === 1 ? 'indicator' : 'indicators'}`;
  } else $('ti-count').textContent = '';
  if (tiState.open && !shown.some((i) => i.id === tiState.open)) closeIndicator();
  if (!shown.length) {
    box.replaceChildren(tiFiltered()
      ? riEmpty({ icon: 'search', title: 'No indicators match', text: 'Nothing matches these filters. A value inside a listed network still counts as a match.', action: { label: 'Clear filters', run: clearIntelFilters } })
      : riEmpty({ icon: 'radar', title: 'No indicators yet', text: can('analyst') ? 'Indicators come from feeds. Add your own with Add indicators.' : 'Indicators come from feeds and from analysts.' }));
    return;
  }
  const rows = shown.map((ind) => {
    const open = () => showIndicator(ind.id);
    const tr = el('tr', { 'data-id': ind.id, onclick: open },
      el('td', { class: 'ti-c-ind' }, tiChip(ind), el('span', { class: 'ti-sub' }, ind.description || (ind.tags || []).join(', '))),
      el('td', { class: 'hide-sm ti-c-type muted' }, TI_TYPE_SHORT[ind.type] || ind.type),
      el('td', { class: 'hide-sm ti-c-source muted' }, tiSourceLabel(ind.source)),
      el('td', { class: 'num hide-sm ti-c-weight' }, riNum(ind.weight)),
      el('td', { class: 'hide-sm ti-c-seen' }, el('span', { class: 'age', title: ind.first_seen ? 'First seen ' + fmtTime(ind.first_seen) : '' }, ago(ind.last_seen))),
      el('td', { class: 'hide-sm ti-c-exp' }, el('span', { class: 'age', title: ind.expires ? fmtTime(ind.expires) : '' }, ind.expires ? until(ind.expires) : 'Never')));
    if (ind.id === tiState.open) tr.setAttribute('aria-selected', 'true');
    riRowKeys(tr, open, () => !!tiState.open);
    return tr;
  });
  fill(box,
    tiState.lookup ? el('div', { class: 'ti-note' }, el('div', { class: 'callout' }, icon('info'),
      el('div', {}, 'No indicator contains ', el('b', { class: 'mono' }, $('ti-q').value.trim()), ', but it matches these the way a search would.'))) : null,
    el('table', { class: 'table ti-ind-table' }, riHead(TI_IND_COLS), el('tbody', {}, ...rows)));
}

function clearIntelFilters() {
  $('ti-q').value = '';
  $('ti-source').value = '';
  tiState.type = '';
  tiState.offset = 0;
  renderTypePills();
  loadIndicators();
}

function markIndicatorRow() {
  $('ti-list').querySelectorAll('tbody tr').forEach((tr) => {
    if (tr.dataset.id === tiState.open) tr.setAttribute('aria-selected', 'true');
    else tr.removeAttribute('aria-selected');
  });
}

function closeIndicator() {
  if (!tiState.open) return;
  const hadFocus = $('ti-detail').contains(document.activeElement);
  const row = $('ti-list').querySelector('tr[aria-selected="true"]');
  tiState.open = null;
  riHidePanel($('ti-detail'));
  markIndicatorRow();
  if (row && (hadFocus || document.activeElement === document.body)) row.focus();
}
riInspectors.push({ page: 'intel', panel: $('ti-detail'), close: closeIndicator });

function showIndicator(id) {
  const shown = tiShown();
  const idx = shown.findIndex((i) => i.id === id);
  if (idx < 0) return;
  const ind = shown[idx];
  tiState.open = id;
  markIndicatorRow();
  const box = $('ti-detail');
  const step = (d) => { const o = shown[idx + d]; if (o) showIndicator(o.id); };
  const bar = el('div', { class: 'inspector__bar' }, icon(TI_TYPE_ICON[ind.type] || 'hash', 'icon--sm'), el('span', {}, TI_TYPE_LABEL[ind.type] || ind.type),
    el('span', {}, `· ${idx + 1} of ${shown.length}`), el('span', { class: 'spacer' }),
    riIconBtn('chevron-up', 'Previous', () => step(-1), idx === 0),
    riIconBtn('chevron-down', 'Next', () => step(1), idx === shown.length - 1),
    riIconBtn('x', 'Close details', closeIndicator));
  const title = el('h2', { class: 'inspector__title mono ti-value', tabindex: '-1' }, ind.value);
  const meta = el('div', { class: 'inspector__meta' }, el('span', {}, tiSourceLabel(ind.source)), el('span', { class: 'dotsep' }),
    el('span', {}, `Weight ${riNum(ind.weight)}`), el('span', { class: 'dotsep' }), el('span', { title: fmtTime(ind.last_seen) }, 'seen ' + ago(ind.last_seen)));
  const kv = [];
  const add = (k, v) => { if (v) kv.push(el('dt', {}, k), el('dd', {}, v)); };
  add('Type', TI_TYPE_LABEL[ind.type] || ind.type);
  add('Source', ind.source === 'manual' ? 'Added by hand or uploaded' : ind.source);
  add('Weight', `${riNum(ind.weight)} (multiplies the risk a match adds)`);
  add('First seen', ind.first_seen ? fmtTime(ind.first_seen) : '');
  add('Last seen', ind.last_seen ? fmtTime(ind.last_seen) : '');
  add('Expires', ind.expires ? `${fmtTime(ind.expires)} (${until(ind.expires)})` : 'Never');
  add('ID', el('span', { class: 'mono' }, ind.id));
  const body = el('div', { class: 'inspector__body' },
    ind.description ? el('p', {}, ind.description) : null,
    (ind.tags || []).length ? el('section', { class: 'section', 'aria-label': 'Tags' }, el('h3', { class: 'section-title' }, 'Tags'),
      el('div', { class: 'chips' }, ...ind.tags.map((t) => el('span', { class: 'chip' }, el('span', {}, t))))) : null,
    el('section', { class: 'section', 'aria-label': 'Details' }, el('h3', { class: 'section-title' }, 'Details'), el('dl', { class: 'kv' }, ...kv)),
    ind.source !== 'manual' ? el('div', { class: 'callout' }, icon('info'),
      el('div', {}, 'This comes from the feed ', el('b', {}, ind.source), ' and returns with its next download. To remove it, disable the feed.')) : null);
  const foot = el('div', { class: 'inspector__foot' },
    el('button', { class: 'btn btn--secondary', type: 'button', title: 'Search the last 7 days for this indicator', onclick: () => openSearch(huntQuery(ind), '-7d') }, icon('search'), 'Search events'));
  if (ind.source === 'manual' && can('analyst')) {
    foot.append(el('span', { class: 'spacer' }), el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => confirmDelete(ind) }, icon('trash-2'), 'Delete'));
  }
  box.replaceChildren(bar, el('div', { class: 'inspector__head' }, title, meta), body, foot);
  const wasOpen = !box.classList.contains('hidden');
  riShowPanel(box);
  if (riSlideOver.matches && !wasOpen) title.focus();
  if (!wasOpen) riReveal(box);
}

// ---------- delete ----------
let tiDeleting = null;
function confirmDelete(ind) {
  tiDeleting = ind;
  $('ti-confirm-desc').replaceChildren(el('span', { class: 'mono' }, ind.value), ' stops matching events right away.');
  $('ti-confirm-delete').disabled = false;
  $('ti-confirm').showModal();
}
$('ti-confirm-delete').addEventListener('click', async () => {
  const ind = tiDeleting;
  if (!ind) return;
  const btn = $('ti-confirm-delete');
  btn.disabled = true;
  try {
    await api('api/intel/indicators/' + encodeURIComponent(ind.id), undefined, 'DELETE');
  } catch (e) {
    btn.disabled = false;
    $('ti-confirm-desc').replaceChildren(riAlert('danger', 'Couldn’t delete it.', el('p', {}, riCap(e.message) + '.')));
    return;
  }
  $('ti-confirm').close();
  closeIndicator();
  toast(`Deleted ${ind.value}.`);
  loadIntel();
});

// ---------- add and upload ----------
function selectAddTab(which, focus) {
  const one = which === 'one';
  $('ti-tab-one').setAttribute('aria-selected', String(one));
  $('ti-tab-upload').setAttribute('aria-selected', String(!one));
  $('ti-tab-one').tabIndex = one ? 0 : -1;
  $('ti-tab-upload').tabIndex = one ? -1 : 0;
  $('ti-add').hidden = !one;
  $('ti-upload-panel').hidden = one;
  if (focus) (one ? $('ti-tab-one') : $('ti-tab-upload')).focus();
}
for (const [id, which] of [['ti-tab-one', 'one'], ['ti-tab-upload', 'upload']]) {
  $(id).addEventListener('click', () => selectAddTab(which));
  $(id).addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight') return;
    ev.preventDefault();
    selectAddTab(which === 'one' ? 'upload' : 'one', true);
  });
}

function clearFieldError(input) {
  input.removeAttribute('aria-invalid');
  input.removeAttribute('aria-describedby');
  const err = input.parentElement.querySelector('.field-error');
  if (err) err.remove();
}
function setFieldError(input, text) {
  clearFieldError(input);
  input.setAttribute('aria-invalid', 'true');
  input.setAttribute('aria-describedby', input.id + '-error');
  input.parentElement.append(el('span', { class: 'field-error', id: input.id + '-error' }, icon('circle-alert'), text));
}

$('ti-add-open').addEventListener('click', () => {
  $('ti-add-msg').replaceChildren();
  $('ti-upload-msg').replaceChildren();
  clearFieldError($('ti-value'));
  clearFieldError($('ti-file'));
  selectAddTab('one');
  $('ti-add-dialog').showModal();
  $('ti-value').focus();
});
$('ti-value').addEventListener('input', () => clearFieldError($('ti-value')));
$('ti-file').addEventListener('change', () => { clearFieldError($('ti-file')); $('ti-upload-msg').replaceChildren(); });

$('ti-add').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const msg = $('ti-add-msg');
  msg.replaceChildren();
  if (!$('ti-value').value.trim()) {
    setFieldError($('ti-value'), 'Enter an IP address, network, domain, URL, hash or email address.');
    $('ti-value').focus();
    return;
  }
  const body = {
    value: $('ti-value').value, type: $('ti-add-type').value, description: $('ti-desc').value,
    weight: $('ti-weight').value, expires: $('ti-expires').value,
    tags: $('ti-tags').value.split(',').map((t) => t.trim()).filter(Boolean),
  };
  const btn = $('ti-add-submit');
  btn.disabled = true;
  try {
    const ind = await api('api/intel/indicators', body);
    $('ti-add-dialog').close();
    toast(`Added ${TI_TYPE_LABEL[ind.type] || ind.type} ${ind.value}. Searches and the threat detection use it right away.`);
    $('ti-value').value = '';
    $('ti-desc').value = '';
    loadIntel();
  } catch (e) {
    msg.replaceChildren(riAlert('danger', 'Couldn’t add it.', el('p', {}, riCap(e.message) + '.')));
  } finally {
    btn.disabled = false;
  }
});

$('ti-upload').addEventListener('click', async () => {
  const msg = $('ti-upload-msg');
  msg.replaceChildren();
  const file = $('ti-file').files[0];
  if (!file) {
    setFieldError($('ti-file'), 'Choose a CSV or text file first.');
    $('ti-file').focus();
    return;
  }
  const btn = $('ti-upload');
  btn.disabled = true;
  try {
    const text = await file.text();
    const resp = await fetch('api/intel/upload', { method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: text });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      msg.replaceChildren(riAlert('danger', riCap(data.error || resp.statusText) + '.', riLineErrors(data.lines)));
      return;
    }
    $('ti-add-dialog').close();
    toast(`Added ${data.count.toLocaleString()} ${data.count === 1 ? 'indicator' : 'indicators'}.`);
    $('ti-file').value = '';
    loadIntel();
  } catch (e) {
    msg.replaceChildren(riAlert('danger', 'The upload failed.', el('p', {}, e.message)));
  } finally {
    btn.disabled = false;
  }
});

// ---------- example feed settings ----------
function openExamples() {
  $('ti-example-copy').replaceChildren(icon('copy'), 'Copy');
  $('ti-examples').showModal();
}
$('ti-examples-open').addEventListener('click', openExamples);
$('ti-example-copy').addEventListener('click', async () => {
  const pre = $('ti-example-yaml');
  try {
    await navigator.clipboard.writeText(pre.textContent);
    $('ti-example-copy').replaceChildren(icon('check'), 'Copied');
  } catch (_) {
    // Without clipboard access (plain http), select it for Ctrl+C.
    const r = document.createRange();
    r.selectNodeContents(pre);
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(r);
    $('ti-example-copy').replaceChildren(icon('copy'), 'Selected: press Ctrl+C');
  }
});

for (const d of ['ti-add-dialog', 'ti-examples', 'ti-confirm']) {
  $(d).querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => $(d).close()));
}

// ---------- filters and actions ----------
let tiTimer = null;
$('ti-q').addEventListener('input', () => {
  clearTimeout(tiTimer);
  tiTimer = setTimeout(() => { tiState.offset = 0; loadIndicators(); }, 250);
});
$('ti-source').addEventListener('change', () => { tiState.offset = 0; loadIndicators(); });
$('ti-prev').addEventListener('click', () => { tiState.offset = Math.max(0, tiState.offset - tiState.limit); loadIndicators(); });
$('ti-next').addEventListener('click', () => { tiState.offset += tiState.limit; loadIndicators(); });
$('ti-refresh').addEventListener('click', loadIntel);
$('ti-hunt').addEventListener('click', () => openSearch(TI_HUNT, '-24h'));

pageHooks.push((name) => {
  if (name === 'intel') loadIntel();
});
