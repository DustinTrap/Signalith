// Sample data: a clean card on the Add data page that loads a week of
// made-up activity with a few attacks hidden in it, so Signalith can be
// tried on real-looking data, and removes it in one click. Admins only;
// others see a short read-only note. It also offers a one-line pointer on
// empty states (Home, Search, Findings) for admins when there is no data.

let sampleInfo = null; // last api/sample reply (admins only), or null
let samplePoll = null; // interval id while a load or remove runs
let sampleConfirm = false; // true while Remove is in its confirm step

// fetchSample reads the sample-data status for admins and caches it.
async function fetchSample() {
  if (!can('admin')) { sampleInfo = null; return null; }
  try { sampleInfo = await api('api/sample'); } catch (_) { sampleInfo = null; }
  return sampleInfo;
}

// samplePointer returns a one-line admin pointer for an empty state, or null
// when it does not apply: not an admin, the feature is off, or sample data
// is already loaded or a job is running.
function samplePointer() {
  if (!can('admin') || !sampleInfo || !sampleInfo.available || sampleInfo.loaded || sampleInfo.running) return null;
  return el('span', { class: 'sample-hint' },
    icon('wand-sparkles', 'icon--sm'), ' New here? ',
    el('a', { href: '#data', 'data-page': 'data' }, 'Load sample data'),
    ' to try Signalith on a week of activity.');
}

function stopSamplePoll() {
  if (samplePoll) { clearInterval(samplePoll); samplePoll = null; }
}

// loadSampleCard draws the card when the Add data page opens.
function loadSampleCard() {
  const card = $('sample-card');
  if (!card) return;
  stopSamplePoll();
  sampleConfirm = false;
  if (!can('admin')) {
    card.hidden = false;
    fill(card, el('div', { class: 'card__head sample-card__head' },
      el('span', { class: 'sample-card__icon' }, icon('wand-sparkles')),
      el('div', {},
        el('h3', { class: 'card__title' }, 'Sample data'),
        el('p', { class: 'card__sub' }, 'An admin can load a week of made-up activity here to try Signalith.'))));
    return;
  }
  card.hidden = false;
  renderSampleCard(true);
  fetchSample().then(() => renderSampleCard());
}

function sampleHead() {
  return el('div', { class: 'card__head sample-card__head' },
    el('span', { class: 'sample-card__icon' }, icon('wand-sparkles')),
    el('div', {},
      el('h3', { class: 'card__title' }, 'Try it with sample data'),
      el('p', { class: 'card__sub' },
        'Load a week of made-up activity, with a few attacks hidden in it, to see detections, findings, risk and the dashboards come to life. Everything is fictional, and you remove it in one click.')));
}

// renderSampleCard draws the card body from the current status.
function renderSampleCard(loading) {
  const card = $('sample-card');
  if (!card || !can('admin')) return;
  if (loading) {
    fill(card, sampleHead(), el('div', { class: 'card__body sample-card__body' },
      el('p', { class: 'muted' }, 'Checking…')));
    return;
  }
  if (sampleInfo === null) {
    fill(card, sampleHead(), el('div', { class: 'card__body sample-card__body' },
      el('div', { class: 'empty__actions' },
        el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: loadSampleCard }, icon('refresh-cw'), 'Try again'))));
    return;
  }
  if (!sampleInfo.available) {
    fill(card, sampleHead(), el('div', { class: 'card__body sample-card__body' },
      el('p', { class: 'muted' }, 'Sample data is not available on this server.')));
    return;
  }
  let body;
  if (sampleInfo.running) body = sampleRunningBody();
  else if (sampleInfo.loaded) body = sampleLoadedBody();
  else body = sampleIdleBody();
  fill(card, sampleHead(), body);
}

// sampleIdleBody: nothing loaded. Pick a size and load.
function sampleIdleBody() {
  const size = el('select', { id: 'sample-size', class: 'select select--sm' },
    el('option', { value: 'standard' }, 'Standard (a full week, tens of thousands of events)'),
    el('option', { value: 'small' }, 'Small (a lighter set, quicker to load)'));
  const loadBtn = el('button', { type: 'button', class: 'btn btn--primary', onclick: () => sampleLoad(size.value) },
    icon('wand-sparkles'), 'Load sample data');
  return el('div', { class: 'card__body sample-card__body' },
    sampleInfo.error ? el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' },
      icon('circle-alert'), el('p', {}, 'The last run did not finish: ' + sampleInfo.error)) : null,
    el('div', { class: 'sample-load' },
      el('label', { class: 'sample-load__size' }, el('span', { class: 'label' }, 'How much'), size),
      loadBtn));
}

// sampleRunningBody: a load or remove is going. Show the step and poll.
function sampleRunningBody() {
  const verb = sampleInfo.op === 'remove' ? 'Removing' : 'Loading';
  const phase = sampleInfo.phase || 'Working';
  const pct = sampleInfo.total > 0 ? Math.round((sampleInfo.done / sampleInfo.total) * 100) : null;
  const bar = el('div', { class: 'sample-bar' + (pct === null ? ' sample-bar--indeterminate' : ''), role: 'progressbar',
    'aria-label': verb + ' sample data' },
    el('div', { class: 'sample-bar__fill', style: pct === null ? '' : 'width:' + pct + '%' }));
  if (pct !== null) { bar.setAttribute('aria-valuenow', String(pct)); bar.setAttribute('aria-valuemin', '0'); bar.setAttribute('aria-valuemax', '100'); }
  if (!samplePoll) samplePoll = setInterval(sampleTick, 1000);
  return el('div', { class: 'card__body sample-card__body' },
    el('p', { class: 'sample-phase' }, verb + ' sample data… ' + phase + (pct !== null ? ' (' + pct + '%)' : '')),
    bar);
}

// sampleLoadedBody: a set is loaded. Offer things to try and Remove.
function sampleLoadedBody() {
  const st = sampleInfo.state || {};
  const counts = el('div', { class: 'sample-counts' },
    sampleCount(st.events, 'events'),
    sampleCount(st.findings, 'findings'),
    sampleCount(st.risk_events, 'risk events'),
    sampleCount(st.indicators, 'intel matches'));
  const tries = [
    ['See the findings that fired', 'findings', 'shield-alert'],
    ['Watch risk build on users and hosts', 'risk', 'trending-up'],
    ['Open the investigation', 'cases', 'briefcase'],
    ['Light up the dashboards', 'dashboards', 'layout-dashboard'],
    ['Search the whole week', 'search', 'search'],
  ];
  const tryList = el('ul', { class: 'sample-try', role: 'list' },
    ...tries.map(([label, page, ic]) => el('li', {},
      el('a', { href: '#' + page, 'data-page': page }, icon(ic, 'icon--sm'), label))));
  const stories = (st.stories || []).map((s) => s.title).filter(Boolean);

  let actions;
  if (sampleConfirm) {
    actions = el('div', { class: 'sample-confirm', role: 'group', 'aria-label': 'Remove sample data?' },
      el('span', {}, 'Remove all sample data?'),
      el('button', { type: 'button', class: 'btn btn--danger btn--sm', onclick: sampleRemove }, 'Yes, remove it'),
      el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => { sampleConfirm = false; renderSampleCard(); } }, 'Cancel'));
  } else {
    actions = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => { sampleConfirm = true; renderSampleCard(); } },
      icon('x'), 'Remove sample data');
  }

  return el('div', { class: 'card__body sample-card__body' },
    el('div', { class: 'sample-loaded-head' },
      el('span', { class: 'sample-badge' }, icon('circle-check', 'icon--sm'), 'Loaded'),
      el('span', { class: 'muted' }, st.loaded_at ? ago(st.loaded_at) : '')),
    counts,
    el('div', { class: 'sample-try-wrap' },
      el('p', { class: 'label' }, 'Things to try'),
      tryList),
    stories.length ? el('p', { class: 'muted sample-stories' }, 'Hidden in it: ' + stories.join(', ') + '.') : null,
    el('div', { class: 'sample-actions' }, actions));
}

function sampleCount(n, label) {
  return el('div', { class: 'sample-count' },
    el('span', { class: 'sample-count__n' }, String(n == null ? 0 : n)),
    el('span', { class: 'sample-count__l' }, label));
}

// sampleTick polls the status while a job runs and re-renders when it ends.
async function sampleTick() {
  await fetchSample();
  if (!sampleInfo || !sampleInfo.running) {
    stopSamplePoll();
    renderSampleCard();
    if (sampleInfo && sampleInfo.error) toast('Sample data: ' + sampleInfo.error, null, { tone: 'danger' });
    else if (sampleInfo && sampleInfo.loaded) toast('Sample data loaded. Have a look around.');
    else toast('Sample data removed.');
    return;
  }
  renderSampleCard();
}

async function sampleLoad(size) {
  try {
    await api('api/sample/load', { size });
  } catch (e) {
    toast(e.message || 'Could not start the load.', null, { tone: 'danger' });
    await fetchSample();
    renderSampleCard();
    return;
  }
  await fetchSample();
  renderSampleCard();
  if (!samplePoll) samplePoll = setInterval(sampleTick, 1000);
}

async function sampleRemove() {
  sampleConfirm = false;
  try {
    await api('api/sample/remove', {});
  } catch (e) {
    toast(e.message || 'Could not start the removal.', null, { tone: 'danger' });
    await fetchSample();
    renderSampleCard();
    return;
  }
  await fetchSample();
  renderSampleCard();
  if (!samplePoll) samplePoll = setInterval(sampleTick, 1000);
}

// Prefetch the status once the role is known, so the empty-state pointers on
// Home, Search and Findings can appear on their first render for admins.
if (typeof meReady !== 'undefined') meReady.then(() => { if (can('admin')) fetchSample(); });
