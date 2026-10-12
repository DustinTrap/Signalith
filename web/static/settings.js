// Settings page (admins): how the server runs. The sections, the settings
// in them and what each one does come from api/settings (the registry in
// internal/config/settings.go); this page only draws them. Changes wait in
// drafts until Save sends them together. Settings that apply at once do so
// when saved; the others wait for "Restart now", which restarts Signalith
// inside the same process and reloads the page when it is back.
'use strict';

(function () {
  // S.view is the last api/settings reply. S.drafts holds the unsaved
  // changes by setting: { kind: 'value', value, raw } for a new value,
  // 'clear' to remove a saved password or key, 'reset' to take a setting
  // off the page. S.replacing marks secrets whose Replace box is open.
  const S = {
    view: null, seq: 0, drafts: {}, replacing: {}, fields: {}, sections: {}, controls: {},
    saveErr: null, tests: {}, restart: null, restartErr: '', pinned: '', pinnedY: 0, focusKey: '',
  };
  const DEFAULT_AI_URL = { anthropic: 'https://api.anthropic.com', openai: 'https://api.openai.com/v1' };
  const RESTART_NOTE = 'signalith.settingsRestarted';
  // Settings shown in a monospaced font: addresses, paths and names.
  const MONO = new Set(['url', 'address', 'list']);
  const MONO_KEYS = new Set(['server.tls_cert', 'server.tls_key', 'opensearch.index_prefix', 'assistant.model']);
  const SOURCE_FILE = 'signalith.yaml';

  // The connection tests: the settings each one reads, so only they make
  // its result out of date.
  const TESTS = {
    opensearch: {
      keys: ['opensearch.url', 'opensearch.username', 'opensearch.password', 'opensearch.tls_skip_verify'],
      path: 'api/settings/test/opensearch', button: 'Test connection', icon: 'network', busy: 'Connecting…',
      lead: 'Connects with the settings above, saved or not.',
    },
    assistant: {
      keys: ['assistant.provider', 'assistant.url', 'assistant.model', 'assistant.api_key'],
      path: 'api/settings/test/assistant', button: 'Test', icon: 'sparkles', busy: 'Asking the model…',
      lead: 'Asks the model one sample question with the settings above, saved or not.',
    },
  };

  // ---------- small helpers ----------
  const idOf = (key) => 'st-' + key.replace(/[^a-z0-9]+/gi, '-');
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const dirtyKeys = () => Object.keys(S.drafts);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const sectionOf = (key) => S.sections[key];
  const isShown = () => $('page-settings').classList.contains('active');
  const editable = () => !!(S.view && S.view.editable);
  const readOnly = (f) => f.locked || !editable();

  // origin is scheme://host:port of an address, with the default port
  // filled in, as the server compares them; '' for anything else.
  function origin(raw) {
    try {
      const u = new URL(String(raw || '').trim());
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
      return u.protocol.slice(0, -1) + '://' + u.hostname.toLowerCase() + ':' + (u.port || (u.protocol === 'https:' ? '443' : '80'));
    } catch (_) {
      return '';
    }
  }

  // current is a setting's value as the form has it now.
  function current(key) {
    const f = S.fields[key];
    const d = S.drafts[key];
    if (!f) return undefined;
    if (d && d.kind === 'value') return d.value;
    if (d && d.kind === 'reset') return f.reset_to ? f.reset_to.value : f.value;
    return f.value;
  }

  // sentToNow is where a saved secret would be sent with the form as it
  // is: the only place the server lets it go is f.sent_to.
  function sentToNow(key) {
    if (key === 'opensearch.password') return origin(current('opensearch.url'));
    if (key === 'assistant.api_key') {
      const p = current('assistant.provider');
      return p ? origin(current('assistant.url') || DEFAULT_AI_URL[p]) : '';
    }
    return '';
  }

  // parse reads a control's raw value as the setting's type.
  function parse(f, raw) {
    switch (f.type) {
      case 'number': {
        const t = String(raw).trim();
        if (t === '') return f.empty_means ? 0 : '';
        const n = Number(t);
        return Number.isFinite(n) ? n : t;
      }
      case 'bool': return !!raw;
      case 'list': return String(raw).split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
      case 'secret': return String(raw);
      default: return String(raw).trim();
    }
  }

  // show writes a value for people: On and Off, choice labels, and what
  // an empty value means.
  function show(f, v) {
    if (f.type === 'bool') return v ? 'On' : 'Off';
    if (f.type === 'list') return v && v.length ? v.join(', ') : (f.empty_means || 'none');
    if (f.type === 'choice') {
      const c = (f.choices || []).find((x) => x.value === v);
      if (c) return c.label;
    }
    if (v === '' || v == null || (f.type === 'number' && v === 0 && f.empty_means)) return f.empty_means || 'empty';
    return String(v);
  }

  // shortName names a setting outside its section, as in the restart
  // banner: "Listen address", "Syslog UDP address", "OpenSearch password".
  function shortName(key) {
    const f = S.fields[key];
    const sec = sectionOf(key);
    if (!f || !sec) return key;
    if (['general', 'web', 'search', 'detections', 'intel'].includes(sec.id)) return f.label;
    return sec.title + ' ' + noun(f.label);
  }
  // noun is a label inside a sentence: "Password" becomes "password",
  // while "API key" and "OpenSearch address" keep their capitals.
  const noun = (label) => (/^[A-Z][a-z]*(\s|$)/.test(label) ? label.charAt(0).toLowerCase() + label.slice(1) : label);
  function listWords(items) {
    if (items.length <= 1) return items.join('');
    return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
  }
  function uptime(s) {
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    return m ? `${m}m` : 'less than a minute';
  }

  // ---------- loading ----------
  pageHooks.push((name) => {
    if (name === 'settings') load();
  });

  async function load() {
    const seq = ++S.seq;
    if (!S.view) renderLoading();
    let v;
    try {
      v = await api('api/settings');
    } catch (e) {
      if (seq === S.seq && !S.view) renderError(e);
      else if (seq === S.seq && e.code !== 'forbidden') toastError('Couldn’t refresh the settings', e);
      return;
    }
    if (seq !== S.seq) return;
    S.view = v;
    render();
    focusSetting();
    if (v.restart.in_progress && !S.restart) watchRestart({ before: lastAt(v), started: Date.now(), external: true });
    // The page that asked for the restart leaves a note: in this tab's
    // storage, or in the address when it followed Signalith to a new one
    // (another origin, with its own storage).
    let note = null;
    try { note = sessionStorage.getItem(RESTART_NOTE); sessionStorage.removeItem(RESTART_NOTE); } catch (_) { /* storage may be blocked */ }
    if (new URLSearchParams(location.search).has('restarted')) {
      note = '1';
      try { history.replaceState(null, '', location.pathname + location.hash); } catch (_) { /* sandboxed */ }
    }
    const last = v.restart.last;
    if (note && last && last.ok) toast('Signalith restarted with the saved settings.', null, { title: 'Restarted' });
  }
  const lastAt = (v) => (v.restart.last ? v.restart.last.at : '');

  function renderLoading() {
    fill($('st-alerts'));
    fill($('st-nav'));
    $('st-main').setAttribute('aria-busy', 'true');
    fill($('st-main'), ...[0, 1, 2].map(() => el('div', { class: 'card st-card st-skel' },
      el('div', { class: 'st-card__head' }, dxSkel('120px')),
      el('div', { class: 'st-card__body' }, ...[0, 1].map(() => el('div', { class: 'st-field' },
        el('div', { class: 'st-field__text' }, dxSkel('140px'), dxSkel('70%')), el('div', {}, dxSkel('100%'))))))));
  }
  function renderError(e) {
    fill($('st-nav'));
    $('st-main').setAttribute('aria-busy', 'false');
    fill($('st-main'), el('div', { class: 'card' }, dxEmpty({
      tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load the settings', text: sentence(e.message), action: dxRetry(load),
    })));
  }

  // ---------- drawing ----------
  function render() {
    const v = S.view;
    S.fields = {};
    S.sections = {};
    S.controls = {};
    for (const sec of v.sections) {
      for (const f of sec.fields) { S.fields[f.key] = f; S.sections[f.key] = sec; }
    }
    // Drafts of settings that are now locked, or back to the value saved,
    // are no longer changes.
    for (const k of dirtyKeys()) {
      const f = S.fields[k];
      const d = S.drafts[k];
      if (!f || readOnly(f) || (d.kind === 'value' && f.type !== 'secret' && same(d.value, f.value))) delete S.drafts[k];
    }
    renderAlerts();
    renderNav();
    const main = $('st-main');
    main.setAttribute('aria-busy', 'false');
    fill(main, ...v.sections.map(sectionCard), aboutCard(), saveBar());
    for (const k of Object.keys(S.fields)) syncRow(k);
    syncAll();
    syncActive();
  }

  // openSetting opens the page at one setting, for links from other pages
  // (the syslog steps on Add data, turned-away senders on Health).
  window.openSetting = (key) => {
    S.focusKey = key;
    showPage('settings');
  };
  function focusSetting() {
    const key = S.focusKey;
    S.focusKey = '';
    const row = key && document.querySelector(`#st-main .st-field[data-key="${CSS.escape(key)}"]`);
    if (!row) return;
    const sec = sectionOf(key);
    row.scrollIntoView({ block: 'center' });
    S.pinned = sec.id;
    S.pinnedY = window.scrollY;
    markActive(sec.id);
    const ctl = S.controls[key];
    const target = ctl && !ctl.disabled ? ctl : $('st-sec-' + sec.id + '-title');
    if (target) target.focus({ preventScroll: true });
  }

  // ---- the list of sections ----
  function renderNav() {
    const items = S.view.sections.map((s) => [s.id, s.title]).concat([['about', 'About this server']]);
    fill($('st-nav'), el('ul', { class: 'st-nav__list', role: 'list' }, ...items.map(([id, title]) => el('li', {},
      el('button', { type: 'button', class: 'st-nav__item', 'data-sec': id, onclick: () => goToSection(id) },
        el('span', {}, title), el('span', { class: 'st-nav__mark', 'aria-hidden': 'true' }))))));
    syncActive();
  }

  function goToSection(id) {
    const card = $('st-sec-' + id);
    if (!card) return;
    card.scrollIntoView({ block: 'start' });
    S.pinned = id;
    S.pinnedY = window.scrollY;
    markActive(id);
    const t = $('st-sec-' + id + '-title');
    if (t) t.focus({ preventScroll: true });
  }
  function markActive(id) {
    document.querySelectorAll('#st-nav .st-nav__item').forEach((b) => {
      if (b.dataset.sec === id) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
    });
  }
  // syncActive highlights the section at the top of the window, or the
  // last one at the end of the page; a section just picked in the list
  // stays highlighted until the page scrolls.
  let activeFrame = 0;
  function syncActive() {
    activeFrame = 0;
    if (!S.view || !isShown()) return;
    if (S.pinned && Math.abs(window.scrollY - S.pinnedY) < 4) { markActive(S.pinned); return; }
    S.pinned = '';
    const cards = [...document.querySelectorAll('#st-main > .st-card[id]')];
    if (!cards.length) return;
    let cur = cards[0];
    for (const c of cards) if (c.getBoundingClientRect().top <= 140) cur = c;
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) cur = cards[cards.length - 1];
    markActive(cur.id.replace(/^st-sec-/, ''));
  }
  window.addEventListener('scroll', () => { if (!activeFrame) activeFrame = requestAnimationFrame(syncActive); }, { passive: true });

  // ---- the sections ----
  function sectionCard(sec) {
    const restart = sec.fields.filter((f) => f.apply === 'restart').length;
    const mixed = restart > 0 && restart < sec.fields.length;
    const tag = mixed ? null : restart
      ? el('span', { class: 'st-apply' }, icon('rotate-ccw', 'icon--sm'), 'Applies after a restart')
      : el('span', { class: 'st-apply' }, icon('zap', 'icon--sm'), 'Applies when saved');
    const titleId = 'st-sec-' + sec.id + '-title';
    return el('section', { class: 'card st-card', id: 'st-sec-' + sec.id, 'aria-labelledby': titleId },
      el('div', { class: 'st-card__head' },
        el('div', { class: 'st-card__heading' }, el('h3', { class: 'st-card__title', id: titleId, tabindex: '-1' }, sec.title),
          sec.help ? el('p', { class: 'st-card__desc' }, sec.help) : null),
        tag),
      el('div', { class: 'st-card__body' }, ...sec.fields.map((f) => fieldRow(f, mixed))),
      TESTS[sec.id] ? testBlock(sec.id) : null);
  }

  // fieldRow draws one setting: its label, help and where its value comes
  // from on the left; the control and any problem with it on the right.
  function fieldRow(f, mixed) {
    const id = idOf(f.key);
    const ctl = control(f, id);
    const labelAttrs = { class: 'st-field__label', id: id + '-label' };
    // A secret's box comes and goes; its label names the whole group.
    const label = f.type === 'secret' ? el('span', labelAttrs, f.label) : el('label', Object.assign(labelAttrs, { for: id }), f.label);
    const row = el('div', { class: 'st-field', 'data-key': f.key, 'data-type': f.type },
      el('div', { class: 'st-field__text' }, label,
        el('p', { class: 'st-field__help', id: id + '-help' }, f.help),
        mixed && f.apply === 'restart' ? el('p', { class: 'st-field__note' }, icon('rotate-ccw', 'icon--xs'), 'Applies after a restart') : null,
        el('div', { class: 'st-field__meta', id: id + '-meta' })),
      el('div', { class: 'st-field__control' }, ctl,
        el('div', { class: 'st-field__notes', id: id + '-notes' })));
    return row;
  }

  // rerenderRow draws a setting again after Reset, Replace and the like,
  // and puts focus on what takes the place of the button pressed.
  function rerenderRow(key, focus) {
    const old = document.querySelector(`#st-main .st-field[data-key="${CSS.escape(key)}"]`);
    if (!old) return;
    const sec = sectionOf(key);
    const restart = sec.fields.filter((f) => f.apply === 'restart').length;
    const row = fieldRow(S.fields[key], restart > 0 && restart < sec.fields.length);
    old.replaceWith(row);
    syncRow(key);
    syncAll();
    if (focus) {
      const target = typeof focus === 'string' ? row.querySelector(focus) : S.controls[key];
      if (target) target.focus();
    }
  }

  function inputFor(f, id, value) {
    const attrs = { id, class: 'input' + (MONO.has(f.type) || MONO_KEYS.has(f.key) ? ' mono' : ''), type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' };
    // An example reads as one, unless it is also what empty means.
    if (f.placeholder) attrs.placeholder = f.placeholder === f.empty_means ? f.placeholder : 'e.g. ' + f.placeholder;
    if (f.type === 'url') attrs.inputmode = 'url';
    if (f.type === 'duration' || f.type === 'number') attrs.class += ' st-input--short';
    if (f.type === 'number') {
      Object.assign(attrs, { type: 'number', inputmode: 'numeric', step: '1' });
      if (f.min != null) attrs.min = String(f.min);
      if (f.max != null) attrs.max = String(f.max);
      if (f.empty_means) attrs.placeholder = f.empty_means;
    }
    const n = el('input', attrs);
    n.value = value;
    return n;
  }

  // rawOf is what a control shows for a value.
  function rawOf(f, v) {
    if (f.type === 'list') return (v || []).join('\n');
    if (f.type === 'number' && v === 0 && f.empty_means) return '';
    return v == null ? '' : String(v);
  }

  function control(f, id) {
    const d = S.drafts[f.key];
    const ro = readOnly(f);
    if (f.type === 'secret') return secretControl(f, id);
    const value = d && d.kind === 'value' && d.raw != null ? d.raw : rawOf(f, current(f.key));
    let n;
    if (f.type === 'bool') {
      const box = el('input', { type: 'checkbox', id, role: 'switch' });
      box.checked = !!current(f.key);
      const state = el('span', { class: 'st-switch__state', 'aria-hidden': 'true' }, box.checked ? 'On' : 'Off');
      box.addEventListener('change', () => { state.textContent = box.checked ? 'On' : 'Off'; edited(f, box.checked); });
      if (ro) box.disabled = true;
      S.controls[f.key] = box;
      describe(box, f);
      return el('label', { class: 'switch st-switch' }, box, state);
    }
    if (f.type === 'choice') {
      n = el('select', { id, class: 'select select--block' });
      const choices = (f.choices || []).slice();
      if (!choices.some((c) => c.value === value)) choices.push({ value, label: value });
      for (const c of choices) {
        const o = el('option', { value: c.value }, c.label);
        if (c.value === value) o.selected = true;
        n.append(o);
      }
      n.addEventListener('change', () => edited(f, n.value));
    } else if (f.type === 'list') {
      n = el('textarea', { id, class: 'textarea mono', rows: '3', spellcheck: 'false', autocomplete: 'off', placeholder: f.placeholder ? 'e.g. ' + f.placeholder : '' });
      n.value = value;
      n.addEventListener('input', () => edited(f, n.value));
    } else {
      n = inputFor(f, id, value);
      n.addEventListener('input', () => edited(f, n.value));
    }
    if (ro) n.disabled = true;
    S.controls[f.key] = n;
    describe(n, f);
    return n;
  }
  function describe(n, f) {
    const id = idOf(f.key);
    n.setAttribute('aria-describedby', [id + '-help', id + '-meta', id + '-notes'].join(' '));
  }

  // secretControl shows a saved password or key as "Saved, hidden" with
  // Replace and Remove; it is never sent back to the page.
  function secretControl(f, id) {
    const d = S.drafts[f.key];
    const ro = readOnly(f);
    const box = el('div', { class: 'st-secret', role: 'group', 'aria-labelledby': id + '-label', 'aria-describedby': [id + '-help', id + '-meta', id + '-notes'].join(' ') });
    const status = (text, ...kids) => el('div', { class: 'st-secret__saved' }, icon('key-round', 'icon--sm'), el('span', {}, text), ...kids);
    if (ro) {
      box.append(status(f.set ? 'Saved, hidden' : 'Not set'));
      return box;
    }
    const removing = d && (d.kind === 'clear' || (d.kind === 'reset' && f.reset_to && !f.reset_to.set));
    const undo = () => el('button', { type: 'button', class: 'link-btn st-secret__undo', onclick: () => { delete S.drafts[f.key]; rerenderRow(f.key, '.st-secret__btn'); } }, 'Undo');
    if (removing) {
      box.append(el('div', { class: 'st-secret__saved is-removing' }, icon('trash-2', 'icon--sm'), el('span', {}, 'Removed when you save'), undo()));
      return box;
    }
    if (d && d.kind === 'reset') {
      box.append(status('Back to the one in ' + SOURCE_FILE + ' when you save', undo()));
      return box;
    }
    if (f.set && !S.replacing[f.key] && !d) {
      const replace = el('button', { type: 'button', class: 'btn btn--secondary btn--sm st-secret__btn', 'aria-label': 'Replace the ' + noun(f.label) }, 'Replace');
      replace.addEventListener('click', () => { S.replacing[f.key] = true; rerenderRow(f.key, true); });
      const remove = el('button', { type: 'button', class: 'btn btn--ghost btn--sm st-secret__btn', 'aria-label': 'Remove the ' + noun(f.label) }, 'Remove');
      remove.addEventListener('click', () => {
        // Off the page entirely when nothing else sets one; otherwise an
        // empty one here overrides signalith.yaml.
        S.drafts[f.key] = f.source.kind === 'page' && f.reset_to && !f.reset_to.set ? { kind: 'reset' } : { kind: 'clear' };
        rerenderRow(f.key, '.st-secret__undo');
      });
      box.append(el('div', { class: 'st-secret__row' }, status('Saved, hidden'), replace, remove));
      S.controls[f.key] = replace;
      return box;
    }
    const n = el('input', { id, class: 'input', type: 'password', autocomplete: 'new-password', spellcheck: 'false', placeholder: f.set ? 'Type the new one' : 'Not set' });
    n.setAttribute('aria-labelledby', id + '-label');
    n.value = d && d.kind === 'value' ? d.raw : '';
    n.addEventListener('input', () => edited(f, n.value));
    S.controls[f.key] = n;
    const kids = [n];
    if (f.set) {
      kids.push(el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => {
        delete S.replacing[f.key];
        delete S.drafts[f.key];
        rerenderRow(f.key, '.st-secret__btn');
      } }, 'Keep saved'));
    }
    box.append(el('div', { class: 'st-secret__input' }, ...kids));
    return box;
  }

  // edited records a change typed or picked in a control.
  function edited(f, raw) {
    const v = parse(f, raw);
    if (f.type === 'secret') {
      if (raw === '') delete S.drafts[f.key]; else S.drafts[f.key] = { kind: 'value', value: raw, raw };
    } else if (same(v, f.value)) {
      delete S.drafts[f.key];
    } else {
      S.drafts[f.key] = { kind: 'value', value: v, raw };
    }
    if (S.saveErr && S.saveErr.fields[f.key]) delete S.saveErr.fields[f.key];
    syncRow(f.key);
    syncAll();
  }

  // syncRow fills in a setting's notes: where its value comes from, and
  // under the control any problem, warning, or what an empty value means.
  function syncRow(key) {
    const f = S.fields[key];
    const id = idOf(key);
    const meta = $(id + '-meta');
    const notes = $(id + '-notes');
    if (!f || !meta || !notes) return;
    const d = S.drafts[key];
    const ro = readOnly(f);
    const bits = [];
    if (f.locked) {
      const n = el('p', { class: 'st-source st-source--env', title: f.locked_reason || '' }, icon('lock', 'icon--xs'),
        el('span', {}, 'Set by ', el('code', {}, f.source.env), '. To change it, change Signalith’s environment and restart.'));
      bits.push(n);
    } else if (d && d.kind === 'reset' && f.type !== 'secret') {
      const to = f.reset_to || {};
      bits.push(el('p', { class: 'st-source st-source--reset' }, icon('undo-2', 'icon--xs'),
        el('span', {}, to.source === 'file' ? `Back to ${show(f, to.value)} from ${SOURCE_FILE} when you save. ` : `Back to the default, ${show(f, to.value)}, when you save. `),
        el('button', { type: 'button', class: 'link-btn', onclick: () => { delete S.drafts[key]; rerenderRow(key, '.st-reset'); } }, 'Undo')));
    } else if (f.source.kind === 'page') {
      const who = f.source.by ? `Changed here by ${f.source.by}` : 'Changed here';
      const when = f.source.at ? el('span', { class: 'age', title: new Date(f.source.at).toLocaleString() }, ago(f.source.at)) : null;
      const reset = ro || (d && d.kind === 'reset') ? null : el('button', {
        type: 'button', class: 'link-btn st-reset',
        'aria-label': `Reset ${noun(f.label)} to the ${f.reset_to && f.reset_to.source === 'file' ? SOURCE_FILE : 'default'} value`,
        onclick: () => { S.drafts[key] = { kind: 'reset' }; delete S.replacing[key]; if (S.saveErr) delete S.saveErr.fields[key]; rerenderRow(key, f.type === 'secret' ? '.st-secret__undo' : '.link-btn'); },
      }, 'Reset');
      bits.push(el('p', { class: 'st-source' }, el('span', {}, who, when ? ', ' : '', when), reset ? el('span', { class: 'st-dot', 'aria-hidden': 'true' }) : null, reset));
    } else if (f.source.kind === 'file') {
      bits.push(el('p', { class: 'st-source' }, 'From ' + SOURCE_FILE));
    }
    if (f.pending && !d) bits.push(el('p', { class: 'st-source st-source--pending' }, icon('clock', 'icon--xs'), 'Saved. Waits for a restart.'));
    fill(meta, ...bits);

    const out = [];
    const problem = (S.saveErr && S.saveErr.fields[key]) || (!d ? f.problem : '');
    if (problem) out.push(el('p', { class: 'field-error', role: S.saveErr && S.saveErr.fields[key] ? 'alert' : null }, icon('circle-alert'), el('span', {}, sentence(problem))));
    if (f.warning && !d) out.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, f.warning)));
    // A saved secret is only sent to the address it was entered for.
    if (f.type === 'secret' && f.set && !ro && !d && f.sent_to && !(S.saveErr && S.saveErr.fields[key])) {
      const now = sentToNow(key);
      if (!now) {
        // Turned off: kept for when the same address comes back.
        out.push(el('p', { class: 'st-hint' }, 'Not sent anywhere now. Kept for ', el('span', { class: 'mono' }, f.sent_to), '.'));
      } else if (now !== f.sent_to) {
        out.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {},
          `Enter the ${noun(f.label)} again, or remove it: the saved one is only sent to ${f.sent_to}.`)));
      } else {
        out.push(el('p', { class: 'st-hint' }, 'Only sent to ', el('span', { class: 'mono' }, f.sent_to), '.'));
      }
    }
    if (f.empty_means && !ro && f.type !== 'number' && f.type !== 'secret' && f.type !== 'choice') {
      const v = current(key);
      if (v === '' || (Array.isArray(v) && !v.length)) out.push(el('p', { class: 'st-hint' }, 'When empty: ' + f.empty_means + '.'));
    }
    fill(notes, ...out);
    const c = S.controls[key];
    if (c && c.matches('input, select, textarea')) {
      if (problem) c.setAttribute('aria-invalid', 'true'); else c.removeAttribute('aria-invalid');
    }
    const row = notes.closest('.st-field');
    if (row) row.classList.toggle('is-changed', !!d);
  }

  // syncAll updates what depends on every draft: the save bar, the marks
  // in the section list, test results and the secrets' addresses.
  function syncAll() {
    const n = dirtyKeys().length;
    const bar = $('st-savebar');
    if (bar) {
      const problems = S.saveErr ? Object.keys(S.saveErr.fields).length + S.saveErr.problems.length : 0;
      bar.hidden = !n && !problems;
      const text = $('st-savebar-text');
      if (problems) {
        fill(text, el('span', { class: 'st-savebar__error' }, icon('circle-alert', 'icon--sm'),
          problems === 1 ? 'Nothing was saved. Fix the setting marked.' : `Nothing was saved. Fix the ${problems} settings marked.`), ' ',
        el('button', { type: 'button', class: 'link-btn', onclick: focusFirstProblem }, 'Show'));
      } else {
        fill(text, el('span', { class: 'st-savebar__dot', 'aria-hidden': 'true' }), n === 1 ? '1 unsaved change' : `${n} unsaved changes`);
      }
      $('st-save').disabled = !n;
      $('st-discard').hidden = !n;
      const general = $('st-savebar-general');
      fill(general, ...(S.saveErr && S.saveErr.problems.length ? [el('ul', { class: 'st-problems' }, ...S.saveErr.problems.map((p) => el('li', {}, sentence(p))))] : []));
      general.hidden = !general.firstChild;
    }
    // section marks: unsaved changes, problems
    document.querySelectorAll('#st-nav .st-nav__item').forEach((b) => {
      const sec = S.view.sections.find((s) => s.id === b.dataset.sec);
      const keys = sec ? sec.fields.map((f) => f.key) : [];
      const bad = keys.some((k) => (S.saveErr && S.saveErr.fields[k]) || (!S.drafts[k] && S.fields[k].problem));
      const changed = keys.some((k) => S.drafts[k]);
      const mark = b.querySelector('.st-nav__mark');
      mark.dataset.state = bad ? 'problem' : changed ? 'changed' : '';
      b.title = bad ? 'Needs fixing' : changed ? 'Unsaved changes' : '';
    });
    for (const k of ['opensearch.password', 'assistant.api_key']) if (S.fields[k]) syncRow(k);
    syncStale();
    syncRestartButton();
  }

  // ---- saving ----
  function saveBar() {
    const discard = el('button', { type: 'button', class: 'btn btn--ghost', id: 'st-discard' }, 'Discard');
    const save = el('button', { type: 'button', class: 'btn btn--primary', id: 'st-save' }, 'Save changes');
    discard.addEventListener('click', discardAll);
    save.addEventListener('click', saveAll);
    const bar = el('div', { class: 'st-savebar', id: 'st-savebar', role: 'region', 'aria-label': 'Unsaved changes' },
      el('div', { class: 'st-savebar__general', id: 'st-savebar-general' }),
      el('div', { class: 'st-savebar__row' }, el('span', { class: 'st-savebar__text', id: 'st-savebar-text', role: 'status' }),
        el('span', { class: 'spacer' }), discard, save));
    bar.hidden = true;
    return bar;
  }

  function discardAll() {
    S.drafts = {};
    S.replacing = {};
    S.saveErr = null;
    render();
    toast('Changes discarded.');
    const t = $('crumb-page');
    if (t) t.focus({ preventScroll: true });
  }

  // needsConfirm returns what a dangerous change asks before saving.
  function needsConfirm(key) {
    const f = S.fields[key];
    const d = S.drafts[key];
    if (!f || !f.confirm || !d) return null;
    const next = d.kind === 'reset' ? (f.reset_to ? f.reset_to.value : f.value) : d.value;
    if (same(next, f.value)) return null;
    if (f.confirm_when === 'on' && next !== true) return null;
    if (f.confirm_when === 'off' && next !== false) return null;
    return { f, next };
  }

  // confirmChanges asks once for every dangerous change, naming what each
  // one does. It resolves to true or false.
  function confirmChanges(list) {
    const d = modalDialog('st-confirm');
    d.classList.add('st-dialog');
    return new Promise((resolve) => {
      let answer = false;
      const one = list.length === 1 ? list[0] : null;
      let title = 'Save these changes?';
      if (one) {
        const short = shortName(one.f.key);
        title = one.f.type === 'bool' ? `Turn ${one.next ? 'on' : 'off'} “${one.f.label}”?` : `Change the ${noun(short)}?`;
      }
      const cancel = el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel');
      const ok = el('button', { type: 'button', class: 'btn btn--danger', onclick: () => { answer = true; d.close(); } }, 'Save changes');
      const item = ({ f, next }) => el('li', { class: 'st-confirm__item' },
        el('div', { class: 'st-confirm__what' }, el('b', {}, shortName(f.key)),
          f.type !== 'bool' ? el('span', { class: 'st-confirm__change' }, el('span', { class: 'mono' }, show(f, f.value)), icon('arrow-right', 'icon--xs'), el('span', { class: 'mono' }, show(f, next))) : null),
        el('p', {}, f.confirm));
      fill(d, modalHead('st-confirm', title, one ? null : 'Some of them change how Signalith works:', () => d.close()),
        el('div', { class: 'modal__body' }, el('ul', { class: 'st-confirm__list', role: 'list' }, ...list.map(item))),
        el('div', { class: 'modal__foot' }, cancel, ok));
      d.onclose = () => resolve(answer);
      d.showModal();
      cancel.focus();
    });
  }

  async function saveAll() {
    const keys = dirtyKeys();
    if (!keys.length) return;
    const risky = keys.map(needsConfirm).filter(Boolean);
    if (risky.length && !(await confirmChanges(risky))) { $('st-save').focus(); return; }
    const body = { values: {}, clear: [], reset: [] };
    for (const k of keys) {
      const d = S.drafts[k];
      if (d.kind === 'value') body.values[k] = d.value;
      else if (d.kind === 'clear') body.clear.push(k);
      else body.reset.push(k);
    }
    const restore = busy($('st-save'), 'Saving…');
    let v;
    try {
      v = await api('api/settings', body, 'PUT');
    } catch (e) {
      restore();
      if (e.status === 400 && e.fields) {
        const fields = {};
        const problems = (e.problems || []).slice();
        for (const [k, msg] of Object.entries(e.fields)) {
          if (S.fields[k] && !readOnly(S.fields[k])) fields[k] = msg; else problems.push((S.fields[k] ? S.fields[k].label + ': ' : '') + msg);
        }
        if (!Object.keys(fields).length && !problems.length) problems.push(e.message);
        S.saveErr = { fields, problems };
        for (const k of Object.keys(S.fields)) syncRow(k);
        syncAll();
        focusFirstProblem();
      } else if (e.code === 'settings_file') {
        S.saveErr = null;
        load();
        toastError('The settings were not saved', e);
      } else if (e.code !== 'forbidden') {
        toastError('The settings were not saved', e);
      }
      return;
    }
    const focusKey = keys[0];
    S.view = v;
    S.drafts = {};
    S.replacing = {};
    S.saveErr = null;
    render();
    const later = v.after_restart || [];
    const now = v.applied || [];
    if (later.length) {
      toast(now.length ? 'Some apply now. The rest wait for a restart.' : 'They apply after a restart.', null, { title: 'Saved' });
      const banner = $('st-restart');
      if (banner) { window.scrollTo({ top: 0 }); banner.focus({ preventScroll: true }); }
    } else {
      toast(now.length ? 'Saved. The changes apply now.' : 'Saved.');
      const c = S.controls[focusKey];
      if (c && !c.disabled) c.focus({ preventScroll: true });
    }
  }

  // focusFirstProblem goes to the first setting marked, preferring one
  // that was changed: a problem can also mark the settings it depends on.
  function focusFirstProblem() {
    const keys = Object.keys(S.fields).filter((k) => S.saveErr && S.saveErr.fields[k]);
    const first = keys.find((k) => S.drafts[k]) || keys[0];
    if (!first) { const g = $('st-savebar-general'); if (g) g.scrollIntoView({ block: 'nearest' }); return; }
    const row = document.querySelector(`#st-main .st-field[data-key="${CSS.escape(first)}"]`);
    if (row) row.scrollIntoView({ block: 'center' });
    const c = S.controls[first];
    if (c) c.focus({ preventScroll: true });
  }

  // Leaving with unsaved changes asks first, inside the app and out.
  leaveGuards.push((from, to, opts) => {
    if (from !== 'settings' || !dirtyKeys().length) return true;
    const n = dirtyKeys().length;
    caseConfirm({
      title: 'Discard your changes?',
      text: `${n === 1 ? 'One setting was' : n + ' settings were'} changed but not saved. Leave this page without saving?`,
      confirm: 'Discard changes',
    }).then((ok) => {
      if (!ok) { $('st-save').focus(); return; }
      S.drafts = {};
      S.replacing = {};
      S.saveErr = null;
      showPage(to, Object.assign({}, opts, { force: true }));
    });
    return false;
  });
  window.addEventListener('beforeunload', (ev) => {
    if (dirtyKeys().length && !S.restart) { ev.preventDefault(); ev.returnValue = ''; }
  });

  // ---- testing ----
  function testPayload(id) {
    const body = { values: {}, clear: [] };
    for (const k of TESTS[id].keys) {
      const f = S.fields[k];
      const d = S.drafts[k];
      if (!f || f.locked) continue;
      if (f.type === 'secret') {
        if (d && d.kind === 'value') body.values[k] = d.value;
        else if (d && (d.kind === 'clear' || (d.kind === 'reset' && f.reset_to && !f.reset_to.set))) body.clear.push(k);
        continue;
      }
      body.values[k] = current(k);
    }
    return body;
  }

  function testBlock(id) {
    const t = TESTS[id];
    const btn = el('button', { type: 'button', class: 'btn btn--secondary', id: 'st-test-' + id }, icon(t.icon), t.button);
    const out = el('div', { class: 'st-test__out', id: 'st-test-' + id + '-out', 'aria-live': 'polite' }, S.tests[id] ? testResult(id, S.tests[id].result) : null);
    btn.addEventListener('click', () => runTest(id));
    return el('div', { class: 'st-test' },
      el('div', { class: 'st-test__row' }, btn, el('p', { class: 'st-test__lead' }, t.lead)), out);
  }

  async function runTest(id) {
    const t = TESTS[id];
    const btn = $('st-test-' + id);
    const out = $('st-test-' + id + '-out');
    const body = testPayload(id);
    const snap = JSON.stringify(body);
    const restore = busy(btn, t.busy);
    fill(out, el('p', { class: 'st-test__busy' }, t.busy));
    out.classList.remove('is-stale');
    let r;
    try {
      r = await api(t.path, body);
    } catch (e) {
      r = e.status === 400 && e.fields ? { ok: false, fields: e.fields, message: e.message } : { ok: false, failed: true, message: sentence(e.message) };
    }
    restore();
    S.tests[id] = { result: r, snap };
    fill(out, testResult(id, r));
    syncStale();
  }

  // A test result says when the settings it used changed since.
  function syncStale() {
    for (const id of Object.keys(TESTS)) {
      const out = $('st-test-' + id + '-out');
      const t = S.tests[id];
      if (out) out.classList.toggle('is-stale', !!t && t.snap !== JSON.stringify(testPayload(id)));
    }
  }
  const staleNote = () => el('p', { class: 'st-stale' }, icon('info', 'icon--sm'), 'The settings changed since this test. Test again to check them.');

  // Which setting a failed test points at.
  const OS_PROBLEM = {
    unreachable: ['Couldn’t reach OpenSearch', 'opensearch.url'], tls: ['Certificate problem', 'opensearch.url'],
    http: ['HTTP and HTTPS don’t match', 'opensearch.url'], auth: ['Sign-in refused', 'opensearch.password'],
    forbidden: ['Signed in, but not allowed', 'opensearch.username'], not_opensearch: ['That’s not OpenSearch', 'opensearch.url'],
    error: ['OpenSearch answered with an error', ''],
  };
  function settingLink(key) {
    if (!key || !S.fields[key] || readOnly(S.fields[key])) return null;
    return el('button', { type: 'button', class: 'link-btn st-goto', onclick: () => {
      const row = document.querySelector(`#st-main .st-field[data-key="${CSS.escape(key)}"]`);
      if (row) row.scrollIntoView({ block: 'center' });
      const c = S.controls[key];
      if (c) c.focus({ preventScroll: true });
    } }, 'Show the setting', icon('arrow-right', 'icon--xs'));
  }

  function testResult(id, r) {
    const kids = [staleNote()];
    if (r.fields) {
      const keys = Object.keys(r.fields);
      kids.push(dxAlert('danger', 'Fix these settings first', null, el('div', {},
        el('ul', { class: 'st-problems' }, ...keys.map((k) => el('li', {}, el('b', {}, S.fields[k] ? S.fields[k].label + ': ' : ''), sentence(r.fields[k])))),
        settingLink(keys.find((k) => S.fields[k])))));
    } else if (r.failed) {
      kids.push(dxAlert('danger', 'Couldn’t run the test', r.message));
    } else if (id === 'opensearch') {
      if (r.ok) {
        const found = r.version && r.cluster_name ? `OpenSearch ${r.version}, cluster “${r.cluster_name}”. Health: ${r.health}.` : r.message;
        kids.push(dxAlert('success', 'Connected to OpenSearch', found, r.health && r.health !== 'green' ? el('p', {}, r.health === 'yellow'
          ? 'Yellow is normal with one OpenSearch node: there is nowhere to put the extra copies.'
          : 'Red means some data cannot be read. Check OpenSearch itself.') : null));
      } else {
        const [title, key] = OS_PROBLEM[r.problem] || ['Couldn’t connect', 'opensearch.url'];
        const field = r.problem === 'auth' && !current('opensearch.username') ? 'opensearch.username' : key;
        kids.push(dxAlert('danger', title, r.message, settingLink(field)));
      }
    } else if (r.ok) {
      const took = r.took_ms < 1000 ? 'in under a second' : `in ${(r.took_ms / 1000).toFixed(1)} seconds`;
      kids.push(dxAlert('success', 'The model answered ' + took, null, el('div', { class: 'st-test__qa' },
        el('p', {}, 'Asked: ', el('q', {}, r.question)),
        el('pre', { class: 'st-test__query mono' }, r.query))));
    } else {
      const key = /API key/i.test(r.message) ? 'assistant.api_key' : /not found/i.test(r.message) ? 'assistant.url' : '';
      kids.push(dxAlert('danger', 'The model didn’t answer', r.message, settingLink(key)));
    }
    return el('div', { class: 'st-result' }, ...kids);
  }

  // ---- about this server ----
  function aboutCard() {
    const v = S.view;
    const a = v.about || {};
    const file = v.settings_file || {};
    const facts = [
      ['Version', a.version || 'unknown'],
      ['Platform', (a.platform || '') + (a.container ? ', in a container' : '')],
    ];
    if (a.started) facts.push(['Running for', el('span', { title: 'Since ' + new Date(a.started).toLocaleString() }, uptime(a.uptime_seconds || 0))]);
    const kv = (rows) => el('dl', { class: 'kv st-kv' }, ...rows.flatMap(([k, val]) => [el('dt', {}, k), el('dd', {}, val)]));
    const pathRow = (p) => [p.label, el('span', { class: 'st-path' }, el('span', { class: 'mono' }, p.path || 'none'),
      p.source && p.source.kind === 'env' ? el('span', { class: 'st-path__note' }, icon('lock', 'icon--xs'), 'Set by ', el('code', {}, p.source.env)) : null)];
    const changed = (file.keys || []).length;
    const pages = (v.elsewhere || []).filter((x) => $('page-' + x.page));
    const exportLink = el('a', { class: 'btn btn--secondary', href: 'api/settings/export?download=1', download: 'signalith-settings.yaml' }, icon('download'), 'Download settings as YAML');
    const resetAll = changed && editable() ? el('button', { type: 'button', class: 'btn btn--ghost', id: 'st-reset-all', onclick: () => resetEverything() }, icon('undo-2'), 'Reset all') : null;
    return el('section', { class: 'card st-card st-about', id: 'st-sec-about', 'aria-labelledby': 'st-sec-about-title' },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' },
        el('h3', { class: 'st-card__title', id: 'st-sec-about-title', tabindex: '-1' }, 'About this server'),
        el('p', { class: 'st-card__desc' }, 'Where Signalith keeps its files. These are set in ' + SOURCE_FILE + ' only, because pages save into them.'))),
      el('div', { class: 'st-card__body st-about__body' },
        kv(facts),
        el('div', { class: 'st-about__part' }, el('h4', { class: 'section-title' }, 'Files and folders'), kv((a.paths || []).map(pathRow))),
        el('div', { class: 'st-about__part' }, el('h4', { class: 'section-title' }, 'Changed on this page'),
          el('p', { class: 'st-about__text' }, changed
            ? `${changed === 1 ? '1 setting is' : changed + ' settings are'} changed on this page and kept in the settings page file. Reset all puts back the values from ${SOURCE_FILE} or the defaults.`
            : `Nothing is changed on this page yet. Every setting comes from ${SOURCE_FILE}, the environment or the defaults.`),
          el('div', { class: 'btn-row' }, exportLink, resetAll),
          el('p', { class: 'st-hint' }, 'The download has the settings in the format of ' + SOURCE_FILE + ', for another server. Passwords and keys are left out.')),
        pages.length ? el('div', { class: 'st-about__part' }, el('h4', { class: 'section-title' }, 'Set up on other pages'),
          el('ul', { class: 'st-links', role: 'list' }, ...pages.map((x) => el('li', {},
            el('a', { href: '#' + x.page, 'data-page': x.page }, el('span', {}, x.what), icon('arrow-right', 'icon--xs')),
            x.detail ? el('span', { class: 'st-links__detail' }, x.detail) : null)))) : null));
  }

  async function resetEverything() {
    const n = ((S.view.settings_file || {}).keys || []).length;
    const ok = await caseConfirm({
      title: n === 1 ? 'Reset the setting changed here?' : `Reset all ${n} settings changed here?`,
      text: `They go back to the values in ${SOURCE_FILE}, or the defaults. Settings that need a restart wait for one.`,
      confirm: 'Reset all',
    });
    if (!ok) { const b = $('st-reset-all'); if (b) b.focus(); return; }
    let v;
    try {
      v = await api('api/settings', { reset_all: true }, 'PUT');
    } catch (e) {
      if (e.code !== 'forbidden') toastError('Nothing was reset', e);
      return;
    }
    S.view = v;
    S.drafts = {};
    S.replacing = {};
    S.saveErr = null;
    render();
    toast((v.after_restart || []).length ? 'Some changes wait for a restart.' : 'Every setting is back to ' + SOURCE_FILE + ' or its default.', null, { title: 'Reset' });
  }

  // ---------- the top of the page: problems and the restart ----------
  function renderAlerts() {
    const v = S.view;
    const out = [];
    const file = v.settings_file || {};
    if (file.error) {
      out.push(dxAlert('danger', 'The settings page file can’t be read', file.error, el('div', { class: 'btn-row st-alert-actions' },
        el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => resetEverything() }, 'Reset all settings'))));
    }
    if (v.startup_problem) out.push(dxAlert('warning', 'Signalith started without the settings saved here', v.startup_problem));
    if (!v.editable) out.push(dxAlert('info', 'These settings can’t be changed here', 'This server was started without a configuration file. Start it with one (signalith serve -c signalith.yaml) to change settings on this page.'));
    if ((v.problems || []).length) {
      out.push(dxAlert('danger', SOURCE_FILE + ' has problems', 'Fix them in the file on the server, then restart Signalith.',
        el('ul', { class: 'st-problems' }, ...v.problems.map((p) => el('li', {}, sentence(p))))));
    }
    for (const w of v.warnings || []) out.push(dxAlert('warning', sentence(w)));
    const banner = restartBanner();
    if (banner) out.push(banner);
    fill($('st-alerts'), ...out);
    syncRestartButton();
  }

  function restartBanner() {
    const v = S.view;
    const r = v.restart || {};
    const pending = v.pending || [];
    const last = r.last;
    const st = S.restart;
    const box = (tone, ...kids) => el('div', { class: 'st-banner', 'data-tone': tone, id: 'st-restart', tabindex: '-1', role: 'region', 'aria-label': 'Restart' }, ...kids);
    if (st) {
      if (st.timedOut) {
        return box('danger', icon('circle-alert'), el('div', { class: 'st-banner__body' },
          el('b', {}, 'Signalith hasn’t come back yet'),
          el('p', {}, 'It has not answered for 90 seconds. Check it on the server, for example with systemctl status signalith or docker compose logs signalith. If a saved setting stops it from starting, run signalith settings reset there.')),
        el('div', { class: 'st-banner__actions' }, el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => location.reload() }, icon('refresh-cw'), 'Reload the page')));
      }
      const moving = st.goTo ? el('p', {}, 'Signalith moves to ', el('span', { class: 'mono' }, st.goTo), '. This page follows it there.') : null;
      return box('progress', el('span', { class: 'st-spinner', 'aria-hidden': 'true' }), el('div', { class: 'st-banner__body', role: 'status' },
        el('b', {}, st.done ? 'Signalith is back. Reloading the page…' : st.external ? 'Signalith is restarting…' : 'Restarting Signalith…'),
        st.done ? null : el('p', {}, 'It checks the new settings first, and keeps the current ones if they can’t work. This usually takes a few seconds; the page reloads when it is back.'),
        moving, el('div', { class: 'st-progress', 'aria-hidden': 'true' }, el('span', {}))));
    }
    if (!pending.length) {
      if (S.restartErr) return box('danger', icon('circle-alert'), el('div', { class: 'st-banner__body' }, el('b', {}, 'Signalith didn’t restart'), el('p', {}, S.restartErr)));
      return null;
    }
    const names = pending.map((p) => shortName(p.key));
    const failed = last && !last.ok && same((last.keys || []).slice().sort(), pending.map((p) => p.key).sort());
    const changes = el('details', { class: 'st-banner__details' }, el('summary', {}, pending.length === 1 ? 'What changes' : `What changes (${pending.length})`),
      el('ul', { class: 'st-changes', role: 'list' }, ...pending.map((p) => {
        const f = S.fields[p.key];
        return el('li', {}, el('span', { class: 'st-changes__name' }, shortName(p.key)), p.secret || !f
          ? el('span', { class: 'st-changes__val' }, 'changed')
          : el('span', { class: 'st-changes__val' }, el('span', { class: 'mono' }, show(f, p.old)), icon('arrow-right', 'icon--xs'), el('span', { class: 'mono' }, show(f, p.new))));
      })));
    const body = [];
    if (failed) {
      body.push(el('b', {}, last.rolled_back ? 'The restart went back to the previous settings' : 'The restart didn’t apply the changes'),
        el('p', {}, sentence(last.error)), el('p', { class: 'st-banner__meta' }, `Still waiting: ${listWords(names)}.`));
    } else {
      body.push(el('b', {}, `Restart Signalith to apply: ${listWords(names)}`));
      body.push(el('p', {}, r.available ? 'Saved changes wait for a restart. Signalith restarts in a few seconds and everyone stays signed in.' : (r.unavailable || 'Restart Signalith on the server to apply them.')));
    }
    if (S.restartErr) body.push(el('p', { class: 'st-banner__error' }, icon('circle-alert', 'icon--sm'), S.restartErr));
    if (r.blocked) body.push(el('p', { class: 'st-banner__error' }, icon('circle-alert', 'icon--sm'), r.blocked));
    if (r.available) body.push(el('p', { class: 'st-banner__error st-banner__dirty', id: 'st-restart-dirty', hidden: '' }, 'Save or discard the changes on this page first.'));
    body.push(changes);
    const btn = r.available ? el('button', { type: 'button', class: 'btn btn--primary', id: 'st-restart-now' }, icon('rotate-ccw'), failed ? 'Try again' : 'Restart now') : null;
    if (btn) btn.addEventListener('click', () => restartNow(btn));
    return box(failed ? 'warning' : 'info', icon(failed ? 'triangle-alert' : 'rotate-ccw'), el('div', { class: 'st-banner__body' }, ...body),
      btn ? el('div', { class: 'st-banner__actions' }, btn) : null);
  }

  // The restart button waits for unsaved changes to be saved or discarded,
  // and is the page's main button only while there are none.
  function syncRestartButton() {
    const btn = $('st-restart-now');
    if (!btn) return;
    const dirty = dirtyKeys().length > 0;
    const blocked = !!(S.view.restart && S.view.restart.blocked);
    btn.disabled = dirty || blocked;
    btn.classList.toggle('btn--primary', !dirty);
    btn.classList.toggle('btn--secondary', dirty);
    const note = $('st-restart-dirty');
    if (note) note.hidden = !dirty;
  }

  async function restartNow(btn) {
    S.restartErr = '';
    const before = lastAt(S.view);
    const restore = busy(btn, 'Restarting…');
    let res;
    try {
      res = await api('api/settings/restart', {});
    } catch (e) {
      restore();
      if (e.code === 'restarting') { watchRestart({ before, started: Date.now(), external: true }); return; }
      if (e.code !== 'forbidden') {
        S.restartErr = sentence(e.message);
        renderAlerts();
        const b = $('st-restart');
        if (b) b.focus();
      }
      return;
    }
    watchRestart({ before, started: Date.now(), goTo: res.go_to || '' });
  }

  // watchRestart shows the restart under way and asks the server how it
  // went until it has finished: then the page reloads (at the new address
  // when the web address moved), or shows why the settings were kept.
  async function watchRestart(st) {
    S.restart = st;
    renderAlerts();
    const b = $('st-restart');
    if (b && !st.external) b.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
    while (S.restart === st) {
      await sleep(1000);
      if (S.restart !== st) return;
      if (Date.now() - st.started > 90000) { st.timedOut = true; renderAlerts(); return; }
      let v;
      try {
        // Requests wait while the server switches; one that waits too
        // long is answered 503, which only means "ask again".
        v = await api('api/settings');
      } catch (_) {
        continue;
      }
      if (v.restart.in_progress || lastAt(v) === st.before) continue;
      const last = v.restart.last;
      if (last && last.ok && !st.external) {
        st.done = true;
        renderAlerts();
        try { sessionStorage.setItem(RESTART_NOTE, '1'); } catch (_) { /* ignore */ }
        if (st.goTo) location.assign(st.goTo.replace(/[?#].*$/, '') + '?restarted=1#settings'); else location.reload();
        return;
      }
      S.restart = null;
      S.view = v;
      render();
      const banner = $('st-restart');
      if (banner && !st.external) banner.focus();
      if (last && last.ok && st.external) toast('Signalith restarted with the saved settings.', null, { title: 'Restarted' });
      return;
    }
  }
}());
