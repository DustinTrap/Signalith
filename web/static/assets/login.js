// Sign-in page. Posts the form as JSON and, on success, returns to the page
// the user first asked for.
'use strict';

(function () {
  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  const auth = document.querySelector('.auth');
  const form = $('login-form');
  const user = $('username');
  const pass = $('password');
  const remember = $('remember');
  const submit = $('login-submit');
  const submitLabel = $('login-submit-label');
  const reveal = $('reveal');
  const caps = $('caps-hint');
  const forgot = $('forgot');
  const forgotNote = $('forgot-note');
  const params = new URLSearchParams(location.search);
  let lockTimer = null;

  // Only a path on this site is allowed as the return address, so a crafted
  // link cannot send someone to another site after signing in. The check
  // compares the resolved origin, because browsers drop tabs and newlines
  // and read \ as /, which turns "/<tab>/evil.example" into another site.
  // Without ?next, a #page the browser kept through the redirect applies.
  function nextPath() {
    const home = new URL('./', location.href).pathname + location.hash;
    const next = params.get('next');
    if (!next || !next.startsWith('/')) return home;
    try {
      const u = new URL(next, location.href);
      // The full URL, not the path: "/.//evil.example" resolves to the
      // path "//evil.example", which on its own would leave the site.
      return u.origin === location.origin ? u.href : home;
    } catch (_) {
      return home;
    }
  }

  // setView shows one of the messages above the form: error, locked,
  // signedout, or none.
  function setView(view) {
    auth.dataset.view = view || '';
    if (view === 'error') pass.setAttribute('aria-invalid', 'true');
    else pass.removeAttribute('aria-invalid');
  }

  function showError(title, text) {
    $('login-error-title').textContent = title;
    $('login-error-text').textContent = text || '';
    $('login-error-text').hidden = !text;
    setView('error');
  }

  function sentence(s) {
    s = String(s || '').trim();
    if (!s) return '';
    s = s.charAt(0).toUpperCase() + s.slice(1);
    return /[.!?]$/.test(s) ? s : s + '.';
  }

  function setBusy(busy) {
    submit.disabled = busy;
    submitLabel.textContent = busy ? 'Signing in…' : 'Sign in';
  }

  // locked pauses the form until the server's Retry-After has passed.
  function locked(message, seconds) {
    $('login-locked-text').textContent = sentence(message) || 'Too many failed sign-ins from this address. Try again later.';
    setView('locked');
    submit.disabled = true;
    clearTimeout(lockTimer);
    const wait = Number(seconds);
    if (wait > 0) {
      lockTimer = setTimeout(() => {
        submit.disabled = false;
        if (auth.dataset.view === 'locked') setView('');
      }, wait * 1000);
    }
  }

  if (params.has('signedout')) setView('signedout');

  reveal.addEventListener('click', () => {
    const show = pass.type === 'password';
    pass.type = show ? 'text' : 'password';
    reveal.setAttribute('aria-pressed', String(show));
    reveal.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    reveal.title = show ? 'Hide password' : 'Show password';
    reveal.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
    pass.focus();
  });

  forgot.addEventListener('click', () => {
    const open = forgotNote.hidden;
    forgotNote.hidden = !open;
    forgot.setAttribute('aria-expanded', String(open));
  });

  // Caps Lock hint while typing the password.
  const capsCheck = (ev) => {
    if (ev.getModifierState) caps.toggleAttribute('data-on', ev.getModifierState('CapsLock'));
  };
  pass.addEventListener('keydown', capsCheck);
  pass.addEventListener('keyup', capsCheck);
  pass.addEventListener('blur', () => caps.removeAttribute('data-on'));

  // The theme toggle saves the choice under the same key as the app.
  document.querySelectorAll('[data-theme-toggle]').forEach((b) => b.addEventListener('click', () => {
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('signalith.theme', root.dataset.theme); } catch (_) { /* storage may be blocked */ }
  }));

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (submit.disabled) return;
    if (!user.value.trim() || !pass.value) {
      showError('Enter your username and password.', '');
      (user.value.trim() ? pass : user).focus();
      return;
    }
    setBusy(true);
    let resp;
    try {
      resp = await fetch('api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user.value.trim(), password: pass.value, remember: remember.checked }),
      });
    } catch (_) {
      setBusy(false);
      showError('Could not reach the Signalith server.', 'Check your connection and try again.');
      return;
    }
    if (resp.ok) {
      location.replace(nextPath());
      return;
    }
    const data = await resp.json().catch(() => ({}));
    setBusy(false);
    if (resp.status === 429) {
      locked(data.error, resp.headers.get('Retry-After'));
      return;
    }
    if (resp.status === 401) showError('That username and password don’t match.', 'After 10 failed attempts, sign-in pauses for 15 minutes.');
    else showError('Sign-in failed.', sentence(data.error) || 'Try again.');
    pass.select();
  });

  (user.value ? pass : user).focus();
}());
