// Sign-in page. Posts the form as JSON and, on success, returns to the page
// the user first asked for.
'use strict';

(function () {
  const form = document.getElementById('login-form');
  const user = document.getElementById('username');
  const pass = document.getElementById('password');
  const remember = document.getElementById('remember');
  const errorBox = document.getElementById('login-error');
  const submit = form.querySelector('button[type=submit]');
  const reveal = document.getElementById('reveal');

  // Only same-site paths are allowed as the return address, so a crafted
  // link cannot send someone to another site after signing in.
  function nextPath() {
    const next = new URLSearchParams(location.search).get('next') || '/';
    return next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = !msg;
    form.classList.toggle('has-error', !!msg);
  }

  if (reveal) {
    reveal.addEventListener('click', () => {
      const show = pass.type === 'password';
      pass.type = show ? 'text' : 'password';
      reveal.setAttribute('aria-pressed', String(show));
      reveal.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      pass.focus();
    });
  }

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!user.value.trim() || !pass.value) {
      showError('Enter your username and password.');
      (user.value.trim() ? pass : user).focus();
      return;
    }
    showError('');
    submit.disabled = true;
    form.classList.add('busy');
    try {
      const resp = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user.value.trim(), password: pass.value, remember: remember ? remember.checked : false }),
      });
      if (resp.ok) {
        location.replace(nextPath());
        return;
      }
      const data = await resp.json().catch(() => ({}));
      showError(resp.status === 401 ? 'That username and password did not match.' : (data.error || 'Sign-in failed. Try again.'));
      pass.select();
    } catch (_) {
      showError('Could not reach the Signalith server.');
    } finally {
      submit.disabled = false;
      form.classList.remove('busy');
    }
  });

  (user.value ? pass : user).focus();
}());
