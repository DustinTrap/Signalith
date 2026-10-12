// Applies the saved light or dark choice before the page paints. Without a
// saved choice the page follows the system setting.
'use strict';
try {
  const t = localStorage.getItem('signalith.theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
} catch (_) { /* storage may be blocked */ }
