// Floating tri-state theme toggle in the top-right of every page. Cycles
// system -> light -> dark on click, persists the choice in localStorage.
//
// The inline bootstrap script in <head> already applied the right theme
// before paint. This file just renders the visible button and hooks up
// the click handler.

(function () {
  'use strict';

  var STORAGE_KEY = 'transfersh_theme';
  var ORDER = ['system', 'light', 'dark'];
  var TEXT_FALLBACK = { light: '☀', dark: '☾', system: '◐' }; // sun, moon, half-circle
  var root = document.documentElement;

  function stored() {
    try {
      var v = localStorage.getItem(STORAGE_KEY);
      if (v === 'light' || v === 'dark' || v === 'system') return v;
    } catch (_) {}
    return null;
  }

  function serverDefault() {
    var d = root.getAttribute('data-theme-default');
    return (d === 'light' || d === 'dark' || d === 'system') ? d : 'system';
  }

  function current() {
    return stored() || serverDefault();
  }

  function apply(theme) {
    if (theme === 'light' || theme === 'dark') {
      root.setAttribute('data-theme', theme);
    } else {
      root.removeAttribute('data-theme');
    }
  }

  function iconFor(theme) {
    if (theme === 'light') return 'sun';
    if (theme === 'dark') return 'moon';
    return 'monitor';
  }

  // Render every static <i data-lucide="..."> the server emitted (admin
  // table actions, footer github icon, etc). theme-toggle.js loads after
  // lucide and after the page-specific scripts, so this is the natural
  // place to do a one-shot global pass.
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    window.lucide.createIcons({ nameAttr: 'data-lucide' });
  }

  var btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'theme-toggle';
  btn.setAttribute('aria-label', 'Switch theme');
  document.body.appendChild(btn);

  function render(theme) {
    btn.title = 'Theme: ' + theme + ' (click to cycle)';
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      btn.innerHTML = '<i data-lucide="' + iconFor(theme) + '"></i>';
      window.lucide.createIcons({ nameAttr: 'data-lucide' });
    } else {
      btn.textContent = TEXT_FALLBACK[theme] || '?';
    }
  }

  render(current());

  btn.addEventListener('click', function () {
    var cur = current();
    var idx = ORDER.indexOf(cur);
    if (idx < 0) idx = 0;
    var next = ORDER[(idx + 1) % ORDER.length];
    try { localStorage.setItem(STORAGE_KEY, next); } catch (_) {}
    apply(next);
    render(next);
  });
})();
