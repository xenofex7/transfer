// Tiny toast notifier. Stack of floating cards in the top-right corner,
// auto-dismisses after a few seconds. Exposes window.toast.
//
// Usage:
//   toast.success('Link copied to clipboard');
//   toast.error('Upload failed: ' + err);
//   toast.info('Saved');
//
// Loaded after lucide.min.js so we can render icons via createIcons.

(function () {
  'use strict';

  var DEFAULT_TTL = 2800; // ms

  var container;

  function ensureContainer() {
    if (container) return container;
    container = document.createElement('div');
    container.className = 'toast-container';
    container.setAttribute('aria-live', 'polite');
    container.setAttribute('aria-atomic', 'false');
    document.body.appendChild(container);
    return container;
  }

  function iconFor(kind) {
    if (kind === 'success') return 'check-circle-2';
    if (kind === 'error') return 'alert-circle';
    return 'info';
  }

  function show(message, opts) {
    opts = opts || {};
    var kind = opts.kind || 'info';
    var ttl = typeof opts.ttl === 'number' ? opts.ttl : DEFAULT_TTL;

    var c = ensureContainer();
    var t = document.createElement('div');
    t.className = 'toast toast-' + kind;
    t.setAttribute('role', kind === 'error' ? 'alert' : 'status');

    t.innerHTML =
      '<span class="toast-icon"><i data-lucide="' + iconFor(kind) + '"></i></span>' +
      '<span class="toast-msg"></span>' +
      '<button type="button" class="toast-close" aria-label="Dismiss"><i data-lucide="x"></i></button>';
    t.querySelector('.toast-msg').textContent = message;

    c.appendChild(t);
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons({ nameAttr: 'data-lucide' });
    }

    // Animate in on the next frame so the transition fires.
    requestAnimationFrame(function () { t.classList.add('is-in'); });

    var dismissed = false;
    function dismiss() {
      if (dismissed) return;
      dismissed = true;
      t.classList.remove('is-in');
      t.classList.add('is-out');
      setTimeout(function () { t.parentNode && t.parentNode.removeChild(t); }, 220);
    }

    t.querySelector('.toast-close').addEventListener('click', dismiss);
    if (ttl > 0) setTimeout(dismiss, ttl);

    return { dismiss: dismiss };
  }

  window.toast = {
    show: show,
    success: function (msg, opts) { return show(msg, Object.assign({ kind: 'success' }, opts || {})); },
    error: function (msg, opts) { return show(msg, Object.assign({ kind: 'error', ttl: 5000 }, opts || {})); },
    info: function (msg, opts) { return show(msg, Object.assign({ kind: 'info' }, opts || {})); },
  };
})();
