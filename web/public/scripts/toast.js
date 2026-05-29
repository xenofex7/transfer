// Toast notifier - baseline-spec.
//
// Variants: success | warning | danger | neutral (alias: info, error)
// Stack:    max 3 visible, newest at bottom, older queue surfaces as
//           earlier ones dismiss.
// Auto-dismiss defaults:
//   - success / neutral   4000 ms
//   - warning             6000 ms
//   - danger              never (sticky, requires user click)
// Hovering a toast pauses its dismiss timer; resumes on hover-out.
// Toasts with an action (opts.action) are sticky regardless of variant.
//
// Usage:
//   toast.success('Link copied');
//   toast.warning('Storage nearly full');
//   toast.danger('Upload failed: ' + err);
//   toast.neutral('Saved');                // == toast.info(...)
//   toast.show('msg', { kind: 'success', ttl: 6000 });
//
// Loaded after lucide.min.js so we can render icons via createIcons.

(function () {
  'use strict';

  var MAX_VISIBLE = 3;
  var TRANSITION_MS = 220;
  var DEFAULT_TTL = {
    success: 4000,
    neutral: 4000,
    warning: 6000,
    danger:  0,   // 0 == sticky
  };

  var KIND_ALIAS = {
    info:  'neutral',
    error: 'danger',
  };

  var container = null;
  var queue = [];
  var visible = [];

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
    if (kind === 'warning') return 'alert-triangle';
    if (kind === 'danger')  return 'alert-circle';
    return 'info';
  }

  function renderLucide() {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons({ nameAttr: 'data-lucide' });
    }
  }

  function buildToast(message, kind, opts) {
    var t = document.createElement('div');
    t.className = 'toast toast-' + kind;
    t.setAttribute('role', kind === 'danger' ? 'alert' : 'status');

    t.innerHTML =
      '<span class="toast-icon"><i data-lucide="' + iconFor(kind) + '"></i></span>' +
      '<span class="toast-msg"></span>' +
      '<button type="button" class="toast-close" aria-label="Dismiss"><i data-lucide="x"></i></button>';
    t.querySelector('.toast-msg').textContent = message;

    return t;
  }

  function show(message, opts) {
    opts = opts || {};
    var kind = opts.kind || 'neutral';
    if (KIND_ALIAS[kind]) kind = KIND_ALIAS[kind];
    if (!DEFAULT_TTL.hasOwnProperty(kind)) kind = 'neutral';

    var ttl = typeof opts.ttl === 'number' ? opts.ttl : DEFAULT_TTL[kind];
    if (opts.action) ttl = 0;  // toasts with actions are sticky

    var item = {
      message: message,
      kind: kind,
      ttl: ttl,
      el: null,
      timer: null,
      remaining: ttl,
      lastResume: 0,
      dismissed: false,
    };

    queue.push(item);
    pump();

    return {
      dismiss: function () { dismiss(item); },
    };
  }

  function pump() {
    while (visible.length < MAX_VISIBLE && queue.length > 0) {
      var item = queue.shift();
      mount(item);
    }
  }

  function mount(item) {
    var c = ensureContainer();
    item.el = buildToast(item.message, item.kind);
    c.appendChild(item.el);
    renderLucide();
    visible.push(item);

    requestAnimationFrame(function () { item.el.classList.add('is-in'); });

    item.el.querySelector('.toast-close').addEventListener('click', function () {
      dismiss(item);
    });

    if (item.ttl > 0) {
      item.el.addEventListener('mouseenter', function () { pauseTimer(item); });
      item.el.addEventListener('mouseleave', function () { startTimer(item); });
      startTimer(item);
    }
  }

  function startTimer(item) {
    if (item.ttl <= 0 || item.dismissed) return;
    item.lastResume = Date.now();
    item.timer = setTimeout(function () { dismiss(item); }, item.remaining);
  }

  function pauseTimer(item) {
    if (!item.timer) return;
    clearTimeout(item.timer);
    item.timer = null;
    var elapsed = Date.now() - item.lastResume;
    item.remaining = Math.max(0, item.remaining - elapsed);
  }

  function dismiss(item) {
    if (item.dismissed) return;
    item.dismissed = true;
    if (item.timer) { clearTimeout(item.timer); item.timer = null; }
    if (!item.el) return;
    item.el.classList.remove('is-in');
    item.el.classList.add('is-out');
    setTimeout(function () {
      if (item.el && item.el.parentNode) item.el.parentNode.removeChild(item.el);
      visible = visible.filter(function (v) { return v !== item; });
      pump();
    }, TRANSITION_MS);
  }

  window.toast = {
    show:    show,
    success: function (msg, opts) { return show(msg, Object.assign({ kind: 'success' }, opts || {})); },
    warning: function (msg, opts) { return show(msg, Object.assign({ kind: 'warning' }, opts || {})); },
    danger:  function (msg, opts) { return show(msg, Object.assign({ kind: 'danger'  }, opts || {})); },
    neutral: function (msg, opts) { return show(msg, Object.assign({ kind: 'neutral' }, opts || {})); },
    // Backward-compatible aliases:
    info:    function (msg, opts) { return show(msg, Object.assign({ kind: 'neutral' }, opts || {})); },
    error:   function (msg, opts) { return show(msg, Object.assign({ kind: 'danger'  }, opts || {})); },
  };
})();
