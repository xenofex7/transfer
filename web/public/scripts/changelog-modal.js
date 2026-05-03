// Click handler on .footer-version that opens a modal showing the
// embedded CHANGELOG.md (rendered server-side via blackfriday). Cached
// after the first fetch so reopening is instant.
//
// Loaded on every page after lucide so the close button can use a Lucide
// X icon.

(function () {
  'use strict';

  var trigger = document.querySelector('.footer-version');
  if (!trigger || !trigger.textContent.trim()) return;

  // Make the version look + behave like an interactive control.
  trigger.classList.add('footer-version-link');
  trigger.setAttribute('role', 'button');
  trigger.setAttribute('tabindex', '0');
  trigger.title = 'View changelog';

  var cachedHTML = null;
  var cachedVersion = null;
  var modal, backdrop, body, escListener;

  function open() {
    if (modal) return;
    backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.innerHTML =
      '<div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">' +
        '<header class="modal-head">' +
          '<h2 class="modal-title" id="modal-title">Changelog</h2>' +
          '<button type="button" class="modal-close" aria-label="Close"><i data-lucide="x"></i></button>' +
        '</header>' +
        '<div class="modal-body" id="modal-body"><p style="color:var(--text-dim)">Loading...</p></div>' +
      '</div>';
    document.body.appendChild(backdrop);
    modal = backdrop.querySelector('.modal');
    body = backdrop.querySelector('#modal-body');

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons({ nameAttr: 'data-lucide' });
    }

    requestAnimationFrame(function () { backdrop.classList.add('is-in'); });

    backdrop.addEventListener('click', function (e) {
      if (e.target === backdrop) close();
    });
    backdrop.querySelector('.modal-close').addEventListener('click', close);

    escListener = function (e) { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', escListener);

    if (cachedHTML !== null) {
      render(cachedHTML, cachedVersion);
    } else {
      fetch('/changelog.json', { credentials: 'same-origin' })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (data) {
          cachedHTML = data.html || '';
          cachedVersion = data.version || '';
          render(cachedHTML, cachedVersion);
        })
        .catch(function (err) {
          body.innerHTML = '<p style="color:var(--danger)">Could not load changelog: ' + err.message + '</p>';
        });
    }
  }

  function render(html, version) {
    body.innerHTML = html;
    if (version) {
      var title = backdrop.querySelector('#modal-title');
      if (title) title.textContent = 'Changelog — currently running ' + version;
    }
  }

  function close() {
    if (!backdrop) return;
    backdrop.classList.remove('is-in');
    var b = backdrop;
    setTimeout(function () { b.parentNode && b.parentNode.removeChild(b); }, 180);
    document.removeEventListener('keydown', escListener);
    backdrop = modal = body = null;
  }

  trigger.addEventListener('click', open);
  trigger.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
  });
})();
