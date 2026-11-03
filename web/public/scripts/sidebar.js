// Off-canvas sidebar toggle for the admin/account shell (mobile only;
// on >=768px the sidebar is static and these controls are hidden).

(function () {
  'use strict';

  var sidebar = document.getElementById('sidebar');
  var openBtn = document.getElementById('sidebar-open');
  var closeBtn = document.getElementById('sidebar-close');
  var overlay = document.getElementById('sidebar-overlay');

  if (!sidebar || !openBtn) return;

  function isOpen() {
    return sidebar.classList.contains('is-open');
  }

  function setOpen(open) {
    var hadFocus = sidebar.contains(document.activeElement);
    sidebar.classList.toggle('is-open', open);
    openBtn.setAttribute('aria-expanded', String(open));
    if (overlay) overlay.hidden = !open;
    document.body.classList.toggle('sidebar-locked', open);
    if (open) {
      (closeBtn || sidebar.querySelector('a, button')).focus();
    } else if (hadFocus) {
      openBtn.focus();
    }
  }

  openBtn.addEventListener('click', function () { setOpen(true); });
  if (closeBtn) closeBtn.addEventListener('click', function () { setOpen(false); });
  if (overlay) overlay.addEventListener('click', function () { setOpen(false); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && isOpen()) setOpen(false);
  });
})();
