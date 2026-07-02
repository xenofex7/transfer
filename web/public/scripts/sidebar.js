// Off-canvas sidebar toggle for the admin/account shell (mobile only;
// on >=768px the sidebar is static and these controls are hidden).

(function () {
  'use strict';

  var sidebar = document.getElementById('sidebar');
  var openBtn = document.getElementById('sidebar-open');
  var closeBtn = document.getElementById('sidebar-close');
  var overlay = document.getElementById('sidebar-overlay');

  if (!sidebar || !openBtn) return;

  function setOpen(open) {
    sidebar.classList.toggle('is-open', open);
    if (overlay) overlay.hidden = !open;
    document.body.classList.toggle('sidebar-locked', open);
  }

  openBtn.addEventListener('click', function () { setOpen(true); });
  if (closeBtn) closeBtn.addEventListener('click', function () { setOpen(false); });
  if (overlay) overlay.addEventListener('click', function () { setOpen(false); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') setOpen(false);
  });
})();
