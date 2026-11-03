(function () {
  'use strict';

  document.querySelectorAll('[data-branding-reset]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var slot = btn.getAttribute('data-branding-reset');
      window.dialog.confirm({
        title: 'Reset ' + slot,
        message: 'Remove the custom ' + slot + ' and revert to the embedded default?',
        confirmLabel: 'Reset',
        danger: true,
      }).then(function (ok) {
        if (!ok) return;
        fetch('/admin/branding/' + slot, { method: 'DELETE', credentials: 'same-origin' })
          .then(function (r) {
            if (r.ok) {
              window.toast.success(slot.charAt(0).toUpperCase() + slot.slice(1) + ' reset to default');
              setTimeout(function () { window.location.reload(); }, 600);
              return;
            }
            r.text().then(function (t) { window.toast.error('Reset failed: ' + t); });
          })
          .catch(function (e) { window.toast.error('Reset failed: ' + e); });
      });
    });
  });
})();
