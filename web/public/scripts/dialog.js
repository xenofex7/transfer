(function () {
  'use strict';

  var FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  var active = null;
  var seq = 0;

  function renderIcons(root) {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons({ nameAttr: 'data-lucide', root: root });
    }
  }

  function makeButton(className, label) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = className;
    b.textContent = label;
    return b;
  }

  function open(opts) {
    if (active) return Promise.resolve(false);

    var titleId = 'dialog-title-' + (++seq);
    var previous = document.activeElement;
    var backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.innerHTML =
      '<div class="modal modal-sm" role="dialog" aria-modal="true" aria-labelledby="' + titleId + '">' +
        '<header class="modal-head">' +
          '<h2 class="modal-title" id="' + titleId + '"></h2>' +
          '<button type="button" class="modal-close" aria-label="Close" data-tooltip="Close"><i data-lucide="x"></i></button>' +
        '</header>' +
        '<div class="modal-body"><p></p></div>' +
        '<footer class="modal-actions"></footer>' +
      '</div>';
    backdrop.querySelector('.modal-title').textContent = opts.title || '';
    var bodyText = backdrop.querySelector('.modal-body p');
    if (opts.body) bodyText.parentNode.replaceChild(opts.body, bodyText);
    else bodyText.textContent = opts.message || '';

    var actions = backdrop.querySelector('.modal-actions');
    var cancelBtn = null;
    if (!opts.alert) {
      cancelBtn = makeButton('btn-secondary', opts.cancelLabel);
      actions.appendChild(cancelBtn);
    }
    var confirmBtn = makeButton(opts.danger ? 'btn-danger' : 'btn-primary', opts.confirmLabel);
    actions.appendChild(confirmBtn);

    document.body.appendChild(backdrop);
    renderIcons(backdrop);
    active = backdrop;
    requestAnimationFrame(function () { backdrop.classList.add('is-in'); });

    return new Promise(function (resolve) {
      function finish(result) {
        if (active !== backdrop) return;
        active = null;
        document.removeEventListener('keydown', onKey, true);
        backdrop.classList.remove('is-in');
        setTimeout(function () { backdrop.parentNode && backdrop.parentNode.removeChild(backdrop); }, 180);
        if (previous && typeof previous.focus === 'function') previous.focus();
        resolve(result);
      }

      function onKey(e) {
        if (e.key === 'Escape') {
          e.preventDefault();
          finish(false);
          return;
        }
        if (e.key !== 'Tab') return;
        var items = backdrop.querySelectorAll(FOCUSABLE);
        if (!items.length) return;
        var first = items[0];
        var last = items[items.length - 1];
        var focused = document.activeElement;
        if (!backdrop.contains(focused)) {
          e.preventDefault();
          first.focus();
        } else if (e.shiftKey && focused === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && focused === last) {
          e.preventDefault();
          first.focus();
        }
      }

      document.addEventListener('keydown', onKey, true);
      backdrop.addEventListener('click', function (e) {
        if (e.target === backdrop) finish(false);
      });
      backdrop.querySelector('.modal-close').addEventListener('click', function () { finish(false); });
      if (cancelBtn) cancelBtn.addEventListener('click', function () { finish(false); });
      confirmBtn.addEventListener('click', function () { finish(true); });

      var firstField = opts.body && opts.body.querySelector('input, select, textarea');
      (firstField || (opts.danger && cancelBtn ? cancelBtn : confirmBtn)).focus();
    });
  }

  window.dialog = {
    confirm: function (opts) {
      opts = opts || {};
      return open({
        title: opts.title,
        message: opts.message,
        body: opts.body,
        confirmLabel: opts.confirmLabel || 'Confirm',
        cancelLabel: opts.cancelLabel || 'Cancel',
        danger: !!opts.danger,
      });
    },
    alert: function (opts) {
      opts = opts || {};
      return open({
        title: opts.title,
        message: opts.message,
        confirmLabel: opts.okLabel || 'OK',
        alert: true,
      }).then(function () {});
    },
  };

  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form || form.tagName !== 'FORM' || !form.hasAttribute('data-confirm')) return;
    if (form.dataset.confirmState === 'ok') return;
    e.preventDefault();
    if (form.dataset.confirmState === 'open') return;
    form.dataset.confirmState = 'open';
    window.dialog.confirm({
      title: form.dataset.confirmTitle || 'Please confirm',
      message: form.dataset.confirm,
      confirmLabel: form.dataset.confirmLabel || 'Confirm',
      danger: form.hasAttribute('data-confirm-danger'),
    }).then(function (ok) {
      if (!ok) {
        delete form.dataset.confirmState;
        return;
      }
      form.dataset.confirmState = 'ok';
      form.submit();
    });
  });
})();
