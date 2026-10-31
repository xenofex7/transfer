// Admin dashboard helpers: live-filter the file table and copy URLs to the
// clipboard. No external dependencies.

(function () {
  'use strict';

  // ---- live filter ----
  var filter = document.getElementById('filter');
  var tbody = document.getElementById('rows');
  if (filter && tbody) {
    filter.addEventListener('input', function () {
      var q = filter.value.trim().toLowerCase();
      var rows = tbody.querySelectorAll('tr');
      for (var i = 0; i < rows.length; i++) {
        var hay = (rows[i].getAttribute('data-search') || '').toLowerCase();
        rows[i].hidden = q && hay.indexOf(q) === -1;
      }
    });
  }

  // ---- copy buttons ----
  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('.copy-btn');
    if (!btn) return;
    var value = btn.getAttribute('data-copy') || '';
    if (!value) return;

    var done = function () {
      var prevTitle = btn.dataset.tooltip;
      btn.dataset.tooltip = 'Copied';
      btn.classList.add('copied');
      setTimeout(function () {
        btn.dataset.tooltip = prevTitle;
        btn.classList.remove('copied');
      }, 1200);
      if (window.toast) window.toast.success('Link copied to clipboard');
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () {
        fallbackCopy(value, done);
      });
    } else {
      fallbackCopy(value, done);
    }
  });

  function fallbackCopy(text, cb) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    cb();
  }

  // ---- delete buttons ----
  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('.delete-btn');
    if (!btn) return;
    var url = btn.getAttribute('data-delete') || '';
    var name = btn.getAttribute('data-name') || 'this file';
    if (!url) return;

    window.dialog.confirm({
      title: 'Delete file',
      message: 'Delete "' + name + '"? This cannot be undone.',
      confirmLabel: 'Delete',
      danger: true,
    }).then(function (ok) {
      if (ok) deleteFile(btn, url, name);
    });
  });

  function deleteFile(btn, url, name) {
    var row = btn.closest('tr');
    var prevTitle = btn.dataset.tooltip;
    btn.disabled = true;
    btn.dataset.tooltip = 'Deleting...';

    fetch(url, { method: 'DELETE', credentials: 'include' })
      .then(function (resp) {
        if (resp.ok) {
          if (row) {
            row.style.transition = 'opacity 200ms, transform 200ms';
            row.style.opacity = '0';
            row.style.transform = 'translateX(8px)';
            setTimeout(function () { row && row.parentNode && row.parentNode.removeChild(row); }, 220);
          }
          updateCount(-1);
          if (window.toast) window.toast.success('Deleted ' + name);
        } else {
          btn.disabled = false;
          btn.dataset.tooltip = 'Failed (' + resp.status + ') - click to retry';
          setTimeout(function () { btn.dataset.tooltip = prevTitle; }, 2000);
          if (window.toast) window.toast.error('Delete failed (' + resp.status + ')');
        }
      })
      .catch(function () {
        btn.disabled = false;
        btn.dataset.tooltip = 'Network error - click to retry';
        setTimeout(function () { btn.dataset.tooltip = prevTitle; }, 2000);
        if (window.toast) window.toast.error('Delete failed: network error');
      });
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('.options-btn');
    if (!btn) return;
    editOptions(btn);
  });

  function field(label, input, hint) {
    var wrap = document.createElement('div');
    wrap.className = 'settings-field';
    var caption = document.createElement('label');
    caption.className = 'settings-label';
    caption.htmlFor = input.id;
    caption.textContent = label;
    var note = document.createElement('p');
    note.className = 'settings-hint';
    note.textContent = hint;
    wrap.appendChild(caption);
    wrap.appendChild(input);
    wrap.appendChild(note);
    return wrap;
  }

  function editOptions(btn) {
    var url = btn.getAttribute('data-options') || '';
    var max = parseInt(btn.getAttribute('data-max'), 10);
    var isProtected = btn.getAttribute('data-protected') === 'true';
    if (!url) return;

    var form = document.createElement('form');
    form.className = 'options-form';
    form.noValidate = true;

    var maxInput = document.createElement('input');
    maxInput.id = 'options-max';
    maxInput.className = 'field-input';
    maxInput.type = 'number';
    maxInput.min = '1';
    maxInput.step = '1';
    maxInput.placeholder = 'unlimited';
    maxInput.value = max > 0 ? String(max) : '';
    form.appendChild(field('Max downloads', maxInput, 'Counts all downloads, including past ones. Leave empty for unlimited.'));

    var pwInput = document.createElement('input');
    pwInput.id = 'options-password';
    pwInput.className = 'field-input';
    pwInput.type = 'text';
    pwInput.maxLength = 256;
    pwInput.autocomplete = 'off';
    pwInput.spellcheck = false;
    pwInput.placeholder = isProtected ? 'unchanged' : 'none';
    form.appendChild(field('Password', pwInput, isProtected
      ? 'Leave empty to keep the current password.'
      : 'Leave empty for no password.'));

    var remove = null;
    if (isProtected) {
      var check = document.createElement('label');
      check.className = 'field-check';
      remove = document.createElement('input');
      remove.type = 'checkbox';
      remove.addEventListener('change', function () {
        pwInput.disabled = remove.checked;
        if (remove.checked) pwInput.value = '';
      });
      check.appendChild(remove);
      check.appendChild(document.createTextNode('Remove password'));
      form.appendChild(check);
    }

    form.addEventListener('submit', function (e) { e.preventDefault(); });
    form.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' || e.target.type === 'checkbox') return;
      e.preventDefault();
      var confirm = document.querySelector('.modal-backdrop .modal-actions .btn-primary');
      if (confirm) confirm.click();
    });

    window.dialog.confirm({
      title: 'Options for ' + (btn.getAttribute('data-name') || 'file'),
      body: form,
      confirmLabel: 'Save',
    }).then(function (ok) {
      if (!ok) return;
      var next = parseInt(maxInput.value, 10);
      var body = { maxDownloads: next > 0 ? next : 0 };
      if (pwInput.value) body.password = pwInput.value;
      else if (remove && remove.checked) body.password = '';
      else if (!isProtected) body.password = '';
      saveOptions(url, body);
    });
  }

  function saveOptions(url, body) {
    fetch(url, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(function (resp) {
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      if (window.toast) window.toast.success('Options saved');
      setTimeout(function () { window.location.reload(); }, 600);
    }).catch(function (err) {
      if (window.toast) window.toast.error('Could not save options (' + err.message + ')');
    });
  }

  function updateCount(delta) {
    var counter = document.querySelector('.admin-count');
    if (!counter) return;
    var n = parseInt(counter.textContent, 10);
    if (isNaN(n)) return;
    counter.textContent = String(Math.max(0, n + delta));
  }
})();
