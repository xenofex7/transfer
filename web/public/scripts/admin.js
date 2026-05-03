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
      var prevTitle = btn.title;
      btn.title = 'Copied';
      btn.classList.add('copied');
      setTimeout(function () {
        btn.title = prevTitle;
        btn.classList.remove('copied');
      }, 1200);
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

    if (!window.confirm('Delete "' + name + '"? This cannot be undone.')) return;

    var row = btn.closest('tr');
    var prevTitle = btn.title;
    btn.disabled = true;
    btn.title = 'Deleting...';

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
        } else {
          btn.disabled = false;
          btn.title = 'Failed (' + resp.status + ') - click to retry';
          setTimeout(function () { btn.title = prevTitle; }, 2000);
        }
      })
      .catch(function () {
        btn.disabled = false;
        btn.title = 'Network error - click to retry';
        setTimeout(function () { btn.title = prevTitle; }, 2000);
      });
  });

  function updateCount(delta) {
    var counter = document.querySelector('.admin-count');
    if (!counter) return;
    var n = parseInt(counter.textContent, 10);
    if (isNaN(n)) return;
    counter.textContent = String(Math.max(0, n + delta));
  }
})();
