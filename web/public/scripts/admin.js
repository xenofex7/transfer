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
      var prev = btn.textContent;
      btn.textContent = 'copied';
      btn.classList.add('copied');
      setTimeout(function () {
        btn.textContent = prev;
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
})();
