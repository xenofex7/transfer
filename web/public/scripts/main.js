// Minimal drag-and-drop uploader. No external dependencies.

(function () {
  'use strict';

  var dropzone = document.getElementById('dropzone');
  var fileinput = document.getElementById('fileinput');
  var browse = document.getElementById('browse');
  var uploadList = document.getElementById('uploads');
  var defaultPrompt = dropzone && dropzone.querySelector('.dropzone-default');
  var activePrompt = dropzone && dropzone.querySelector('.dropzone-active');
  var optMaxDays = document.getElementById('opt-max-days');
  var optMaxDownloads = document.getElementById('opt-max-downloads');

  if (!dropzone || !fileinput) return;

  // ----- prompt + file picker -----
  dropzone.addEventListener('click', function (e) {
    if (e.target.tagName === 'A' || e.target.tagName === 'BUTTON') return;
    fileinput.click();
  });
  dropzone.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileinput.click();
    }
  });
  if (browse) {
    browse.addEventListener('click', function (e) {
      e.stopPropagation();
      fileinput.click();
    });
  }
  fileinput.addEventListener('change', function () {
    handleFiles(fileinput.files);
    fileinput.value = '';
  });

  // ----- drag indicators -----
  ['dragenter', 'dragover'].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('is-active');
      if (defaultPrompt) defaultPrompt.hidden = true;
      if (activePrompt) activePrompt.hidden = false;
    });
  });
  ['dragleave', 'dragend', 'drop'].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('is-active');
      if (defaultPrompt) defaultPrompt.hidden = false;
      if (activePrompt) activePrompt.hidden = true;
    });
  });
  dropzone.addEventListener('drop', function (e) {
    if (e.dataTransfer && e.dataTransfer.files) {
      handleFiles(e.dataTransfer.files);
    }
  });

  // ----- upload -----
  function handleFiles(files) {
    if (!files || !files.length) return;
    uploadList.hidden = false;
    for (var i = 0; i < files.length; i++) {
      uploadOne(files[i]);
    }
  }

  function uploadOne(file) {
    var item = document.createElement('li');
    item.className = 'upload-item';
    var name = document.createElement('span');
    name.className = 'upload-name';
    name.textContent = file.name;
    name.title = file.name;
    var status = document.createElement('span');
    status.className = 'upload-status';
    status.textContent = '0%';
    item.appendChild(name);
    item.appendChild(status);
    uploadList.appendChild(item);

    var xhr = new XMLHttpRequest();
    xhr.open('PUT', '/' + encodeURIComponent(file.name));
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');

    var maxDays = optMaxDays && parseInt(optMaxDays.value, 10);
    if (maxDays && maxDays > 0) {
      if (maxDays > 365) maxDays = 365;
      xhr.setRequestHeader('Max-Days', String(maxDays));
    }
    var maxDownloads = optMaxDownloads && parseInt(optMaxDownloads.value, 10);
    if (maxDownloads && maxDownloads > 0) {
      xhr.setRequestHeader('Max-Downloads', String(maxDownloads));
    }

    xhr.upload.addEventListener('progress', function (e) {
      if (!e.lengthComputable) return;
      var pct = Math.round((e.loaded / e.total) * 100);
      status.textContent = pct + '%';
    });

    xhr.addEventListener('load', function () {
      if (xhr.status >= 200 && xhr.status < 300) {
        var url = (xhr.responseText || '').trim();
        item.classList.add('is-done');
        item.removeChild(status);

        var result = document.createElement('div');
        result.className = 'upload-result';

        var link = document.createElement('a');
        link.href = url;
        link.className = 'upload-link';
        link.textContent = shortenUrl(url);
        link.title = url;
        link.target = '_blank';
        link.rel = 'noopener';
        result.appendChild(link);

        var copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'upload-copy';
        copy.title = 'Copy link';
        copy.setAttribute('aria-label', 'Copy link');
        copy.innerHTML = '<i data-lucide="copy"></i>';
        copy.addEventListener('click', function (e) {
          e.preventDefault();
          e.stopPropagation();
          copyToClipboard(url, copy);
        });
        result.appendChild(copy);
        item.appendChild(result);
        renderIcons(copy);
      } else if (xhr.status === 401) {
        item.classList.add('is-error');
        status.textContent = 'auth required';
        if (window.toast) window.toast.error('Auth required to upload ' + file.name);
      } else {
        item.classList.add('is-error');
        status.textContent = 'failed (' + xhr.status + ')';
        if (window.toast) window.toast.error('Upload failed (' + xhr.status + '): ' + file.name);
      }
    });

    xhr.addEventListener('error', function () {
      item.classList.add('is-error');
      status.textContent = 'network error';
      if (window.toast) window.toast.error('Network error uploading ' + file.name);
    });

    xhr.send(file);
  }

  // ----- helpers -----
  function shortenUrl(url) {
    try {
      var u = new URL(url);
      var parts = u.pathname.split('/').filter(Boolean);
      var token = parts[0] || '';
      return u.host + '/' + token;
    } catch (_) {
      return url;
    }
  }

  function copyToClipboard(text, btn) {
    var done = function () {
      btn.classList.add('is-copied');
      btn.title = 'Copied';
      setTimeout(function () {
        btn.classList.remove('is-copied');
        btn.title = 'Copy link';
      }, 1500);
      if (window.toast) window.toast.success('Link copied to clipboard');
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () {
        legacyCopy(text);
        done();
      });
    } else {
      legacyCopy(text);
      done();
    }
  }

  function legacyCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (_) { /* ignore */ }
    document.body.removeChild(ta);
  }

  // renderIcons converts every <i data-lucide="..."> in the given container
  // into an inline SVG. Safe to call before lucide finishes loading - it's
  // a no-op until window.lucide exists, and the script ordering in <head>
  // guarantees lucide.min.js loads before main.js fires DOM events.
  function renderIcons(container) {
    if (!(window.lucide && typeof window.lucide.createIcons === 'function')) {
      // Lucide hasn't loaded yet (defer race) - retry once after it does.
      window.addEventListener('load', function once() {
        window.removeEventListener('load', once);
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
          window.lucide.createIcons({ nameAttr: 'data-lucide', root: container || document });
        }
      });
      return;
    }
    window.lucide.createIcons({ nameAttr: 'data-lucide', root: container || document });
  }
})();
