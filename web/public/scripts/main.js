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
  var optPassword = document.getElementById('opt-password');

  if (!dropzone || !fileinput) return;

  // ----- prompt + file picker -----
  dropzone.addEventListener('click', function (e) {
    if (e.target.closest('a, button, #uploads')) return;
    fileinput.click();
  });
  dropzone.addEventListener('keydown', function (e) {
    if (e.target !== dropzone) return;
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
      if (e.type === 'dragleave' && e.relatedTarget && dropzone.contains(e.relatedTarget)) return;
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
    name.dataset.tooltip = file.name;
    var status = document.createElement('span');
    status.className = 'upload-status';
    status.textContent = '0%';
    var bar = document.createElement('div');
    bar.className = 'upload-bar';
    var barFill = document.createElement('div');
    barFill.className = 'upload-bar-fill';
    bar.appendChild(barFill);
    item.appendChild(name);
    item.appendChild(status);
    item.appendChild(bar);
    uploadList.appendChild(item);

    var xhr = new XMLHttpRequest();
    xhr.open('PUT', '/' + encodeURIComponent(file.name));
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');

    var maxDays = optMaxDays && parseInt(optMaxDays.value, 10);
    if (maxDays && maxDays > 0) {
      var maxDaysCap = parseInt(optMaxDays.getAttribute('max'), 10) || 365;
      if (maxDays > maxDaysCap) maxDays = maxDaysCap;
      xhr.setRequestHeader('Max-Days', String(maxDays));
    }
    var maxDownloads = optMaxDownloads && parseInt(optMaxDownloads.value, 10);
    if (maxDownloads && maxDownloads > 0) {
      xhr.setRequestHeader('Max-Downloads', String(maxDownloads));
    }
    var password = optPassword && optPassword.value;
    if (password) {
      xhr.setRequestHeader('X-Password', unescape(encodeURIComponent(password)));
    }

    xhr.upload.addEventListener('progress', function (e) {
      if (!e.lengthComputable) return;
      var pct = Math.round((e.loaded / e.total) * 100);
      status.textContent = pct + '%';
      barFill.style.width = pct + '%';
    });

    xhr.addEventListener('load', function () {
      item.removeChild(bar);
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
        link.dataset.tooltip = url;
        link.target = '_blank';
        link.rel = 'noopener';
        result.appendChild(link);

        var copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'upload-copy';
        copy.dataset.tooltip = 'Copy link';
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

        var optionsUrl = xhr.getResponseHeader('X-Url-Delete');
        if (optionsUrl) {
          addOptionsEditor(item, result, optionsUrl, {
            maxDays: maxDays > 0 ? maxDays : 0,
            maxDownloads: maxDownloads > 0 ? maxDownloads : 0,
            password: password || ''
          });
        }
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
      item.removeChild(bar);
      item.classList.add('is-error');
      status.textContent = 'network error';
      if (window.toast) window.toast.error('Network error uploading ' + file.name);
    });

    xhr.send(file);
  }

  function describeOptions(opts) {
    var downloads = opts.maxDownloads > 0
      ? 'Max ' + opts.maxDownloads + (opts.maxDownloads === 1 ? ' download' : ' downloads')
      : 'Unlimited downloads';
    var summary = downloads + ' \u00b7 ' + (opts.password ? 'password' : 'no password');
    if (opts.maxDays > 0) {
      summary += ' \u00b7 auto-delete after ' + opts.maxDays + (opts.maxDays === 1 ? ' day' : ' days');
    }
    return summary;
  }

  function optionField(label, input, suffix) {
    var wrap = document.createElement('label');
    wrap.className = 'upload-option';
    var caption = document.createElement('span');
    caption.className = 'upload-option-label';
    caption.textContent = label;
    var box = document.createElement('span');
    box.className = 'upload-option-input';
    box.appendChild(input);
    if (suffix) {
      var unit = document.createElement('span');
      unit.className = 'upload-option-suffix';
      unit.textContent = suffix;
      box.appendChild(unit);
    }
    wrap.appendChild(caption);
    wrap.appendChild(box);
    return wrap;
  }

  function addOptionsEditor(item, result, optionsUrl, opts) {
    var meta = document.createElement('span');
    meta.className = 'upload-meta';
    meta.textContent = describeOptions(opts);
    item.appendChild(meta);

    var toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'upload-copy';
    toggle.dataset.tooltip = 'Edit options';
    toggle.setAttribute('aria-label', 'Edit options');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.innerHTML = '<i data-lucide="sliders-horizontal"></i>';
    result.appendChild(toggle);
    renderIcons(toggle);

    var form = document.createElement('form');
    form.className = 'upload-edit';
    form.noValidate = true;
    form.hidden = true;

    var daysInput = null;
    if (optMaxDays) {
      daysInput = document.createElement('input');
      daysInput.type = 'number';
      daysInput.min = '1';
      daysInput.max = optMaxDays.getAttribute('max');
      daysInput.step = '1';
      daysInput.placeholder = optMaxDays.getAttribute('placeholder');
      daysInput.autocomplete = 'off';
    }

    var maxInput = document.createElement('input');
    maxInput.type = 'number';
    maxInput.min = '1';
    maxInput.step = '1';
    maxInput.placeholder = 'unlimited';
    maxInput.autocomplete = 'off';

    var pwInput = document.createElement('input');
    pwInput.type = 'text';
    pwInput.maxLength = 256;
    pwInput.placeholder = 'none';
    pwInput.autocomplete = 'off';
    pwInput.spellcheck = false;

    var grid = document.createElement('div');
    grid.className = 'upload-options-grid';
    if (daysInput) grid.appendChild(optionField('Auto-delete after', daysInput, 'days'));
    grid.appendChild(optionField('Max downloads', maxInput));
    grid.appendChild(optionField('Password', pwInput));
    form.appendChild(grid);

    var actions = document.createElement('div');
    actions.className = 'upload-edit-actions';
    var save = document.createElement('button');
    save.type = 'submit';
    save.className = 'btn-primary';
    save.textContent = 'Save';
    var cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'btn-secondary';
    cancel.textContent = 'Cancel';
    actions.appendChild(save);
    actions.appendChild(cancel);
    form.appendChild(actions);
    item.appendChild(form);

    function setOpen(open) {
      form.hidden = !open;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        if (daysInput) daysInput.value = opts.maxDays > 0 ? String(opts.maxDays) : '';
        maxInput.value = opts.maxDownloads > 0 ? String(opts.maxDownloads) : '';
        pwInput.value = opts.password;
        (daysInput || maxInput).focus();
      }
    }

    toggle.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      setOpen(form.hidden);
    });
    cancel.addEventListener('click', function () { setOpen(false); toggle.focus(); });
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var next = {
        maxDownloads: parseInt(maxInput.value, 10) > 0 ? parseInt(maxInput.value, 10) : 0,
        password: pwInput.value
      };
      if (daysInput) {
        var days = parseInt(daysInput.value, 10);
        var daysCap = parseInt(daysInput.max, 10) || 365;
        next.maxDays = days > 0 ? Math.min(days, daysCap) : 0;
      }
      save.disabled = true;
      fetch(optionsUrl, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(next)
      }).then(function (res) {
        if (!res.ok) {
          var plain = (res.headers.get('Content-Type') || '').indexOf('text/plain') === 0;
          return (plain ? res.text() : Promise.resolve('')).then(function (text) {
            throw new Error(text.trim() || 'HTTP ' + res.status);
          });
        }
        opts = next;
        meta.textContent = describeOptions(opts);
        setOpen(false);
        toggle.focus();
        if (window.toast) window.toast.success('Options saved');
      }).catch(function (err) {
        if (window.toast) window.toast.error('Could not save options (' + err.message + ')');
      }).then(function () { save.disabled = false; });
    });
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
      btn.dataset.tooltip = 'Copied';
      setTimeout(function () {
        btn.classList.remove('is-copied');
        btn.dataset.tooltip = 'Copy link';
      }, 1500);
      if (window.toast) window.toast.neutral('Link copied');
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
