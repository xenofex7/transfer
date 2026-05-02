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
        var link = document.createElement('a');
        link.href = url;
        link.textContent = url;
        link.target = '_blank';
        link.rel = 'noopener';
        item.appendChild(link);
      } else if (xhr.status === 401) {
        item.classList.add('is-error');
        status.textContent = 'auth required';
      } else {
        item.classList.add('is-error');
        status.textContent = 'failed (' + xhr.status + ')';
      }
    });

    xhr.addEventListener('error', function () {
      item.classList.add('is-error');
      status.textContent = 'network error';
    });

    xhr.send(file);
  }
})();
