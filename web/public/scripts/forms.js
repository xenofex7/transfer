(function () {
  'use strict';

  var seq = 0;

  function messageFor(input) {
    var isFile = input.type === 'file';
    var value = isFile ? '' : input.value;
    if (input.hasAttribute('required')) {
      var empty = isFile ? !(input.files && input.files.length) : !value.trim();
      if (empty) return isFile ? 'Choose a file first' : 'This field is required';
    }
    if (isFile || !value) return null;
    var min = parseInt(input.getAttribute('minlength'), 10);
    if (min > 0 && value.length < min) return 'At least ' + min + ' characters';
    var max = parseInt(input.getAttribute('maxlength'), 10);
    if (max > 0 && value.length > max) return 'At most ' + max + ' characters';
    var pattern = input.getAttribute('pattern');
    if (pattern) {
      var re = null;
      try { re = new RegExp('^(?:' + pattern + ')$', 'u'); } catch (_) {}
      if (re && !re.test(value)) return input.getAttribute('data-error') || 'Invalid format';
    }
    return null;
  }

  function focusTarget(input) {
    if (input.type !== 'file') return input;
    var picker = input.closest('.file-picker');
    return (picker && picker.querySelector('.file-picker-btn')) || input;
  }

  function placeError(input, p) {
    var field = input.closest('.field');
    if (field) {
      field.classList.add('has-error');
      field.insertAdjacentElement('afterend', p);
      return;
    }
    var row = input.closest('.users-inline-form, .branding-form');
    if (row) {
      row.appendChild(p);
      return;
    }
    input.insertAdjacentElement('afterend', p);
  }

  function clearError(input) {
    var id = input.getAttribute('aria-describedby');
    var p = id && document.getElementById(id);
    if (p && p.parentNode) p.parentNode.removeChild(p);
    input.removeAttribute('aria-describedby');
    input.removeAttribute('aria-invalid');
    input.classList.remove('is-invalid');
    focusTarget(input).classList.remove('is-invalid');
    var field = input.closest('.field');
    if (field) field.classList.remove('has-error');
  }

  function showError(input, message) {
    clearError(input);
    var p = document.createElement('p');
    p.className = 'field-error';
    p.id = 'field-error-' + (++seq);
    p.textContent = message;
    placeError(input, p);
    input.setAttribute('aria-invalid', 'true');
    input.setAttribute('aria-describedby', p.id);
    input.classList.add('is-invalid');
    focusTarget(input).classList.add('is-invalid');
    bindClear(input);
  }

  function bindClear(input) {
    if (input.dataset.clearsError) return;
    input.dataset.clearsError = '1';
    input.addEventListener('input', function () { clearError(input); });
    input.addEventListener('change', function () { clearError(input); });
  }

  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form || form.tagName !== 'FORM' || !form.hasAttribute('novalidate')) return;
    var inputs = form.querySelectorAll('input[required], input[minlength], input[maxlength], input[pattern], textarea[required], textarea[minlength], textarea[maxlength], select[required]');
    var firstInvalid = null;
    for (var i = 0; i < inputs.length; i++) {
      var input = inputs[i];
      if (input.disabled) continue;
      var message = messageFor(input);
      if (!message) continue;
      showError(input, message);
      if (!firstInvalid) firstInvalid = input;
    }
    if (!firstInvalid) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    focusTarget(firstInvalid).focus();
  }, true);

  function humanBytes(n) {
    if (n % 1048576 === 0) return (n / 1048576) + ' MiB';
    if (n % 1024 === 0) return (n / 1024) + ' KiB';
    return n + ' bytes';
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('.file-picker-btn');
    if (!btn) return;
    var picker = btn.closest('.file-picker');
    var input = picker && picker.querySelector('.file-input');
    if (input) input.click();
  });

  document.addEventListener('change', function (e) {
    var input = e.target;
    if (!input.classList || !input.classList.contains('file-input')) return;
    var picker = input.closest('.file-picker');
    var nameEl = picker && picker.querySelector('.file-picker-name');
    var max = parseInt(input.getAttribute('data-max-bytes'), 10);
    var names = [];
    for (var i = 0; i < input.files.length; i++) {
      if (max > 0 && input.files[i].size > max) {
        input.value = '';
        names = [];
        if (window.toast) window.toast.error('File is larger than ' + humanBytes(max));
        break;
      }
      names.push(input.files[i].name);
    }
    if (nameEl) nameEl.textContent = names.length ? names.join(', ') : 'No file chosen';
  });

  var serverInvalid = document.querySelectorAll('[aria-invalid="true"]');
  for (var k = 0; k < serverInvalid.length; k++) bindClear(serverInvalid[k]);
})();
