// One-time secrets: AES-256-GCM in the browser via WebCrypto. The key
// travels in the URL fragment (#...) and never reaches the server; the
// server only ever stores the base64 ciphertext.

(function () {
  'use strict';

  // ----- base64 helpers -----
  function bytesToB64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function b64ToBytes(str) {
    var bin = atob(str);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  // URL-safe variant for the key fragment (no padding, no +/ that would
  // need escaping inside a URL).
  function bytesToB64Url(bytes) {
    return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64UrlToBytes(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return b64ToBytes(str);
  }

  // WebCrypto is only exposed in secure contexts (https or localhost).
  function cryptoAvailable() {
    return !!(window.crypto && window.crypto.subtle);
  }

  // Encrypts text with a fresh AES-256-GCM key. The stored payload is
  // base64(iv || ciphertext); the key is returned separately for the
  // URL fragment.
  function encryptText(text) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var key;
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt'])
      .then(function (k) {
        key = k;
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, new TextEncoder().encode(text));
      })
      .then(function (ct) {
        return crypto.subtle.exportKey('raw', key).then(function (raw) {
          var ctBytes = new Uint8Array(ct);
          var payload = new Uint8Array(iv.length + ctBytes.length);
          payload.set(iv);
          payload.set(ctBytes, iv.length);
          return {
            ciphertext: bytesToB64(payload),
            keyFragment: bytesToB64Url(new Uint8Array(raw))
          };
        });
      });
  }

  function decryptText(ciphertextB64, keyFragment) {
    var payload = b64ToBytes(ciphertextB64);
    var iv = payload.slice(0, 12);
    var ct = payload.slice(12);
    return crypto.subtle.importKey('raw', b64UrlToBytes(keyFragment), { name: 'AES-GCM' }, false, ['decrypt'])
      .then(function (key) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
      })
      .then(function (pt) { return new TextDecoder().decode(pt); });
  }

  function copyToClipboard(text, done) {
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

  function userError(message) {
    var e = new Error(message);
    e.userMessage = message;
    return e;
  }

  // ----- create (homepage composer) -----
  var form = document.getElementById('secret-form');
  if (form) {
    var input = document.getElementById('secret-input');
    var createBtn = document.getElementById('secret-create');
    var result = document.getElementById('secret-result');
    var urlOut = document.getElementById('secret-url');
    var copyBtn = document.getElementById('secret-copy');
    var againBtn = document.getElementById('secret-again');

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var text = input.value;
      if (!text.trim()) {
        input.focus();
        return;
      }
      if (!cryptoAvailable()) {
        if (window.toast) window.toast.error('Secrets need a secure context (HTTPS)');
        return;
      }
      createBtn.disabled = true;
      encryptText(text)
        .then(function (enc) {
          return fetch('/secret', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ciphertext: enc.ciphertext })
          }).then(function (res) {
            if (res.status === 401) throw userError('Sign in to create secrets');
            if (!res.ok) throw userError('Could not create secret (' + res.status + ')');
            return res.json();
          }).then(function (data) {
            urlOut.textContent = data.url + '#' + enc.keyFragment;
            form.hidden = true;
            result.hidden = false;
            input.value = '';
          });
        })
        .catch(function (err) {
          if (window.toast) window.toast.error((err && err.userMessage) || 'Could not create secret');
        })
        .then(function () { createBtn.disabled = false; });
    });

    if (copyBtn) {
      copyBtn.addEventListener('click', function () {
        copyToClipboard(urlOut.textContent, function () {
          if (window.toast) window.toast.success('Link copied to clipboard');
        });
      });
    }
    if (againBtn) {
      againBtn.addEventListener('click', function () {
        result.hidden = true;
        urlOut.textContent = '';
        form.hidden = false;
        input.focus();
      });
    }
  }

  // ----- reveal (secret page) -----
  var revealCard = document.getElementById('secret-reveal-card');
  if (revealCard) {
    var revealBtn = document.getElementById('secret-reveal');
    var output = document.getElementById('secret-output');
    var textOut = document.getElementById('secret-text');
    var copyOut = document.getElementById('secret-copy');
    var errOut = document.getElementById('secret-error');
    var id = revealCard.getAttribute('data-secret-id');

    function fail(message) {
      errOut.textContent = message;
      errOut.hidden = false;
    }

    revealBtn.addEventListener('click', function () {
      var keyFragment = (location.hash || '').slice(1);
      if (!keyFragment) {
        fail('This link is incomplete: the part after "#" is missing. Ask the sender for the full link.');
        return;
      }
      if (!cryptoAvailable()) {
        fail('Your browser cannot decrypt this secret here (needs HTTPS and WebCrypto).');
        return;
      }
      revealBtn.disabled = true;
      fetch('/secret/' + encodeURIComponent(id) + '/reveal', { method: 'POST' })
        .then(function (res) {
          if (res.status === 404) throw userError('This secret is no longer available - it has been viewed already or expired.');
          if (!res.ok) throw userError('Could not fetch secret (' + res.status + ')');
          return res.json();
        })
        .then(function (data) { return decryptText(data.ciphertext, keyFragment); })
        .then(function (text) {
          textOut.textContent = text;
          // style.display, not the hidden attribute: .btn-primary sets
          // display:inline-flex which would win over [hidden].
          revealBtn.style.display = 'none';
          errOut.hidden = true;
          output.hidden = false;
        })
        .catch(function (err) {
          revealBtn.style.display = 'none';
          fail((err && err.userMessage) || 'Could not decrypt this secret: the key in the link does not match.');
        });
    });

    if (copyOut) {
      copyOut.addEventListener('click', function () {
        copyToClipboard(textOut.textContent, function () {
          if (window.toast) window.toast.success('Secret copied to clipboard');
        });
      });
    }
  }
})();
