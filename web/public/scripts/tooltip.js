(function () {
  'use strict';

  var GAP = 6;
  var EDGE = 8;
  var tip = null;
  var current = null;

  function ensureTip() {
    if (tip) return tip;
    tip = document.createElement('div');
    tip.className = 'tooltip';
    tip.setAttribute('role', 'tooltip');
    tip.hidden = true;
    document.body.appendChild(tip);
    return tip;
  }

  function triggerFrom(e) {
    var t = e.target;
    if (!t || typeof t.closest !== 'function') return null;
    return t.closest('[data-tooltip]');
  }

  function position(el) {
    var r = el.getBoundingClientRect();
    var w = tip.offsetWidth;
    var h = tip.offsetHeight;
    var left = r.left + r.width / 2 - w / 2;
    left = Math.max(EDGE, Math.min(left, window.innerWidth - w - EDGE));
    var top = r.top - h - GAP;
    if (top < EDGE) top = r.bottom + GAP;
    tip.style.left = Math.round(left) + 'px';
    tip.style.top = Math.round(top) + 'px';
  }

  function show(el) {
    var text = el.getAttribute('data-tooltip') || '';
    if (!text.trim()) return;
    ensureTip();
    current = el;
    tip.textContent = text;
    tip.hidden = false;
    position(el);
  }

  function hide() {
    if (!tip || !current) return;
    current = null;
    tip.hidden = true;
  }

  document.addEventListener('mouseover', function (e) {
    var el = triggerFrom(e);
    if (!el || el === current) return;
    show(el);
  });

  document.addEventListener('mouseout', function (e) {
    if (!current) return;
    var to = e.relatedTarget;
    if (to && current.contains(to)) return;
    if (triggerFrom(e) === current) hide();
  });

  document.addEventListener('focusin', function (e) {
    var el = triggerFrom(e);
    if (el) show(el);
  });

  document.addEventListener('focusout', function (e) {
    if (current && triggerFrom(e) === current) hide();
  });

  document.addEventListener('pointerdown', hide, true);
  document.addEventListener('click', hide, true);
  document.addEventListener('scroll', hide, true);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') hide();
  });
})();
