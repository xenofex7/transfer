(function () {
  'use strict';

  var root = document.querySelector('[data-tabs]');
  if (!root) return;

  var tabs = Array.prototype.slice.call(root.querySelectorAll('[data-tab]'));
  var panels = Array.prototype.slice.call(document.querySelectorAll('[data-tab-panel]'));

  function activate(name, focus) {
    var found = false;
    tabs.forEach(function (tab) {
      var on = tab.dataset.tab === name;
      if (on) found = true;
      tab.classList.toggle('is-active', on);
      tab.setAttribute('aria-selected', on ? 'true' : 'false');
      tab.tabIndex = on ? 0 : -1;
      if (on && focus) tab.focus();
    });
    if (!found) return false;
    delete document.documentElement.dataset.tab;
    panels.forEach(function (panel) {
      panel.hidden = panel.dataset.tabPanel !== name;
    });
    return true;
  }

  tabs.forEach(function (tab, i) {
    tab.addEventListener('click', function () {
      activate(tab.dataset.tab, false);
      history.replaceState(null, '', '#' + tab.dataset.tab);
    });
    tab.addEventListener('keydown', function (e) {
      var next = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : -1;
      if (next < 0 || next >= tabs.length) return;
      e.preventDefault();
      activate(tabs[next].dataset.tab, true);
      history.replaceState(null, '', '#' + tabs[next].dataset.tab);
    });
  });

  function fromHash() {
    var name = location.hash.replace('#', '');
    if (!name || !activate(name, false)) activate(tabs[0].dataset.tab, false);
  }

  window.addEventListener('hashchange', fromHash);
  fromHash();
})();
