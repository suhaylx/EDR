'use strict';
// Lab SOC evidence controls. Presentation only: never changes endpoint policy.
(function (root) {
  function matchesEvidence(text, query) {
    const q = String(query || '').trim().toLocaleLowerCase();
    return String(text || '').toLocaleLowerCase().includes(q);
  }
  // A source link must reveal an item hidden by the local evidence filter
  // before moving keyboard/screen-reader focus to that retained record.
  function focusEvidence(target, input, update) {
    if (!target || !input || typeof update !== 'function') return false;
    if (target.hidden) {
      input.value = '';
      update();
    }
    if (target.hidden) return false;
    target.tabIndex = -1; // Programmatic focus without adding every record to the tab order.
    if (typeof target.focus === 'function') target.focus();
    if (typeof target.scrollIntoView === 'function') target.scrollIntoView({block: 'nearest'});
    return true;
  }
  function attach(container) {
    if (!container || typeof container.querySelector !== 'function') return false;
    const tree = container.querySelector('.process-tree');
    const timeline = container.querySelector('.evidence-timeline');
    if (!tree && !timeline) return false;
    const doc = container.ownerDocument;
    if (tree && !tree.hasAttribute('data-graph-ux-bound')) {
      // Native details/summary provides Enter/Space operation and screen-reader state.
      for (const li of Array.from(tree.querySelectorAll('li')).reverse()) {
        const node = li.querySelector(':scope > .process-node');
        const children = li.querySelector(':scope > ul');
        if (!node || !children) continue;
        const details = doc.createElement('details');
        details.className = 'process-branch';
        details.open = true;
        const summary = doc.createElement('summary');
        summary.className = node.className;
        if (node.hasAttribute('data-process-guid')) {
          summary.setAttribute('data-process-guid', node.getAttribute('data-process-guid'));
        }
        while (node.firstChild) summary.appendChild(node.firstChild);
        details.append(summary, children);
        li.replaceChildren(details);
      }
      const controls = doc.createElement('div');
      controls.className = 'graph-controls';
      const all = doc.createElement('button');
      all.type = 'button';
      all.textContent = 'Expand all processes';
      const none = doc.createElement('button');
      none.type = 'button';
      none.textContent = 'Collapse all processes';
      all.addEventListener('click', () => tree.querySelectorAll('details.process-branch').forEach(d => { d.open = true; }));
      none.addEventListener('click', () => tree.querySelectorAll('details.process-branch').forEach(d => { d.open = false; }));
      controls.append(all, none);
      tree.parentNode.insertBefore(controls, tree);
      tree.setAttribute('data-graph-ux-bound', 'true');
    }
    if (timeline && !timeline.hasAttribute('data-graph-ux-bound')) {
      const items = Array.from(timeline.querySelectorAll(':scope > li'));
      timeline.id = 'graph-evidence-timeline';
      const searchWrap = doc.createElement('div');
      searchWrap.className = 'graph-filter';
      const label = doc.createElement('label');
      label.htmlFor = 'graphEvidenceFilter';
      label.textContent = 'Filter retained evidence (type, process GUID, source ID or path)';
      const input = doc.createElement('input');
      input.id = 'graphEvidenceFilter';
      input.type = 'search';
      input.autocomplete = 'off';
      input.setAttribute('aria-controls', timeline.id);
      const status = doc.createElement('p');
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      const update = () => {
        let visible = 0;
        for (const item of items) {
          item.hidden = !matchesEvidence(item.textContent, input.value);
          if (!item.hidden) visible++;
        }
        status.textContent = visible + ' of ' + items.length + ' retained evidence record(s) shown. Local filter only; no extra evidence fetched.';
      };
      items.forEach((li, index) => { li.id = 'graph-evidence-' + (index + 1); });
      input.addEventListener('input', update);
      searchWrap.append(label, input, status);
      timeline.parentNode.insertBefore(searchWrap, timeline);
      if (tree) {
        for (const process of tree.querySelectorAll('[data-process-guid]')) {
          const guid = process.getAttribute('data-process-guid');
          if (!guid) continue;
          const matched = items.find(item => item.getAttribute('data-process-guid') === guid);
          if (!matched) continue;
          const link = doc.createElement('a');
          link.className = 'graph-source-link';
          link.href = '#' + matched.id;
          link.textContent = 'Inspect retained source ' + (matched.getAttribute('data-source-id') || 'event');
          // Link sits outside details summary to avoid activation conflicts.
          const li = process.closest('li');
          if (li) {
            li.appendChild(link);
            link.addEventListener('click', event => {
              if (focusEvidence(matched, input, update)) event.preventDefault();
            });
          }
        }
      }
      update();
      timeline.setAttribute('data-graph-ux-bound', 'true');
    }
    return true;
  }
  const exported = Object.freeze({ attach, matchesEvidence, focusEvidence });
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  if (root) root.TuranGraphUX = exported;
})(typeof globalThis === 'undefined' ? null : globalThis);
