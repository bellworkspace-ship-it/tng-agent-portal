function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied');
    if (btn) {
      const orig = btn.innerText;
      btn.innerText = '✓ Copied';
      setTimeout(() => { btn.innerText = orig; }, 1500);
    }
  });
}
function showToast(msg) {
  let t = document.getElementById('toast');
  if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; document.body.appendChild(t); }
  t.innerText = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1800);
}
function switchTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  const btn = document.querySelector('[data-tab="' + tabId + '"]');
  const pane = document.getElementById('pane-' + tabId);
  if (btn) btn.classList.add('active');
  if (pane) pane.classList.add('active');
  window.scrollTo({top: 0, behavior: 'smooth'});
}
function copyFromAttr(btn) {
  const text = btn.dataset.copy;
  copyToClipboard(text, btn);
}
window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  });
  document.querySelectorAll('[data-copy]').forEach(b => {
    b.addEventListener('click', () => copyFromAttr(b));
  });
  document.querySelectorAll('[data-jump]').forEach(a => {
    a.addEventListener('click', (e) => { e.preventDefault(); switchTab(a.dataset.jump); });
  });
});