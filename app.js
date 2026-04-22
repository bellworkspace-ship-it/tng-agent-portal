// ---------- DECRYPTION ----------
async function deriveKey(password, saltB64, iterations) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name: "PBKDF2", salt, iterations, hash: "SHA-256"},
    baseKey,
    {name: "AES-GCM", length: 256},
    false,
    ["decrypt"]
  );
}
async function decryptPayload(payload, password) {
  const key = await deriveKey(password, payload.salt, payload.iter);
  const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(payload.ct), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({name: "AES-GCM", iv}, key, ct);
  return new TextDecoder().decode(plain);
}

// ---------- LOCKSCREEN ----------
function setupLock() {
  const form = document.getElementById('lock-form');
  if (!form) return;
  // Try cached password (sessionStorage only, never localStorage)
  const cached = sessionStorage.getItem('tng-pw-' + window.AGENT_TOKEN);
  if (cached) {
    tryUnlock(cached, true);
  }
  form.addEventListener('submit', e => {
    e.preventDefault();
    const pw = document.getElementById('lock-pw').value;
    tryUnlock(pw, false);
  });
}
async function tryUnlock(password, silent) {
  try {
    const html = await decryptPayload(window.PAYLOAD, password);
    sessionStorage.setItem('tng-pw-' + window.AGENT_TOKEN, password);
    document.getElementById('lock-screen').style.display = 'none';
    const dash = document.getElementById('dash');
    dash.innerHTML = html;
    dash.style.display = 'block';
    initDashboard();
  } catch (err) {
    if (!silent) {
      document.getElementById('lock-error').style.display = 'block';
      document.getElementById('lock-pw').value = '';
      document.getElementById('lock-pw').focus();
    }
  }
}

// ---------- DASHBOARD UI ----------
function initDashboard() {
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  });
  document.querySelectorAll('[data-copy]').forEach(b => {
    b.addEventListener('click', () => copyToClipboard(b.dataset.copy, b));
  });
  document.querySelectorAll('[data-jump]').forEach(a => {
    a.addEventListener('click', e => { e.preventDefault(); switchTab(a.dataset.jump); });
  });
  initCheckboxes();
  const showBtn = document.getElementById('show-completed');
  if (showBtn) showBtn.addEventListener('click', toggleCompleted);
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

// ---------- CHECKBOXES + RESURFACE LOGIC ----------
const STATE_KEY = () => 'tng-done-' + window.AGENT_TOKEN;
function loadDoneState() {
  try { return JSON.parse(localStorage.getItem(STATE_KEY()) || '{}'); }
  catch { return {}; }
}
function saveDoneState(state) {
  localStorage.setItem(STATE_KEY(), JSON.stringify(state));
}
let showingCompleted = false;
function initCheckboxes() {
  const state = loadDoneState();
  // Prune expired entries (older than 30 days) and entries for leads no longer present
  const now = Date.now();
  const presentIds = new Set(Array.from(document.querySelectorAll('.lead-card[data-lead-id]'))
                              .map(c => c.dataset.leadId));
  Object.keys(state).forEach(id => {
    if (now - state[id].at > 30 * 86400 * 1000) delete state[id];
  });
  // Apply to cards
  document.querySelectorAll('.lead-card[data-lead-id]').forEach(card => {
    const id = card.dataset.leadId;
    const sig = card.dataset.sig;
    const cb = card.querySelector('input.lead-done');
    const entry = state[id];
    if (entry) {
      if (entry.sig === sig) {
        // Same signature → still done, hide
        cb.checked = true;
        card.classList.add('done', 'hidden');
      } else {
        // Signature changed → resurface as fresh task. Mark with badge.
        card.classList.add('resurfaced');
        const nameDiv = card.querySelector('.name');
        if (nameDiv && !nameDiv.querySelector('.card-badge.resurfaced')) {
          const b = document.createElement('span');
          b.className = 'card-badge resurfaced';
          b.innerText = '🔔 RESURFACED — new activity';
          nameDiv.appendChild(b);
        }
        delete state[id];
      }
    }
  });
  saveDoneState(state);
  // Wire checkbox handlers
  document.querySelectorAll('input.lead-done').forEach(cb => {
    cb.addEventListener('change', e => {
      const card = cb.closest('.lead-card');
      const id = cb.dataset.leadId;
      const sig = cb.dataset.sig;
      const st = loadDoneState();
      if (cb.checked) {
        st[id] = {sig, at: Date.now()};
        card.classList.add('done');
        setTimeout(() => { if (!showingCompleted) card.classList.add('hidden'); }, 350);
      } else {
        delete st[id];
        card.classList.remove('done', 'hidden');
      }
      saveDoneState(st);
      updateProgressBadge();
    });
  });
  updateProgressBadge();
}
function toggleCompleted() {
  showingCompleted = !showingCompleted;
  document.querySelectorAll('.lead-card.done').forEach(c => {
    c.classList.toggle('hidden', !showingCompleted);
  });
  const btn = document.getElementById('show-completed');
  if (btn) btn.innerText = showingCompleted ? 'Hide completed' : 'Show completed items';
}
function updateProgressBadge() {
  const badge = document.getElementById('progress-badge');
  if (!badge) return;
  const st = loadDoneState();
  // Count entries from today only
  const todayMs = new Date().setHours(0, 0, 0, 0);
  const doneToday = Object.values(st).filter(e => e.at >= todayMs).length;
  badge.innerText = doneToday + ' done today';
}

// ---------- BOOTSTRAP ----------
window.addEventListener('DOMContentLoaded', () => {
  if (window.PAYLOAD) {
    setupLock();
  } else {
    // index page or other unencrypted page — wire copy buttons
    document.querySelectorAll('[data-copy]').forEach(b => {
      b.addEventListener('click', () => copyToClipboard(b.dataset.copy, b));
    });
  }
});