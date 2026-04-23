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
  // Pull worker config out of the embedded DOM element (innerHTML won't execute <script> tags)
  const cfg = document.getElementById('tng-worker-cfg');
  if (cfg) {
    window.TNG_WORKER = {
      url: cfg.dataset.url || '',
      token: cfg.dataset.token || '',
    };
  }
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  });
  document.querySelectorAll('[data-copy]').forEach(b => {
    b.addEventListener('click', () => copyToClipboard(b.dataset.copy, b));
  });
  document.querySelectorAll('[data-jump]').forEach(a => {
    a.addEventListener('click', e => { e.preventDefault(); switchTab(a.dataset.jump); });
  });
  initChannelTabs();
  initFilters();
  initCheckboxes();
  initListingActions();
  initTextLogging();
  const showBtn = document.getElementById('show-completed');
  if (showBtn) showBtn.addEventListener('click', toggleCompleted);
}

// ---------- TEXT AUTO-LOGGING ----------
// When an agent taps "Send text" on a card, the sms: link opens their phone's
// SMS app normally. In parallel, we fire a background POST to the worker's
// /texts endpoint so FUB records an outbound text on the lead's timeline.
// Uses keepalive:true so the request survives the tab losing focus when the
// SMS app takes over. Best-effort — we don't block or wait.
function initTextLogging() {
  if (!window.TNG_WORKER || !window.TNG_WORKER.url) return;  // worker disabled
  document.querySelectorAll('a[data-log-text="1"]').forEach(a => {
    a.addEventListener('click', () => {
      // Don't preventDefault — sms: still needs to navigate.
      const leadId = a.dataset.leadId;
      const toNumber = a.dataset.toNumber || '';
      const message = a.dataset.message || '';
      const statusEl = a.closest('.ch-pane')?.querySelector('[data-log-status]');
      if (!leadId || !message) return;
      try {
        fetch(window.TNG_WORKER.url + '/texts', {
          method: 'POST',
          keepalive: true,
          headers: workerHeaders(),
          body: JSON.stringify({
            personId: parseInt(leadId, 10),
            toNumber: toNumber,
            message: message,
            isIncoming: false,
            sentAt: new Date().toISOString(),
          }),
        }).then(async resp => {
          if (!statusEl) return;
          if (resp.ok) {
            statusEl.innerText = '\u2713 Text logged to FUB';
            statusEl.className = 'log-status ok';
          } else {
            const txt = await resp.text().catch(() => '');
            statusEl.innerText = 'Log failed (' + resp.status + ')' + (txt ? ' \u2014 ' + txt.slice(0, 120) : '');
            statusEl.className = 'log-status err';
          }
        }).catch(err => {
          if (statusEl) {
            statusEl.innerText = 'Log failed \u2014 ' + (err && err.message || err);
            statusEl.className = 'log-status err';
          }
        });
        if (statusEl) {
          statusEl.innerText = 'Logging to FUB\u2026';
          statusEl.className = 'log-status pending';
        }
      } catch (e) {
        if (statusEl) {
          statusEl.innerText = 'Log failed \u2014 ' + (e && e.message || e);
          statusEl.className = 'log-status err';
        }
      }
    });
  });
}

// ---------- LISTING INLINE WRITE-BACK (Add Note / Log Call / Change Stage) ----------
const FUB_CALL_OUTCOMES = {
  '__reached__':    'Interested',
  '__voicemail__':  'Left Message',
  '__no_answer__':  'No Answer',
  '__bad_number__': 'Bad Number',
  '__dnc__':        'Do Not Call',
};
const OUTCOME_LABEL = {
  '__reached__':    'Reached / Spoke',
  '__voicemail__':  'Left voicemail',
  '__no_answer__':  'No answer',
  '__bad_number__': 'Bad number',
  '__dnc__':        'DNC',
};
let currentListingCtx = null;  // {kind, leadId, leadName, currentStage, card}

function initListingActions() {
  const modal = document.getElementById('listing-modal');
  if (!modal) return;  // worker not configured — deep-link fallback, no modal
  document.querySelectorAll('[data-act]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.preventDefault();
      // Buttons live on both listing cards (Active Listings tab) and lead
      // cards (Action Queue, Hot, Online, Fello, Cold 30+, Referrals, Pond).
      const card = btn.closest('.listing-card, .lead-card');
      openListingModal({
        kind: btn.dataset.act,
        leadId: btn.dataset.leadId,
        leadName: btn.dataset.leadName,
        currentStage: btn.dataset.currentStage || '',
        phone: btn.dataset.phone || '',
        card: card,
      });
    });
  });
  // Close handlers
  modal.querySelectorAll('[data-modal-close]').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); closeListingModal(); });
  });
  // Keyboard: Esc
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && modal.style.display !== 'none') closeListingModal();
  });
  // Form submissions
  const noteForm  = modal.querySelector('[data-form="note"]');
  const callForm  = modal.querySelector('[data-form="call"]');
  const stageForm = modal.querySelector('[data-form="stage"]');
  if (noteForm)  noteForm.addEventListener('submit',  submitNoteForm);
  if (callForm)  callForm.addEventListener('submit',  submitCallForm);
  if (stageForm) stageForm.addEventListener('submit', submitStageForm);
}

function openListingModal(ctx) {
  currentListingCtx = ctx;
  const modal = document.getElementById('listing-modal');
  const title = modal.querySelector('[data-modal-title]');
  const sub   = modal.querySelector('[data-modal-sub]');
  const err   = modal.querySelector('[data-modal-err]');
  err.style.display = 'none';
  err.innerText = '';
  // Hide all forms
  modal.querySelectorAll('.listing-modal-form').forEach(f => f.style.display = 'none');
  // Reset fields
  modal.querySelectorAll('textarea, select, input').forEach(i => {
    if (i.tagName === 'SELECT') i.selectedIndex = 0;
    else i.value = '';
  });

  if (ctx.kind === 'note') {
    title.innerText = 'Add note to ' + ctx.leadName;
    sub.innerText   = 'Saves directly to this lead\u2019s FUB profile';
    modal.querySelector('[data-form="note"]').style.display = 'flex';
  } else if (ctx.kind === 'call') {
    title.innerText = 'Log call with ' + ctx.leadName;
    sub.innerText   = 'Logs a call event on this lead in FUB';
    modal.querySelector('[data-form="call"]').style.display = 'flex';
  } else if (ctx.kind === 'stage') {
    title.innerText = 'Change stage for ' + ctx.leadName;
    sub.innerText   = 'Current stage: ' + (ctx.currentStage || 'Unknown');
    const form = modal.querySelector('[data-form="stage"]');
    form.style.display = 'flex';
    // Default-select matching stage by name
    const sel = form.querySelector('select');
    for (let i = 0; i < sel.options.length; i++) {
      if (sel.options[i].text === ctx.currentStage) { sel.selectedIndex = i; break; }
    }
  }
  modal.style.display = 'flex';
  // Focus the first field
  setTimeout(() => {
    const first = modal.querySelector('.listing-modal-form:not([style*="none"]) textarea, .listing-modal-form:not([style*="none"]) select');
    if (first) first.focus();
  }, 50);
}

function closeListingModal() {
  const modal = document.getElementById('listing-modal');
  if (modal) modal.style.display = 'none';
  currentListingCtx = null;
}

function workerHeaders() {
  return {
    'Content-Type': 'application/json',
    'X-TNG-Token': (window.TNG_WORKER && window.TNG_WORKER.token) || '',
  };
}

async function submitNoteForm(e) {
  e.preventDefault();
  const ctx = currentListingCtx; if (!ctx) return;
  const form = e.target;
  const btn  = form.querySelector('[data-submit-btn]');
  const err  = document.querySelector('[data-modal-err]');
  const body = form.querySelector('[data-field="body"]').value.trim();
  if (!body) { err.innerText = 'Note body is required'; err.style.display = 'block'; return; }
  btn.classList.add('saving'); btn.innerText = 'Saving\u2026';
  try {
    const resp = await fetch(window.TNG_WORKER.url + '/notes', {
      method: 'POST',
      headers: workerHeaders(),
      body: JSON.stringify({
        personId: parseInt(ctx.leadId, 10),
        subject: 'Note from agent portal',
        body: body,
        isHtml: false,
      }),
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status + ' \u2014 ' + (await resp.text()));
    await resp.json().catch(() => null);
    closeListingModal();
    markListingUpdated(ctx.card, '\u2713 Note saved to FUB');
    showToast('Note saved', 'good');
  } catch (ex) {
    err.innerText = 'Failed to save note: ' + ex.message;
    err.style.display = 'block';
    btn.classList.remove('saving'); btn.innerText = 'Save note';
  }
}

async function submitCallForm(e) {
  e.preventDefault();
  const ctx = currentListingCtx; if (!ctx) return;
  const form = e.target;
  const btn  = form.querySelector('[data-submit-btn]');
  const err  = document.querySelector('[data-modal-err]');
  const outcomeKey = form.querySelector('[data-field="outcomeId"]').value;
  const direction  = form.querySelector('[data-field="direction"]').value;
  const note       = form.querySelector('[data-field="note"]').value.trim();
  if (!outcomeKey) { err.innerText = 'Outcome is required'; err.style.display = 'block'; return; }
  const outcomeName = FUB_CALL_OUTCOMES[outcomeKey] || outcomeKey;
  const outcomeLbl  = OUTCOME_LABEL[outcomeKey]     || outcomeKey;
  btn.classList.add('saving'); btn.innerText = 'Logging\u2026';
  try {
    const callBody = {
      personId:   parseInt(ctx.leadId, 10),
      note:       note || ('Call: ' + outcomeLbl),
      isIncoming: direction === 'Inbound',
      outcome:    outcomeName,
      duration:   0,
    };
    // FUB requires `phone` on POST /v1/calls. If we have one on the card,
    // pass it through — otherwise the worker will look it up from the
    // person record before forwarding.
    if (ctx.phone) callBody.phone = ctx.phone;
    const resp = await fetch(window.TNG_WORKER.url + '/calls', {
      method: 'POST',
      headers: workerHeaders(),
      body: JSON.stringify(callBody),
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status + ' \u2014 ' + (await resp.text()));
    await resp.json().catch(() => null);
    closeListingModal();
    markListingUpdated(ctx.card, '\u2713 Call logged (' + outcomeLbl + ')');
    showToast('Call logged', 'good');
  } catch (ex) {
    err.innerText = 'Failed to log call: ' + ex.message;
    err.style.display = 'block';
    btn.classList.remove('saving'); btn.innerText = 'Log call';
  }
}

async function submitStageForm(e) {
  e.preventDefault();
  const ctx = currentListingCtx; if (!ctx) return;
  const form = e.target;
  const btn  = form.querySelector('[data-submit-btn]');
  const err  = document.querySelector('[data-modal-err]');
  const sel  = form.querySelector('[data-field="stageId"]');
  const stageId   = sel.value;
  const stageName = sel.options[sel.selectedIndex] ? sel.options[sel.selectedIndex].text : '';
  if (!stageId) { err.innerText = 'Select a new stage'; err.style.display = 'block'; return; }
  btn.classList.add('saving'); btn.innerText = 'Updating\u2026';
  try {
    const resp = await fetch(window.TNG_WORKER.url + '/person/' + encodeURIComponent(ctx.leadId), {
      method: 'PUT',
      headers: workerHeaders(),
      body: JSON.stringify({ stageId: parseInt(stageId, 10) }),
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status + ' \u2014 ' + (await resp.text()));
    await resp.json().catch(() => null);
    closeListingModal();
    updateStageBadge(ctx.card, stageName);
    markListingUpdated(ctx.card, '\u2713 Stage changed to ' + stageName);
    showToast('Stage changed', 'good');
  } catch (ex) {
    err.innerText = 'Failed to change stage: ' + ex.message;
    err.style.display = 'block';
    btn.classList.remove('saving'); btn.innerText = 'Change stage';
  }
}

function markListingUpdated(card, message) {
  if (!card) return;
  // Flip last-comm indicator to "Just now — fresh" optimistically
  const lc = card.querySelector('[data-last-comm]');
  if (lc) {
    lc.innerHTML = '<span class="lc-fresh">\u2713 Just now \u2014 fresh touch recorded</span>';
  }
  card.classList.remove('overdue');
  card.classList.add('fresh');
  const conf = card.querySelector('[data-confirm]');
  if (conf) {
    conf.innerText = message;
    conf.classList.remove('err');
    conf.style.display = 'block';
  }
}

function updateStageBadge(card, stageName) {
  if (!card) return;
  const badge = card.querySelector('[data-stage-badge]');
  if (!badge) return;
  badge.innerText = stageName;
  // Reclass by matching the simple rules from the Python helper
  const s = (stageName || '').trim().toLowerCase();
  badge.className = 'lc-stage-badge';
  if (s === 'active listing')        badge.classList.add('active');
  else if (s === 'under contract' || s === 'pending') badge.classList.add('uc');
  else if (s === 'submitting offers') badge.classList.add('submit');
  else if (s === 'listing agreement') badge.classList.add('agreement');
  else                                 badge.classList.add('other');
  // Also update the button's data-current-stage for subsequent clicks
  const stageBtn = card.querySelector('[data-act="stage"]');
  if (stageBtn) stageBtn.setAttribute('data-current-stage', stageName);
}
function initChannelTabs() {
  // Channel tabs (call/text/email) within each lead card
  document.querySelectorAll('.lead-card').forEach(card => {
    const tabs = card.querySelectorAll('.ch-tab');
    const panes = card.querySelectorAll('.ch-pane');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        panes.forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        const target = card.querySelector('.ch-pane[data-ch="' + tab.dataset.ch + '"]');
        if (target) target.classList.add('active');
      });
    });
  });
}
function initFilters() {
  document.querySelectorAll('.filter-bar').forEach(bar => {
    const targetCls = bar.dataset.target;
    const container = document.querySelector('.' + targetCls);
    if (!container) return;
    const state = {source: '', stage: ''};
    function applyFilter() {
      const cards = container.querySelectorAll('.lead-card');
      let visible = 0;
      cards.forEach(c => {
        const srcOK = !state.source || c.dataset.source === state.source;
        const stgOK = !state.stage || c.dataset.stage === state.stage;
        if (srcOK && stgOK) {
          c.classList.remove('filter-hidden');
          if (!c.classList.contains('hidden')) visible++;
        } else {
          c.classList.add('filter-hidden');
        }
      });
      const cnt = bar.querySelector('.visible-count');
      if (cnt) cnt.innerText = visible;
    }
    bar.querySelectorAll('.filter-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const type = chip.dataset.filterType;
        const value = chip.dataset.filterValue;
        // Toggle within the filter group
        bar.querySelectorAll('.filter-chip[data-filter-type="' + type + '"]').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        state[type] = value;
        applyFilter();
      });
    });
    applyFilter();
  });
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
function showToast(msg, kind) {
  let t = document.getElementById('toast');
  if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; document.body.appendChild(t); }
  t.className = 'toast' + (kind ? (' ' + kind) : '');
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

// ---------- THEME (light / dark toggle) ----------
function getStoredTheme() {
  try { return localStorage.getItem('tng-theme'); } catch (e) { return null; }
}
function storeTheme(t) {
  try { localStorage.setItem('tng-theme', t); } catch (e) {}
}
function applyTheme(theme) {
  const t = (theme === 'light') ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', t);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) {
    const isLight = (t === 'light');
    btn.querySelector('.tt-icon').textContent = isLight ? '\u263C' : '\u263E'; // sun / crescent moon
    btn.querySelector('.tt-label').textContent = isLight ? 'Light' : 'Dark';
    btn.setAttribute('aria-label', 'Switch to ' + (isLight ? 'dark' : 'light') + ' theme');
    btn.setAttribute('title', 'Switch to ' + (isLight ? 'dark' : 'light') + ' theme');
  }
}
function initTheme() {
  const stored = getStoredTheme();
  let theme = stored;
  if (!theme) {
    theme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  }
  applyTheme(theme);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = (cur === 'light') ? 'dark' : 'light';
      applyTheme(next);
      storeTheme(next);
    });
  }
}

// ---------- BOOTSTRAP ----------
window.addEventListener('DOMContentLoaded', () => {
  initTheme();
  if (window.PAYLOAD) {
    setupLock();
  } else {
    // index page or other unencrypted page — wire copy buttons
    document.querySelectorAll('[data-copy]').forEach(b => {
      b.addEventListener('click', () => copyToClipboard(b.dataset.copy, b));
    });
  }
});