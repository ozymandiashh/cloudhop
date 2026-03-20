/*
 * wizard.js - CloudHop setup wizard
 *
 * 6-step wizard flow
 *   Step 1: Welcome / rclone check
 *   Step 2: Select source provider
 *   Step 3: Select destination provider
 *   Step 4: Speed / advanced options
 *   Step 5: Connect accounts (OAuth or credentials)
 *   Step 6: Summary + Start
 *   goTo(step) handles all step transitions; it runs pre-step hooks
 *   (e.g. buildConnectStep, buildSummary) before showing the new step.
 *
 * State persistence
 *   The wizard state (current step, provider names, remote names) is
 *   serialised to sessionStorage on every goTo() call.  An IIFE at the
 *   bottom of the file restores it on load so a page refresh doesn't reset
 *   the user's progress.
 *
 * OAuth flow (Google Drive, OneDrive, Dropbox)
 *   connectRemote() POSTs to /api/wizard/configure-remote which runs
 *   `rclone config create ...`.  For OAuth providers, rclone opens a browser
 *   tab for the sign-in flow.  Meanwhile, startPolling() polls
 *   /api/wizard/check-remote every 2 s to detect when rclone writes the token
 *   to its config file.  The poll times out after 2 minutes and shows a
 *   "Try again" link.
 *
 * Provider keys
 *   `providerKeys` maps the UI provider identifier (e.g. "drive") to the
 *   rclone backend type string (e.g. "gdrive") that is passed to
 *   `rclone config create <name> <type>`.  The remote name used in rclone
 *   paths (e.g. "gdrive:Photos") is stored in sourceName / destName.
 */
function getCsrfToken(){return document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith('csrf_token='))?.substring('csrf_token='.length)||''}
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
// State
let currentStep = 1;
let sourceProvider = null;
let sourceName = '';
let sourceDisplayName = '';
let destProvider = null;
let destName = '';
let destDisplayName = '';
let selectedSpeed = '8';
let existingRemotes = [];

const providerKeys = {
  drive: 'gdrive', onedrive: 'onedrive', dropbox: 'dropbox', mega: 'mega', s3: 's3', protondrive: 'protondrive', local: 'local', icloud: 'local', other: null
};
const providerIcons = {
  drive: '<svg width="32" height="29" viewBox="0 0 87.3 78"><path d="m6.6 66.85 3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3l13.75-23.8h-27.5c0 1.55.4 3.1 1.2 4.5z" fill="#0066da"/><path d="m43.65 25-13.75-23.8c-1.35.8-2.5 1.9-3.3 3.3l-25.4 44c-.8 1.4-1.2 2.9-1.2 4.5h27.5z" fill="#00ac47"/><path d="m73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75 7.65-13.25c.8-1.4 1.2-2.95 1.2-4.5h-27.5l5.85 11.5z" fill="#ea4335"/><path d="m43.65 25 13.75-23.8c-1.35-.8-2.9-1.2-4.5-1.2h-18.5c-1.6 0-3.15.45-4.5 1.2z" fill="#00832d"/><path d="m59.8 53h-32.3l-13.75 23.8c1.35.8 2.9 1.2 4.5 1.2h50.8c1.6 0 3.15-.45 4.5-1.2z" fill="#2684fc"/><path d="m73.4 26.5-12.7-22c-.8-1.4-1.95-2.5-3.3-3.3l-13.75 23.8 16.15 28h27.45c0-1.55-.4-3.1-1.2-4.5z" fill="#ffba00"/></svg>',
  onedrive: '<svg width="32" height="22" viewBox="0 0 24 16"><defs><linearGradient id="odgjs" x1="0" y1="0" x2="24" y2="16" gradientUnits="userSpaceOnUse"><stop stop-color="#0364b8"/><stop offset="1" stop-color="#28a8ea"/></linearGradient></defs><path d="M19.5 7c-.2 0-.4 0-.6.1C18.1 3.6 15.3 1 12 1 9.2 1 6.8 2.8 5.7 5.4 5.5 5.3 5.2 5.2 5 5.2 3.3 5.2 2 6.5 2 8.2c0 .2 0 .4.1.6C.8 9.4 0 10.8 0 12.5 0 15 2 17 4.5 17H19c2.8 0 5-2.2 5-5s-2.2-5-5-5z" fill="url(#odgjs)"/></svg>',
  dropbox: '<svg width="28" height="28" viewBox="0 0 16 16"><path d="M8.01 4.555 4.005 7.11 8.01 9.665 4.005 12.22 0 9.651l4.005-2.555L0 4.555 4.005 2zm-4.026 8.487 4.006-2.555 4.005 2.555-4.005 2.555zm4.026-3.39 4.005-2.556L8.01 4.555 11.995 2 16 4.555 11.995 7.11 16 9.665l-4.005 2.555z" fill="#0061fe"/></svg>',
  mega: '<svg width="28" height="28" viewBox="100 141 118 118"><path d="m158.711 141.289c-32.426 0-58.711 26.285-58.711 58.711s26.285 58.711 58.711 58.711 58.711-26.285 58.711-58.711-26.285-58.711-58.711-58.711zm30.476 79.473c0 1.007-.812 1.819-1.819 1.819h-7.668c-1.007 0-1.819-.812-1.819-1.819v-23.621c0-.195-.228-.293-.39-.163l-16.246 16.246c-1.397 1.397-3.704 1.397-5.101 0l-16.245-16.246c-.13-.13-.39-.032-.39.163v23.621c0 1.007-.812 1.819-1.82 1.819h-7.667c-1.008 0-1.82-.812-1.82-1.819v-41.524c0-1.007.812-1.819 1.82-1.819h5.263c.942 0 1.885.39 2.567 1.072l20.209 20.209c.358.358.91.358 1.267 0l20.21-20.209c.682-.682 1.592-1.072 2.566-1.072h5.264c1.007 0 1.819.812 1.819 1.819z" fill="#d9272e"/></svg>',
  s3: '<svg width="28" height="28" viewBox="0 0 24 24"><path d="M20 4H4l-1 8h18l-1-8z" fill="#f90"/><path d="M3 12l1 8h16l1-8H3z" fill="#f90" opacity=".8"/><ellipse cx="12" cy="4" rx="8" ry="2" fill="#f90" opacity=".6"/><text x="12" y="16" font-family="Arial,sans-serif" font-size="7" font-weight="bold" fill="white" text-anchor="middle">S3</text></svg>',
  protondrive: '<svg width="28" height="26" viewBox="0 0 24 22"><defs><linearGradient id="pdgjs" x1="0" y1="0" x2="24" y2="22" gradientUnits="userSpaceOnUse"><stop stop-color="#d4b4f7"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs><path d="M20 6H4C2.9 6 2 6.9 2 8v10c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z" fill="url(#pdgjs)"/><path d="M22 5H10L8 2H4c-1.1 0-2 .9-2 2v1h16c1.1 0 2 .9 2 2V5z" fill="url(#pdgjs)" opacity=".6"/></svg>',
  local: '<svg width="28" height="28" viewBox="0 0 24 24"><path d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z" fill="var(--text-dim)"/></svg>',
  icloud: '<svg width="32" height="22" viewBox="0 0 24 16"><defs><linearGradient id="icgjs" x1="0" y1="0" x2="24" y2="16" gradientUnits="userSpaceOnUse"><stop stop-color="#a8d8f0"/><stop offset="1" stop-color="#5ab0e4"/></linearGradient></defs><path d="M19 7c-.2 0-.3 0-.5.1C17.7 3.5 15 1 12 1 9.2 1 6.8 2.8 5.7 5.4 5.5 5.3 5.3 5.3 5 5.3 3.3 5.3 2 6.6 2 8.3c0 .2 0 .4.1.5C.8 9.5 0 10.9 0 12.5 0 14.9 2 17 4.5 17h14c2.8 0 5-2.2 5-5s-2.2-5-4.5-5z" fill="url(#icgjs)"/></svg>',
  other: '<svg width="28" height="28" viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1112 8.4a3.6 3.6 0 010 7.2z" fill="var(--text-dim)"/></svg>'
};

// Theme
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  document.body.style.transition = 'none';
  html.setAttribute('data-theme', next);
  document.querySelector('.theme-toggle').textContent = next === 'light' ? '\u2600' : '\u263E';
  localStorage.setItem('cloudhop-theme', next);
  requestAnimationFrame(() => { requestAnimationFrame(() => { document.body.style.transition = ''; }); });
}
(function() {
  const saved = localStorage.getItem('cloudhop-theme');
  if (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('.theme-toggle').textContent = '\u2600';
  }
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('.theme-toggle').textContent = '\u2600';
  }
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem('cloudhop-theme')) {
      document.documentElement.setAttribute('data-theme', e.matches ? 'light' : 'dark');
      document.querySelector('.theme-toggle').textContent = e.matches ? '\u2600' : '\u263E';
    }
  });
})();

// Fetch home directory and check rclone on page load
(function() {
  fetch('/api/wizard/status').then(r => r.json()).then(d => {
    if (d.home_dir) window._homeDir = d.home_dir;
    const el = document.getElementById('welcomeRcloneCheck');
    if (!d.rclone_installed) {
      el.innerHTML = '<span style="color:var(--orange)">Required components will be installed automatically when you proceed.</span>';
    }
  }).catch(() => {});
})();

// Styled confirm modal (replaces native confirm())
function showConfirmModal(message) {
  return new Promise((resolve) => {
    if (document.getElementById('_cm_wiz_overlay')) return resolve(false);
    const overlay = document.createElement('div');
    overlay.id = '_cm_wiz_overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:400;display:flex;align-items:center;justify-content:center;';
    const box = document.createElement('div');
    box.style.cssText = 'background:var(--card);border:1px solid var(--card-border);border-radius:16px;padding:28px 24px;max-width:440px;width:90%;text-align:center;';
    box.innerHTML = '<div style="font-size:0.95rem;color:var(--text);margin-bottom:20px;line-height:1.6;">' + esc(message) + '</div>'
      + '<div style="display:flex;gap:12px;justify-content:center;">'
      + '<button id="cmConfirmCancel" class="btn btn-secondary" style="padding:10px 24px;border-radius:10px;font-size:0.85rem;cursor:pointer;">Cancel</button>'
      + '<button id="cmConfirmOk" class="btn btn-primary" style="padding:10px 24px;border-radius:10px;font-size:0.85rem;cursor:pointer;">Continue</button>'
      + '</div>';
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    function cleanup() { overlay.remove(); document.removeEventListener('keydown', escHandler); }
    function escHandler(e) { if (e.key === 'Escape') { cleanup(); resolve(false); } }
    document.addEventListener('keydown', escHandler);
    box.querySelector('#cmConfirmCancel').onclick = () => { cleanup(); resolve(false); };
    box.querySelector('#cmConfirmOk').onclick = () => { cleanup(); resolve(true); };
    overlay.addEventListener('click', (e) => { if (e.target === overlay) { cleanup(); resolve(false); } });
    box.querySelector('#cmConfirmOk').focus();
  });
}

// Navigation
async function goTo(step) {
  if (step >= 3 && !sourceProvider) return;
  if (step >= 4 && !destProvider) return;
  if (step === 3) updateDestGrid();
  if (step === 5) buildConnectStep();
  if (step === 6) {
    if (sourceProvider === destProvider && sourceProvider !== 'local' && sourceProvider !== 'icloud') {
      const proceed = await showConfirmModal('Source and destination are the same service. Two separate accounts will be set up (e.g. "gdrive" for source and "gdrive_dest" for destination). Continue?');
      if (!proceed) return;
    }
    buildSummary();
  }

  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  document.getElementById('step' + step).classList.add('active');

  const dots = document.querySelectorAll('.dot');
  dots.forEach((d, i) => {
    d.classList.remove('active', 'done');
    if (i < step - 1) d.classList.add('done');
    if (i === step - 1) d.classList.add('active');
  });

  // Restore previous selections when navigating back
  if (step === 2 && sourceProvider) {
    const sc = document.querySelector('#sourceGrid [data-provider="'+sourceProvider+'"]');
    if (sc && !sc.classList.contains('selected')) {
      document.querySelectorAll('#sourceGrid .provider-card').forEach(c => c.classList.remove('selected'));
      sc.classList.add('selected');
    }
    document.getElementById('sourceLocalPath').classList.toggle('show', sourceProvider === 'local' || sourceProvider === 'icloud');
    document.getElementById('sourceOtherName').classList.toggle('show', sourceProvider === 'other');
    if (sourceProvider === 'local' || sourceProvider === 'icloud') {
      document.getElementById('sourceNext').disabled = !document.getElementById('sourcePathInput').value.trim();
    } else if (sourceProvider === 'other') {
      document.getElementById('sourceNext').disabled = !document.getElementById('sourceOtherInput').value.trim();
    } else {
      document.getElementById('sourceNext').disabled = false;
    }
  }
  if (step === 3 && destProvider) {
    const dc = document.querySelector('#destGrid [data-provider="'+destProvider+'"]');
    if (dc && !dc.classList.contains('selected')) {
      document.querySelectorAll('#destGrid .provider-card').forEach(c => c.classList.remove('selected'));
      dc.classList.add('selected');
    }
    document.getElementById('destLocalPath').classList.toggle('show', destProvider === 'local' || destProvider === 'icloud');
    document.getElementById('destOtherName').classList.toggle('show', destProvider === 'other');
    if (destProvider === 'local' || destProvider === 'icloud') {
      document.getElementById('destNext').disabled = !document.getElementById('destPathInput').value.trim();
    } else if (destProvider === 'other') {
      document.getElementById('destNext').disabled = !document.getElementById('destOtherInput').value.trim();
    } else {
      document.getElementById('destNext').disabled = false;
    }
  }
  if (step === 4 && selectedSpeed) {
    document.querySelectorAll('.speed-card').forEach(c => {
      c.classList.remove('selected');
      c.setAttribute('aria-checked', 'false');
    });
    document.querySelectorAll('.speed-card').forEach(c => {
      const radio = c.querySelector('input[type="radio"]');
      if (radio && radio.value === selectedSpeed) {
        c.classList.add('selected');
        c.setAttribute('aria-checked', 'true');
        radio.checked = true;
      }
    });
  }

  currentStep = step;
  // Save wizard state to survive page refresh
  try {
    sessionStorage.setItem('cloudhop_wizard', JSON.stringify({
      step: currentStep, sourceProvider, sourceName, sourceDisplayName,
      destProvider, destName, destDisplayName, selectedSpeed
    }));
  } catch(e) {}
}

function toggleAdvanced() {
    const content = document.getElementById('advancedContent');
    const arrow = document.getElementById('advArrow');
    content.classList.toggle('open');
    arrow.classList.toggle('open');
}

// Schedule toggle
(function() {
  document.addEventListener('DOMContentLoaded', function() {
    const schedEl = document.getElementById('scheduleEnabled');
    if (schedEl) {
      schedEl.addEventListener('change', function() {
        document.getElementById('scheduleConfig').style.display = this.checked ? 'block' : 'none';
      });
    }
  });
})();

// Restore wizard state after refresh
(function() {
  try {
    const saved = sessionStorage.getItem('cloudhop_wizard');
    if (!saved) return;
    const s = JSON.parse(saved);
    if (!s.sourceProvider) return;
    sourceProvider = s.sourceProvider;
    sourceName = s.sourceName || '';
    sourceDisplayName = s.sourceDisplayName || '';
    destProvider = s.destProvider;
    destName = s.destName || '';
    destDisplayName = s.destDisplayName || '';
    selectedSpeed = s.selectedSpeed || '8';
    // Re-select cards visually
    if (sourceProvider) {
      const sc = document.querySelector('#sourceGrid [data-provider="'+sourceProvider+'"]');
      if (sc) sc.classList.add('selected');
    }
    if (destProvider) {
      const dc = document.querySelector('#destGrid [data-provider="'+destProvider+'"]');
      if (dc) dc.classList.add('selected');
    }
    if (s.step > 1) goTo(s.step);
  } catch(e) {}
})();

// Source selection
function selectSource(card) {
  document.querySelectorAll('#sourceGrid .provider-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  sourceProvider = card.dataset.provider;
  sourceDisplayName = card.dataset.name;
  sourceName = providerKeys[sourceProvider] || sourceProvider;

  document.getElementById('sourceLocalPath').classList.toggle('show', sourceProvider === 'local' || sourceProvider === 'icloud');
  document.getElementById('sourceOtherName').classList.toggle('show', sourceProvider === 'other');
  if (sourceProvider === 'icloud') {
    // Auto-fill with macOS iCloud Drive path
    const pathInput = document.getElementById('sourcePathInput');
    if (pathInput) pathInput.value = (window._homeDir || '') + '/Library/Mobile Documents/com~apple~CloudDocs';
  }
  // For Other provider, only enable Next when name is entered
  if (sourceProvider === 'other') {
    const input = document.getElementById('sourceOtherInput');
    document.getElementById('sourceNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        sourceName = input.value.trim();
        document.getElementById('sourceNext').disabled = !input.value.trim();
      });
    }
  } else if (sourceProvider === 'local' || sourceProvider === 'icloud') {
    const input = document.getElementById('sourcePathInput');
    document.getElementById('sourceNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        document.getElementById('sourceNext').disabled = !input.value.trim();
      });
    }
  } else {
    document.getElementById('sourceNext').disabled = false;
  }
}

// Dest selection
function selectDest(card) {
  if (card.classList.contains('disabled')) return;
  document.querySelectorAll('#destGrid .provider-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  destProvider = card.dataset.provider;
  destDisplayName = card.dataset.name;
  destName = providerKeys[destProvider] || destProvider;
  if (destProvider === sourceProvider && sourceProvider !== 'local') {
    destName = sourceName + '_dest';
  }

  document.getElementById('destLocalPath').classList.toggle('show', destProvider === 'local' || destProvider === 'icloud');
  document.getElementById('destOtherName').classList.toggle('show', destProvider === 'other');
  if (destProvider === 'icloud') {
    // Auto-fill with macOS iCloud Drive path
    const pathInput = document.getElementById('destPathInput');
    if (pathInput) pathInput.value = (window._homeDir || '') + '/Library/Mobile Documents/com~apple~CloudDocs';
  }
  // For Other provider, only enable Next when name is entered
  if (destProvider === 'other') {
    const input = document.getElementById('destOtherInput');
    document.getElementById('destNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        destName = input.value.trim();
        document.getElementById('destNext').disabled = !input.value.trim();
      });
    }
  } else if (destProvider === 'local' || destProvider === 'icloud') {
    const input = document.getElementById('destPathInput');
    document.getElementById('destNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        document.getElementById('destNext').disabled = !input.value.trim();
      });
    }
  } else {
    document.getElementById('destNext').disabled = false;
  }
}

function updateDestGrid() {
  document.querySelectorAll('#destGrid .provider-card').forEach(c => {
    c.classList.remove('disabled');
    const note = c.querySelector('.same-provider-note');
    if (note) note.remove();
    if (c.dataset.provider === sourceProvider && sourceProvider !== 'local' && sourceProvider !== 'other') {
      const span = document.createElement('div');
      span.className = 'same-provider-note';
      span.style.cssText = 'font-size:0.75rem;color:var(--text-dim);margin-top:4px;';
      span.textContent = '(will configure as separate account)';
      c.appendChild(span);
    }
  });
}

function selectSpeed(card, val) {
  document.querySelectorAll('.speed-card').forEach(c => { c.classList.remove('selected'); c.setAttribute('aria-checked', 'false'); });
  card.classList.add('selected');
  card.setAttribute('aria-checked', 'true');
  selectedSpeed = val;
}

// Build connect step
async function buildConnectStep() {
  const list = document.getElementById('connectList');
  list.innerHTML = '';

  // Set hint based on provider types
  const oauthProviders = ['drive','onedrive','dropbox'];
  const hasOAuth = oauthProviders.includes(sourceProvider) || oauthProviders.includes(destProvider);
  const credProviders = ['mega','protondrive','s3'];
  const hasCred = credProviders.includes(sourceProvider) || credProviders.includes(destProvider);
  const hint = document.getElementById('connectHint');
  if (hasOAuth && hasCred) {
    hint.innerHTML = 'Some services will open a browser window for sign-in. Others will ask for your username and password below.';
  } else if (hasOAuth) {
    hint.innerHTML = 'A browser window will open. Sign in to your account there, then come back to this page. CloudHop will detect the connection automatically.';
  } else if (hasCred) {
    hint.innerHTML = 'Enter your credentials below to connect your accounts.';
  } else {
    hint.innerHTML = '';
  }

  // Check rclone first
  const statusEl = document.getElementById('rcloneStatus');
  statusEl.innerHTML = '<div class="spinner"></div> Setting up...';
  try {
    const resp = await fetch('/api/wizard/status');
    const data = await resp.json();
    existingRemotes = data.remotes || [];
    if (data.home_dir) window._homeDir = data.home_dir;
    if (!data.rclone_installed) {
      statusEl.innerHTML = '<span style="color:var(--orange)">Installing required components...</span>';
      const installResp = await fetch('/api/wizard/check-rclone', {method:'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}});
      const installData = await installResp.json();
      if (!installData.ok) {
        statusEl.innerHTML = '<span style="color:var(--red)">Setup failed. Please visit rclone.org/install for manual setup.</span>';
        return;
      }
      statusEl.innerHTML = '<span style="color:var(--green)">Setup complete!</span>';
    } else {
      statusEl.innerHTML = '';
    }
  } catch(e) {
    statusEl.innerHTML = '';
  }

  const items = [];
  if (sourceProvider && sourceProvider !== 'local' && sourceProvider !== 'icloud' && sourceProvider !== 'other') {
    items.push({provider: sourceProvider, name: sourceName, display: sourceDisplayName, role: 'source'});
  }
  if (destProvider && destProvider !== 'local' && destProvider !== 'icloud' && destProvider !== 'other') {
    items.push({provider: destProvider, name: destName, display: destDisplayName, role: 'dest'});
  }

  if (items.length === 0) {
    list.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-dim);">No cloud accounts need to be connected. You\'re all set!</div>';
    document.getElementById('connectNext').disabled = false;
    return;
  }

  for (const item of items) {
    const connected = existingRemotes.includes(item.name);
    const div = document.createElement('div');
    div.className = 'connect-item';
    div.id = 'connect-' + item.name;
    div.innerHTML = `
      <div class="connect-info">
        <div class="connect-icon">${providerIcons[item.provider]}</div>
        <div>
          <div class="connect-name">${item.display}</div>
          <div class="connect-status ${connected ? 'ok' : 'pending'}" id="status-${item.name}">
            ${connected ? 'Connected' : 'Not connected'}
          </div>
        </div>
      </div>
      <div id="action-${item.name}">
        ${connected
          ? '<div class="checkmark">✓</div>'
          : `<button class="btn btn-primary btn-connect" onclick="connectRemote('${item.name.replace(/'/g, "\\'")}','${item.provider.replace(/'/g, "\\'")}','${item.display.replace(/'/g, "\\'")}')">Connect ${esc(item.display)}</button>`
        }
      </div>
    `;
    list.appendChild(div);
  }
  checkAllConnected();
}

async function connectRemote(name, type, display, username, password) {
  const safeName = name.replace(/'/g, "\\'");
  const safeType = type.replace(/'/g, "\\'");
  const safeDisplay = display.replace(/'/g, "\\'");
  const actionEl = document.getElementById('action-' + name);
  const statusEl = document.getElementById('status-' + name);
  actionEl.innerHTML = '<div class="spinner"></div>';
  statusEl.textContent = 'Connecting...';
  statusEl.className = 'connect-status pending';

  // Start polling as fallback for OAuth providers (may timeout but still succeed)
  if (['drive','onedrive','dropbox'].includes(type)) {
    startPolling(name, display, type);
  }

  try {
    const body = {name, type};
    if (username) body.username = username;
    if (password) body.password = password;
    const resp = await fetch('/api/wizard/configure-remote', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (data.ok) {
      statusEl.textContent = 'Connected';
      statusEl.className = 'connect-status ok';
      actionEl.innerHTML = '<div class="checkmark">✓</div>';
      if (!existingRemotes.includes(name)) existingRemotes.push(name);
    } else if (data.needs_credentials) {
      statusEl.textContent = data.msg || 'Credentials required';
      statusEl.className = 'connect-status pending';
      const userLabel = data.user_label || 'Username';
      const passLabel = data.pass_label || 'Password';
      actionEl.innerHTML = `
        <div style="display:flex;flex-direction:column;gap:8px;min-width:220px;">
          <input class="form-input" id="cred-user-${safeName}" type="text" placeholder="${userLabel}" style="padding:8px 12px;font-size:0.8rem;">
          <input class="form-input" id="cred-pass-${safeName}" type="password" placeholder="${passLabel}" style="padding:8px 12px;font-size:0.8rem;">
          <button class="btn btn-primary btn-connect" onclick="connectRemote('${safeName}','${safeType}','${safeDisplay}', document.getElementById('cred-user-${safeName}').value, document.getElementById('cred-pass-${safeName}').value)">Connect</button>
        </div>`;
    } else {
      statusEl.textContent = data.msg || 'Failed to connect';
      statusEl.className = 'connect-status pending';
      actionEl.innerHTML = `<button class="btn btn-primary btn-connect" onclick="connectRemote('${safeName}','${safeType}','${safeDisplay}')">Retry</button>`;
    }
  } catch(e) {
    if (['drive','onedrive','dropbox'].includes(type)) {
      statusEl.textContent = 'Waiting for authorization...';
      statusEl.className = 'connect-status pending';
    } else {
      statusEl.textContent = 'Failed to connect';
      statusEl.className = 'connect-status pending';
      actionEl.innerHTML = `<button class="btn btn-primary btn-connect" onclick="connectRemote('${safeName}','${safeType}','${safeDisplay}')">Retry</button>`;
    }
  }
  checkAllConnected();
}

function checkAllConnected() {
  const items = document.querySelectorAll('.connect-item');
  let allOk = true;
  items.forEach(item => {
    const status = item.querySelector('.connect-status');
    if (!status.classList.contains('ok')) allOk = false;
  });
  document.getElementById('connectNext').disabled = !allOk;
}

// Poll for remote connection (for OAuth flow) - per-remote polling
const activePolls = {};
function startPolling(name, display, type) {
  // Clear any existing poll for this remote
  if (activePolls[name]) { clearInterval(activePolls[name]); delete activePolls[name]; }
  const remoteName = name;
  const remoteType = type;
  activePolls[name] = setInterval(async () => {
    try {
      const resp = await fetch('/api/wizard/check-remote', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
        body: JSON.stringify({name})
      });
      const data = await resp.json();
      if (data.configured) {
        clearInterval(activePolls[name]);
        delete activePolls[name];
        const statusEl = document.getElementById('status-' + name);
        const actionEl = document.getElementById('action-' + name);
        if (statusEl) {
          statusEl.textContent = 'Connected';
          statusEl.className = 'connect-status ok';
        }
        if (actionEl) {
          actionEl.innerHTML = '<div class="checkmark">✓</div>';
        }
        if (!existingRemotes.includes(name)) existingRemotes.push(name);
        checkAllConnected();
      }
    } catch(e) {}
  }, 2000);
  // Timeout after 2 minutes
  setTimeout(() => {
    if (activePolls[name]) {
      clearInterval(activePolls[name]);
      delete activePolls[name];
      const statusEl = document.getElementById('status-' + remoteName);
      const actionEl = document.getElementById('action-' + remoteName);
      if (statusEl && !statusEl.classList.contains('ok')) {
        statusEl.innerHTML = '<span style="color:var(--orange);">Timed out.</span>';
        if (actionEl) {
          actionEl.innerHTML = '<button class="btn btn-primary btn-connect" onclick="connectRemote(\'' + remoteName.replace(/'/g, "\\'") + '\',\'' + remoteType.replace(/'/g, "\\'") + '\',\'' + display.replace(/'/g, "\\'") + '\')">Try again</button>';
        }
      }
    }
  }, 120000);
}

// Build summary
function buildSummary() {
  const card = document.getElementById('summaryCard');
  const srcSub = document.getElementById('sourceSubfolder').value.trim();
  const dstSub = document.getElementById('destSubfolder').value.trim();
  const excludes = document.getElementById('excludePatterns').value.trim();
  const bwLimit = document.getElementById('bwLimit').value.trim();
  const speedLabels = {'4': 'Normal (4 files)', '8': 'Fast (8 files)', '16': 'Maximum (16 files)'};
  const useChecksum = document.getElementById('useChecksum').checked;
  const useFastList = document.getElementById('useFastList').checked;

  let srcPath = getSourcePath();
  let dstPath = getDestPath();

  card.innerHTML = `
    <div class="summary-row">
      <span class="summary-label">Source</span>
      <span class="summary-value">${esc(sourceDisplayName)}${srcSub ? ' / ' + esc(srcSub) : ''}</span>
    </div>
    <div class="summary-row">
      <span class="summary-label">Destination</span>
      <span class="summary-value">${esc(destDisplayName)}${dstSub ? ' / ' + esc(dstSub) : ''}</span>
    </div>
    <div class="summary-row">
      <span class="summary-label">Speed</span>
      <span class="summary-value">${esc(speedLabels[selectedSpeed])}</span>
    </div>
    ${excludes ? `<div class="summary-row">
      <span class="summary-label">Excluding</span>
      <span class="summary-value">${esc(excludes)}</span>
    </div>` : ''}
    ${bwLimit ? `<div class="summary-row">
      <span class="summary-label">Bandwidth Limit</span>
      <span class="summary-value">${esc(bwLimit)}</span>
    </div>` : ''}
    ${useChecksum ? `<div class="summary-row"><span class="summary-label">Checksum verification</span><span class="summary-value">Enabled</span></div>` : ''}
    ${useFastList ? `<div class="summary-row"><span class="summary-label">Fast listing</span><span class="summary-value">Enabled</span></div>` : ''}
  `;

  // Add schedule info if enabled
  const schedEl = document.getElementById('scheduleEnabled');
  if (schedEl && schedEl.checked) {
    const start = document.getElementById('scheduleStart').value;
    const end = document.getElementById('scheduleEnd').value;
    const days = [];
    document.querySelectorAll('#scheduleConfig [data-day]').forEach(cb => {
      if (cb.checked) {
        days.push(['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][parseInt(cb.dataset.day)]);
      }
    });
    const bwInWindow = document.getElementById('bwLimitInWindow').value;
    let schedDesc = start + ' - ' + end + ' on ' + days.join(', ');
    if (bwInWindow) schedDesc += ' (limit: ' + bwInWindow.replace('M', ' MB/s') + ')';
    card.innerHTML += `
      <div class="summary-row">
        <span class="summary-label">Schedule</span>
        <span class="summary-value">${esc(schedDesc)}</span>
      </div>`;
  }
}

function showWizardError(msg) {
  const el = document.getElementById('wizardError');
  if (el) { el.textContent = msg; el.style.display = 'block'; setTimeout(() => { el.style.display = 'none'; }, 8000); }
}

function getSourcePath() {
  const srcSub = document.getElementById('sourceSubfolder').value.trim();
  if (sourceProvider === 'local' || sourceProvider === 'icloud') {
    const p = document.getElementById('sourcePathInput').value.trim();
    if (!p) { const errEl = document.getElementById('sourcePathError'); errEl.textContent = 'Please enter a folder path.'; errEl.style.display = 'block'; return null; }
    document.getElementById('sourcePathError').style.display = 'none';
    return srcSub ? p + '/' + srcSub : p;
  }
  if (sourceProvider === 'other') {
    const n = document.getElementById('sourceOtherInput').value.trim();
    return n + ':' + (srcSub || '');
  }
  return sourceName + ':' + (srcSub || '');
}

function getDestPath() {
  const dstSub = document.getElementById('destSubfolder').value.trim();
  if (destProvider === 'local' || destProvider === 'icloud') {
    const p = document.getElementById('destPathInput').value.trim();
    if (!p) { const errEl = document.getElementById('destPathError'); errEl.textContent = 'Please enter a folder path.'; errEl.style.display = 'block'; return null; }
    document.getElementById('destPathError').style.display = 'none';
    return dstSub ? p + '/' + dstSub : p;
  }
  if (destProvider === 'other') {
    const n = document.getElementById('destOtherInput').value.trim();
    return n + ':' + (dstSub || '');
  }
  return destName + ':' + (dstSub || '');
}

async function previewTransfer() {
  const btn = document.getElementById('previewBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  const result = document.getElementById('previewResult');
  try {
    const resp = await fetch('/api/wizard/preview', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify({source: getSourcePath(), dest: getDestPath(), source_type: sourceProvider, dest_type: destProvider})
    });
    const data = await resp.json();
    if (data.ok) {
      result.style.display = 'block';
      result.innerHTML = '<strong>' + esc(data.count.toLocaleString()) + ' files</strong> (' + esc(data.size) + ') will be copied.';
    } else {
      result.style.display = 'block';
      result.innerHTML = 'Could not preview: ' + esc(data.msg || 'unknown error');
    }
  } catch(e) {
    result.style.display = 'block';
    result.innerHTML = 'Preview failed. You can still start the transfer.';
  }
  btn.disabled = false;
  btn.textContent = 'Preview (see what will be copied)';
}

async function startTransfer() {
  const btn = document.getElementById('startBtn');
  if (btn.disabled) return;
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Starting transfer...';

  const safetyTimeout = setTimeout(() => {
    btn.disabled = false;
    btn.textContent = 'Start Transfer';
    showWizardError('Transfer may have started. Check the dashboard.');
  }, 30000);

  const excludes = document.getElementById('excludePatterns').value.trim();
  const excludeList = excludes ? excludes.split(',').map(e => e.trim()).filter(Boolean) : [];

  try {
    const src = getSourcePath();
    const dst = getDestPath();
    if (!src || !dst) {
      clearTimeout(safetyTimeout);
      btn.disabled = false;
      btn.textContent = 'Start Transfer';
      return;
    }
    const resp = await fetch('/api/wizard/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify({
        source: src,
        dest: dst,
        transfers: selectedSpeed,
        excludes: excludeList,
        source_type: sourceProvider === 'icloud' ? 'local' : sourceProvider,
        dest_type: destProvider === 'icloud' ? 'local' : destProvider,
        bw_limit: document.getElementById('bwLimit').value.trim(),
        checksum: document.getElementById('useChecksum').checked,
        fast_list: document.getElementById('useFastList').checked
      })
    });
    clearTimeout(safetyTimeout);
    const data = await resp.json();
    if (data.ok) {
      // Save schedule if enabled
      const schedEnabled = document.getElementById('scheduleEnabled');
      if (schedEnabled && schedEnabled.checked) {
        const days = [];
        document.querySelectorAll('#scheduleConfig [data-day]').forEach(cb => {
          if (cb.checked) days.push(parseInt(cb.dataset.day));
        });
        await fetch('/api/schedule', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
          body: JSON.stringify({
            enabled: true,
            start_time: document.getElementById('scheduleStart').value,
            end_time: document.getElementById('scheduleEnd').value,
            days: days,
            bw_limit_in_window: document.getElementById('bwLimitInWindow').value,
            bw_limit_out_window: '0',
          })
        });
      }
      // Redirect to dashboard
      window.location.href = '/dashboard';
    } else {
      btn.disabled = false;
      btn.textContent = 'Start Transfer';
      showWizardError('Error: ' + (data.msg || 'Failed to start transfer'));
    }
  } catch(e) {
    clearTimeout(safetyTimeout);
    btn.disabled = false;
    btn.textContent = 'Start Transfer';
    showWizardError('Error starting transfer. Please check the console.');
  }
}
