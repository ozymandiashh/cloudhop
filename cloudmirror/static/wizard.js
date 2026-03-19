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
  drive: 'gdrive', onedrive: 'onedrive', dropbox: 'dropbox', mega: 'mega', s3: 's3', protondrive: 'protondrive', local: 'local', other: null
};
const providerIcons = {
  drive: '<div style="font-size:1.5rem;font-weight:800;line-height:1;"><span style="color:#4285f4">G</span><span style="color:#ea4335">o</span><span style="color:#fbbc05">o</span><span style="color:#4285f4">g</span><span style="color:#34a853">l</span><span style="color:#ea4335">e</span></div>',
  onedrive: '<svg width="32" height="22" viewBox="0 0 48 32"><path d="M39.5 16C39.5 9.1 33.9 3.5 27 3.5c-5.1 0-9.5 3-11.5 7.4C14.8 10.3 14 10 13 10c-2.8 0-5 2.2-5 5 0 .3 0 .6.1.9C4.6 17 2 20.1 2 23.5 2 27.6 5.4 31 9.5 31h28c3.6 0 6.5-2.9 6.5-6.5S43.1 18 39.5 16z" fill="#0078d4"/></svg>',
  dropbox: '<svg width="28" height="28" viewBox="0 0 40 40"><path d="M12 2L2 8.5l10 6.5 10-6.5L12 2zm16 0L18 8.5l10 6.5 10-6.5L28 2zM2 21.5L12 28l10-6.5-10-6.5L2 21.5zm26-6.5l-10 6.5 10 6.5 10-6.5-10-6.5zM12 29.5l10 6.5 10-6.5-10-6.5-10 6.5z" fill="#0061fe"/></svg>',
  mega: '<svg width="28" height="28" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="16" font-weight="800" fill="#d9272e">MEGA</text></svg>',
  s3: '<svg width="28" height="28" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="24" font-weight="800" fill="#ff9900">S3</text></svg>',
  protondrive: '<svg width="28" height="28" viewBox="0 0 40 40"><path d="M20 3L6 10v10c0 9.5 5.9 18.4 14 20 8.1-1.6 14-10.5 14-20V10L20 3z" fill="#6d4aff"/></svg>',
  local: '<svg width="28" height="28" viewBox="0 0 24 24"><path d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z" fill="var(--text-dim)"/></svg>',
  other: '<svg width="28" height="28" viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1112 8.4a3.6 3.6 0 010 7.2z" fill="var(--text-dim)"/></svg>'
};

// Theme
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  html.setAttribute('data-theme', next);
  document.querySelector('.theme-toggle').textContent = next === 'light' ? '\u2600' : '\u263E';
  localStorage.setItem('cloudmirror-theme', next);
}
(function() {
  const saved = localStorage.getItem('cloudmirror-theme');
  if (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('.theme-toggle').textContent = '\u2600';
  }
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('.theme-toggle').textContent = '\u2600';
  }
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem('cloudmirror-theme')) {
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
      el.innerHTML = '<span style="color:var(--orange)">rclone is not installed. It will be installed automatically when you proceed.</span>';
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
    box.innerHTML = '<div style="font-size:0.95rem;color:var(--text);margin-bottom:20px;line-height:1.6;">' + message.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</div>'
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
    if (sourceProvider === destProvider && sourceProvider !== 'local') {
      const proceed = await showConfirmModal('Source and destination are the same service. Two separate accounts will be set up (e.g. &ldquo;gdrive&rdquo; for source and &ldquo;gdrive_dest&rdquo; for destination). Continue?');
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
  currentStep = step;
  // Save wizard state to survive page refresh
  try {
    sessionStorage.setItem('cm_wizard', JSON.stringify({
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

// Restore wizard state after refresh
(function() {
  try {
    const saved = sessionStorage.getItem('cm_wizard');
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

  document.getElementById('sourceLocalPath').classList.toggle('show', sourceProvider === 'local');
  document.getElementById('sourceOtherName').classList.toggle('show', sourceProvider === 'other');
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
  } else if (sourceProvider === 'local') {
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

  document.getElementById('destLocalPath').classList.toggle('show', destProvider === 'local');
  document.getElementById('destOtherName').classList.toggle('show', destProvider === 'other');
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
  } else if (destProvider === 'local') {
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
    hint.innerHTML = 'Some services will open a browser for sign-in. Others will ask for credentials below.';
  } else if (hasOAuth) {
    hint.innerHTML = 'A browser tab will open for authentication. Sign in to authorize CloudMirror, then return here.';
  } else if (hasCred) {
    hint.innerHTML = 'Enter your credentials below to connect your accounts.';
  } else {
    hint.innerHTML = '';
  }

  // Check rclone first
  const statusEl = document.getElementById('rcloneStatus');
  statusEl.innerHTML = '<div class="spinner"></div> Checking rclone...';
  try {
    const resp = await fetch('/api/wizard/status');
    const data = await resp.json();
    existingRemotes = data.remotes || [];
    if (data.home_dir) window._homeDir = data.home_dir;
    if (!data.rclone_installed) {
      statusEl.innerHTML = '<span style="color:var(--orange)">rclone not found. Installing...</span>';
      const installResp = await fetch('/api/wizard/check-rclone', {method:'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}});
      const installData = await installResp.json();
      if (!installData.ok) {
        statusEl.innerHTML = '<span style="color:var(--red)">Could not install rclone. Please install manually from rclone.org</span>';
        return;
      }
      statusEl.innerHTML = '<span style="color:var(--green)">rclone installed!</span>';
    } else {
      statusEl.innerHTML = '';
    }
  } catch(e) {
    statusEl.innerHTML = '';
  }

  const items = [];
  if (sourceProvider && sourceProvider !== 'local' && sourceProvider !== 'other') {
    items.push({provider: sourceProvider, name: sourceName, display: sourceDisplayName, role: 'source'});
  }
  if (destProvider && destProvider !== 'local' && destProvider !== 'other') {
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
          : `<button class="btn btn-primary btn-connect" onclick="connectRemote('${item.name}','${item.provider}','${item.display}')">Connect ${item.display}</button>`
        }
      </div>
    `;
    list.appendChild(div);
  }
  checkAllConnected();
}

async function connectRemote(name, type, display, username, password) {
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
          <input class="form-input" id="cred-user-${name}" type="text" placeholder="${userLabel}" style="padding:8px 12px;font-size:0.8rem;">
          <input class="form-input" id="cred-pass-${name}" type="password" placeholder="${passLabel}" style="padding:8px 12px;font-size:0.8rem;">
          <button class="btn btn-primary btn-connect" onclick="connectRemote('${name}','${type}','${display}', document.getElementById('cred-user-${name}').value, document.getElementById('cred-pass-${name}').value)">Connect</button>
        </div>`;
    } else {
      statusEl.textContent = data.msg || 'Failed to connect';
      statusEl.className = 'connect-status pending';
      actionEl.innerHTML = `<button class="btn btn-primary btn-connect" onclick="connectRemote('${name}','${type}','${display}')">Retry</button>`;
    }
  } catch(e) {
    if (['drive','onedrive','dropbox'].includes(type)) {
      statusEl.textContent = 'Waiting for authorization...';
      statusEl.className = 'connect-status pending';
    } else {
      statusEl.textContent = 'Failed to connect';
      statusEl.className = 'connect-status pending';
      actionEl.innerHTML = `<button class="btn btn-primary btn-connect" onclick="connectRemote('${name}','${type}','${display}')">Retry</button>`;
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

// Poll for remote connection (for OAuth flow)
let pollInterval = null;
function startPolling(name, display, type) {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch('/api/wizard/check-remote', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
        body: JSON.stringify({name})
      });
      const data = await resp.json();
      if (data.configured) {
        clearInterval(pollInterval);
        pollInterval = null;
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
  `;
}

function showWizardError(msg) {
  const el = document.getElementById('wizardError');
  if (el) { el.textContent = msg; el.style.display = 'block'; setTimeout(() => { el.style.display = 'none'; }, 8000); }
}

function getSourcePath() {
  const srcSub = document.getElementById('sourceSubfolder').value.trim();
  if (sourceProvider === 'local') {
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
  if (destProvider === 'local') {
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
        source_type: sourceProvider,
        dest_type: destProvider,
        bw_limit: document.getElementById('bwLimit').value.trim(),
        checksum: document.getElementById('useChecksum').checked
      })
    });
    clearTimeout(safetyTimeout);
    const data = await resp.json();
    if (data.ok) {
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
