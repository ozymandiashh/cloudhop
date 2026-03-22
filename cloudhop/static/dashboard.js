/*
 * dashboard.js - CloudHop transfer monitoring dashboard
 *
 * Auto-refresh
 *   refresh() is called immediately on load, then every 5 s via setInterval
 *   (stored in `refreshInterval`).  When the transfer completes, the interval
 *   slows to 30 s.  On fetch failure 3+ times in a row, a "connection lost"
 *   banner is shown.
 *
 * Chart rendering
 *   drawAreaChart(svgId, data, ...) renders an SVG area chart directly by
 *   building an HTML string and assigning it to svg.innerHTML.  null values
 *   in the data array represent session gaps (rclone restarts); the chart
 *   connects across them with a continuous line.  A simple cache key
 *   (svgId + dimensions + last 5 data points) skips redundant redraws.
 *
 * Theme toggle
 *   toggleTheme() switches the data-theme attribute on <html> between "dark"
 *   and "light".  CSS transitions are disabled for two animation frames during
 *   the switch so cards and the header don't flash grey before the new
 *   background colour is applied.
 *
 * Completion overlay
 *   showCompletionScreen(d) renders a full-screen overlay with transfer stats.
 *   `completionShown` (boolean) ensures it appears exactly once per page load,
 *   even if refresh() is called multiple times after the transfer finishes.
 */
// Global error handler - show friendly message instead of silent failure
window.onerror = function(msg, src, line) {
  const el = document.getElementById('toast');
  if (el) {
    el.textContent = 'Something went wrong. The dashboard will keep trying.';
    el.style.borderColor = 'var(--orange)';
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 5000);
  }
  console.error('CloudHop error:', msg, 'at', src, 'line', line);
  return true; // prevent default browser error
};

function getCsrfToken(){return document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith('csrf_token='))?.substring('csrf_token='.length)||''}
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
function isSafeUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:';
  } catch { return false; }
}

let completionShown = false;
let failCount = 0;
let speedHistory = [];
let progressHistory = [];
let filesLocalHistory = []; // Built from global_files_done each refresh (backend files_history is cumulative-buggy)
try { const _saved = sessionStorage.getItem('cloudhop_chartHistory'); if (_saved) filesLocalHistory = JSON.parse(_saved); } catch(e) {}

// Styled confirm modal (replaces native confirm())
function showConfirmModal(message) {
  return new Promise((resolve) => {
    if (document.getElementById('_cm_overlay')) return resolve(false);
    const overlay = document.createElement('div');
    overlay.id = '_cm_overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:9999;';
    overlay.innerHTML = `<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:28px 32px;max-width:420px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.3);"><p style="margin:0 0 20px;font-size:0.95rem;color:var(--text-primary);">${esc(message)}</p><div style="display:flex;gap:10px;justify-content:flex-end;"><button id="_cm_cancel" style="padding:8px 18px;border-radius:8px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-primary);cursor:pointer;">Cancel</button><button id="_cm_ok" style="padding:8px 18px;border-radius:8px;border:none;background:var(--primary);color:#fff;cursor:pointer;font-weight:600;">OK</button></div></div>`;
    document.body.appendChild(overlay);
    function cleanup() { overlay.remove(); document.removeEventListener('keydown', escHandler); }
    function escHandler(e) { if (e.key === 'Escape') { cleanup(); resolve(false); } }
    document.addEventListener('keydown', escHandler);
    overlay.querySelector('#_cm_ok').onclick = () => { cleanup(); resolve(true); };
    overlay.querySelector('#_cm_cancel').onclick = () => { cleanup(); resolve(false); };
    overlay.addEventListener('click', (e) => { if (e.target === overlay) { cleanup(); resolve(false); } });
    overlay.querySelector('#_cm_ok').focus();
  });
}
let _refreshInterval = null;
let _refreshRate = 0;

function ensurePolling(rate) {
  if (_refreshInterval && _refreshRate === rate) return;
  stopPolling();
  _refreshInterval = setInterval(refresh, rate);
  _refreshRate = rate;
}

function stopPolling() {
  if (_refreshInterval) {
    clearInterval(_refreshInterval);
    _refreshInterval = null;
    _refreshRate = 0;
  }
}

let peakSpeedVal = 0;
let peakSpeedTime = '';
try { const _ps = sessionStorage.getItem('cloudhop_peakSpeed'); if (_ps) { const _pd = JSON.parse(_ps); peakSpeedVal = _pd.val || 0; peakSpeedTime = _pd.time || ''; } } catch(e) {}
let lastEtaUpdate = 0;
let lastEtaValue = 0;
let peakProgressPct = 0;

function parseSpeed(str) {
  if (!str) return 0;
  // Handle plain "B/s" (no K/M/G/T prefix)
  const mPlain = str.match(/([\d.]+)\s*B\/s/i);
  if (mPlain && !/[KMGT]i?B\/s/i.test(str)) {
    return parseFloat(mPlain[1]) / (1024 * 1024); // convert B to MiB
  }
  const m = str.match(/([\d.]+)\s*([KMGT]i?B)\/s/i);
  if (!m) return 0;
  let val = parseFloat(m[1]);
  const u = m[2].toUpperCase();
  if (u.startsWith('K')) val /= 1024;
  else if (u.startsWith('G')) val *= 1024;
  else if (u.startsWith('T')) val *= 1024 * 1024;
  return val;
}

function fmtSpeed(mbs) {
  if (mbs === 0) return '--';
  if (mbs < 1) return (mbs * 1024).toFixed(0) + ' KiB/s';
  if (mbs >= 1024) return (mbs / 1024).toFixed(2) + ' GiB/s';
  return mbs.toFixed(2) + ' MiB/s';
}
// Short versions for chart axis labels
function fmtSpeedShort(v) {
  if (v === 0) return '0';
  if (v < 1) return (v * 1024).toFixed(0) + ' KB/s';
  if (v >= 1024) return (v / 1024).toFixed(1) + ' GB/s';
  return v.toFixed(1) + ' MB/s';
}
function fmtFilesShort(v) {
  if (v >= 1000000) return (v / 1000000).toFixed(1) + 'M';
  if (v >= 1000) return (v / 1000).toFixed(0) + 'K';
  return Math.round(v).toString();
}

function fmtEta(eta) {
  if (!eta || eta === '--') return '--';
  return eta.replace(/(\d+)d/, '$1d ').replace(/(\d+)h/, '$1h ').replace(/(\d+)m/, '$1m');
}

function fmtDuration(sec) {
  if (!sec || sec <= 0) return 'none';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  let r = '';
  if (d) r += d + 'd ';
  if (h) r += h + 'h ';
  if (m) r += m + 'm ';
  if (!r && s) r += s + 's';
  return r.trim() || 'none';
}

function drawAreaChart(svgId, data, color, gradId, formatY, minZero, maxCap) {
  const svg = document.getElementById(svgId);
  if (!svg) return;
  const cs = getComputedStyle(document.documentElement);
  const cGrid = cs.getPropertyValue('--chart-grid').trim() || '#151d35';
  const cText = cs.getPropertyValue('--chart-text').trim() || '#2a3555';
  const w = svg.clientWidth || 500;
  const h = svg.clientHeight || 140;
  // Skip redraw if data and dimensions unchanged
  const dataKey = svgId + w + 'x' + h + JSON.stringify(data.slice(-5));
  if (drawAreaChart._cache && drawAreaChart._cache[svgId] === dataKey) return;
  if (!drawAreaChart._cache) drawAreaChart._cache = {};
  drawAreaChart._cache[svgId] = dataKey;
  const realData = data.filter(v => v !== null);
  if (realData.length < 2) {
    const emptyColor = cs.getPropertyValue('--text-secondary').trim() || '#6b7280';
    svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="${emptyColor}" font-size="12" font-family="DM Sans, sans-serif">Collecting data...</text>`;
    return;
  }
  const pad = { t: 12, b: 20, l: 62, r: 12 };
  const cw = w - pad.l - pad.r;
  const ch = h - pad.t - pad.b;

  const dataMax = Math.max(...realData);
  const dataMin = minZero ? 0 : Math.min(...realData);
  let rangeMax = dataMax + (dataMax - dataMin) * 0.1;
  if (maxCap !== undefined) rangeMax = Math.min(rangeMax, maxCap);
  let rangeMin = minZero ? 0 : Math.max(0, dataMin - (dataMax - dataMin) * 0.1);
  if (rangeMax === rangeMin) { rangeMax = rangeMin + 1; }

  function niceNum(range, round) {
    const exp = Math.floor(Math.log10(range));
    const frac = range / Math.pow(10, exp);
    let nice;
    if (round) {
      if (frac < 1.5) nice = 1;
      else if (frac < 3) nice = 2;
      else if (frac < 7) nice = 5;
      else nice = 10;
    } else {
      if (frac <= 1) nice = 1;
      else if (frac <= 2) nice = 2;
      else if (frac <= 5) nice = 5;
      else nice = 10;
    }
    return nice * Math.pow(10, exp);
  }

  const range = rangeMax - rangeMin;
  if (range <= 0) { rangeMax = rangeMin + 1; }
  const tickSpacing = niceNum(Math.max(range, 0.001) / 4, true);
  const niceMin = Math.floor(rangeMin / tickSpacing) * tickSpacing;
  const niceMax = Math.ceil(rangeMax / tickSpacing) * tickSpacing;

  let html = `<defs><linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="${color}" stop-opacity="0.35"/>
    <stop offset="60%" stop-color="${color}" stop-opacity="0.12"/>
    <stop offset="100%" stop-color="${color}" stop-opacity="0.02"/>
  </linearGradient></defs>`;

  for (let tick = niceMin; tick <= niceMax; tick += tickSpacing) {
    const y = pad.t + ch - ((tick - niceMin) / (niceMax - niceMin)) * ch;
    html += `<line x1="${pad.l}" y1="${y}" x2="${w - pad.r}" y2="${y}" stroke="${cGrid}" stroke-width="1"/>`;
    html += `<text x="${pad.l - 6}" y="${y + 3}" text-anchor="end" fill="${cText}" font-size="9" font-family="JetBrains Mono, monospace">${formatY ? formatY(tick) : tick.toFixed(1)}</text>`;
  }

  const maxVal = niceMax;
  const minVal = niceMin;

  if (data.length <= 1) {
    svg.innerHTML = html;
    return;
  }

  let segments = [];
  let current = [];
  data.forEach((v, i) => {
    if (v === null) {
      if (current.length > 0) { segments.push(current); current = []; }
    } else {
      current.push({ v, i });
    }
  });
  if (current.length > 0) segments.push(current);

  // Merge all segments into one continuous line, connecting gaps smoothly.
  // This avoids ugly vertical bars at segment boundaries in the area fill.
  const allPts = [];
  segments.forEach(seg => {
    seg.forEach(p => {
      const x = pad.l + (p.i / (data.length - 1)) * cw;
      const y = pad.t + ch - ((p.v - minVal) / (maxVal - minVal)) * ch;
      allPts.push({ x, y, i: p.i });
    });
  });

  if (allPts.length >= 2) {
    const ptStr = allPts.map(p => `${p.x},${p.y}`);
    const areaStr = [...ptStr, `${allPts[allPts.length-1].x},${pad.t+ch}`, `${allPts[0].x},${pad.t+ch}`];
    html += `<polygon points="${areaStr.join(' ')}" fill="url(#${gradId})"/>`;
    html += `<polyline points="${ptStr.join(' ')}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
  }

  const lastSeg = segments[segments.length - 1];
  if (lastSeg && lastSeg.length > 0) {
    const last = lastSeg[lastSeg.length - 1];
    const lx = pad.l + (last.i / (data.length - 1)) * cw;
    const ly = pad.t + ch - ((last.v - minVal) / (maxVal - minVal)) * ch;
    html += `<circle cx="${lx}" cy="${ly}" r="3.5" fill="${color}" stroke="${cs.getPropertyValue('--bg-card').trim()}" stroke-width="2"/>`;
    html += `<text x="${w-pad.r}" y="${h-3}" text-anchor="end" fill="${cText}" font-size="9" font-family="JetBrains Mono, monospace">${formatY ? formatY(last.v) : last.v.toFixed(2)}</text>`;
  }

  svg.innerHTML = html;
}

const typeColors = {
  pdf:'#ef4444',mp4:'#3b82f6',key:'#f59e0b',docx:'#22c55e',xlsx:'#a78bfa',
  png:'#f472b6',jpg:'#fb923c',zip:'#22d3ee',oas:'#818cf8',pptx:'#34d399',
  mov:'#60a5fa',avi:'#c084fc',doc:'#4ade80',txt:'#fbbf24',other:'#475569'
};
function getTypeColor(ext) { return typeColors[ext] || typeColors.other; }
function getExtension(fn) { const p=fn.split('.'); return p.length>1?p[p.length-1].toLowerCase():'other'; }

function friendlyError(msg) {
    const map = [
        [/403.*rate/i, 'Google Drive rate limit reached. Transfer will resume automatically.'],
        [/429/i, 'Too many requests. Slowing down automatically.'],
        [/quota/i, 'Storage quota exceeded. Free up space on the destination.'],
        [/token.*expired/i, 'Authentication expired. Please reconnect your account.'],
        [/no such host/i, 'Network error. Check your internet connection.'],
        [/permission denied/i, 'Permission denied. Check your account access.'],
        [/not found/i, 'File or folder not found. It may have been moved or deleted.'],
    ];
    for (const [pattern, friendly] of map) {
        if (pattern.test(msg)) return friendly;
    }
    return 'An unexpected error occurred. The transfer will retry automatically.';
}

// Update header status dot appearance
function updateStatusDot(state) {
  const dot = document.getElementById('statusDot');
  if (!dot) return;
  dot.className = 'status-dot';
  dot.style.animation = '';
  dot.style.background = '';
  dot.style.boxShadow = '';
  if (state === 'active') {
    dot.classList.add('active');
    dot.style.background = '#22c55e';
    dot.style.boxShadow = '0 0 8px rgba(34,197,94,0.5)';
  } else if (state === 'paused') {
    dot.classList.add('paused');
  } else if (state === 'error' || state === 'stopped') {
    dot.classList.add('error');
  } else if (state === 'complete') {
    dot.classList.add('complete');
  } else {
    dot.style.background = 'var(--text-tertiary)';
    dot.style.boxShadow = 'none';
  }
}

function $(id) { return document.getElementById(id); }
function setText(id, val) { const el = $(id); if (el) el.textContent = val; }
function setDisplay(id, val) { const el = $(id); if (el) el.style.display = val; }
function setWidth(id, val) { const el = $(id); if (el) el.style.width = val; }

function playCompleteSound() {
  if (_soundMuted) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const notes = [523.25, 659.25, 783.99]; // C5, E5, G5 - pleasant chord
    notes.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.frequency.value = freq;
      osc.type = "sine";
      gain.gain.setValueAtTime(0.1, ctx.currentTime + i * 0.15);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.15 + 0.5);
      osc.start(ctx.currentTime + i * 0.15);
      osc.stop(ctx.currentTime + i * 0.15 + 0.5);
    });
  } catch(e) {}
}

function showCompletionScreen(d) {
    playCompleteSound();
    const overlay = document.createElement('div');
    overlay.id = 'completionOverlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9998;backdrop-filter:blur(8px);';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    const totalFiles = d.global_files_done ? d.global_files_done.toLocaleString() : '0';
    const totalSize = d.global_transferred || '--';
    const totalTime = d.global_elapsed || '--';
    overlay.innerHTML = `
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:20px;padding:48px 40px;max-width:520px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.5);max-height:90vh;overflow-y:auto;">
            <div style="margin-bottom:16px;display:flex;justify-content:center;">
                <svg width="72" height="60" viewBox="0 0 72 60" fill="none" style="animation:cloudFloat 2.5s ease-in-out infinite;">
                    <style>@keyframes cloudFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}</style>
                    <defs><linearGradient id="completionCloudGrad" x1="0" y1="0" x2="72" y2="46"><stop offset="0%" stop-color="#e2e8f0"/><stop offset="100%" stop-color="#94a3b8"/></linearGradient></defs>
                    <path d="M18 46 Q6 46 4 36 Q0 28 8 22 Q4 14 12 10 Q18 2 28 6 Q34 -2 42 4 Q48 -2 56 4 Q64 2 66 12 Q72 18 70 26 Q74 34 68 40 Q64 46 54 46 Z" fill="url(#completionCloudGrad)" stroke="rgba(99,102,241,0.3)" stroke-width="1"/>
                    <circle cx="26" cy="28" r="2.5" fill="#1e293b"/><circle cx="46" cy="28" r="2.5" fill="#1e293b"/>
                    <path d="M30 35 Q36 40 42 35" stroke="#1e293b" stroke-width="2" stroke-linecap="round" fill="none"/>
                    <path d="M28 18 L34 24 L44 12" stroke="var(--green,#22c55e)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none" opacity="0.9"/>
                </svg>
            </div>
            <h2 style="font-size:1.5rem;font-weight:700;color:var(--text-primary);margin-bottom:8px;">Transfer Complete!</h2>
            <p style="color:var(--text-secondary);margin-bottom:24px;">All your files have been copied successfully.</p>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:28px;">
                <div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;font-weight:700;color:var(--text-primary);">${esc(totalSize)}</div>
                    <div style="font-size:0.75rem;color:var(--text-tertiary);margin-top:4px;">Transferred</div>
                </div>
                <div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;font-weight:700;color:var(--text-primary);">${totalFiles}</div>
                    <div style="font-size:0.75rem;color:var(--text-tertiary);margin-top:4px;">Files</div>
                </div>
                <div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;font-weight:700;color:var(--text-primary);">${esc(totalTime)}</div>
                    <div style="font-size:0.75rem;color:var(--text-tertiary);margin-top:4px;">Duration</div>
                </div>
            </div>
            <div style="background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.15);border-radius:12px;padding:16px;margin-bottom:24px;">
                <div style="font-size:0.85rem;font-weight:600;color:var(--text-primary);margin-bottom:8px;">What's next?</div>
                <div style="display:flex;flex-direction:column;gap:8px;">
                    <button id="verifyBtn" onclick="runVerification()" style="padding:10px 16px;border-radius:8px;border:1px solid rgba(34,197,94,0.3);background:rgba(34,197,94,0.08);color:var(--green);cursor:pointer;font-size:0.8rem;font-weight:600;display:flex;align-items:center;justify-content:center;gap:6px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                        Verify transfer integrity
                    </button>
                    <div id="verifyResult" style="display:none;font-size:0.75rem;padding:8px;border-radius:6px;"></div>
                    <button onclick="exportReceipt()" style="padding:10px 16px;border-radius:8px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-secondary);cursor:pointer;font-size:0.8rem;display:flex;align-items:center;justify-content:center;gap:6px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        Download transfer receipt
                    </button>
                </div>
            </div>
            <div style="display:flex;gap:12px;justify-content:center;margin-bottom:28px;">
                <a href="/wizard?new=1" style="padding:12px 24px;border-radius:10px;background:linear-gradient(135deg,var(--primary),var(--secondary));color:#fff;text-decoration:none;font-weight:600;font-size:0.9rem;">New Transfer</a>
                <button onclick="this.closest('#completionOverlay').remove()" style="padding:12px 24px;border-radius:10px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-primary);cursor:pointer;font-size:0.9rem;">View Dashboard</button>
            </div>
            <div style="border-top:1px solid var(--border);padding-top:20px;">
                <p style="color:var(--text-tertiary);font-size:0.8rem;margin-bottom:12px;">CloudHop is free and open source. If it saved you time, consider supporting development:</p>
                <div style="display:flex;gap:10px;justify-content:center;">
                    <a href="https://buymeacoffee.com/husamsoboh" target="_blank" rel="noopener noreferrer" style="padding:8px 16px;border-radius:8px;background:#ffdd00;color:#000;text-decoration:none;font-weight:600;font-size:0.8rem;">Buy Me a Coffee</a>
                    <a href="https://github.com/sponsors/ozymandiashh" target="_blank" rel="noopener noreferrer" style="padding:8px 16px;border-radius:8px;background:rgba(234,74,170,0.15);color:#ea4aaa;border:1px solid rgba(234,74,170,0.3);text-decoration:none;font-weight:600;font-size:0.8rem;">GitHub Sponsor</a>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
    document.addEventListener('keydown', function escClose(e) { if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', escClose); } });
}

async function runVerification() {
    const btn = document.getElementById('verifyBtn');
    const result = document.getElementById('verifyResult');
    if (!btn) return;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Verifying...';
    result.style.display = 'none';
    try {
        const res = await fetch('/api/verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}
        });
        const d = await res.json();
        result.style.display = 'block';
        if (d.ok && d.status === 'perfect') {
            result.style.background = 'rgba(34,197,94,0.1)';
            result.style.color = 'var(--green)';
            result.textContent = d.msg;
            btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Verified!';
            btn.style.color = 'var(--green)';
        } else if (d.ok && d.status === 'differences') {
            result.style.background = 'rgba(245,158,11,0.1)';
            result.style.color = 'var(--orange)';
            result.textContent = d.msg;
            btn.disabled = false;
            btn.innerHTML = 'Verify again';
        } else {
            result.style.background = 'rgba(239,68,68,0.1)';
            result.style.color = 'var(--red)';
            result.textContent = d.msg || 'Verification failed.';
            btn.disabled = false;
            btn.innerHTML = 'Retry verification';
        }
    } catch(e) {
        result.style.display = 'block';
        result.style.background = 'rgba(239,68,68,0.1)';
        result.style.color = 'var(--red)';
        result.textContent = 'Error: ' + e.message;
        btn.disabled = false;
        btn.innerHTML = 'Retry verification';
    }
}

function exportReceipt() {
    const lines = [
        'CloudHop Transfer Receipt',
        '========================',
        '',
        'Date: ' + new Date().toLocaleString(),
        'Status: Complete',
        '',
        'Transferred: ' + (document.getElementById('bpTransferred')?.textContent || '--'),
        'Total: ' + (document.getElementById('bpTotal')?.textContent || '--'),
        'Files: ' + (document.getElementById('filesDone')?.textContent || '0') + ' / ' + (document.getElementById('filesTotal')?.textContent || '0'),
        'Duration: ' + (document.getElementById('elapsed')?.textContent || '--'),
        'Sessions: ' + (document.getElementById('sessionBadge')?.textContent || '--'),
        '',
        'Generated by CloudHop (https://github.com/ozymandiashh/cloudhop)',
    ];
    const blob = new Blob([lines.join('\n')], {type: 'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'CloudHop-Receipt-' + new Date().toISOString().slice(0,10) + '.txt';
    a.click();
    URL.revokeObjectURL(a.href);
}

async function refresh() {
  try {
    let d;
    if (_isDemo) {
      d = getDemoData();
    } else {
      const res = await fetch('/api/status');
      if (!res.ok) {
        failCount++;
        console.error('Dashboard poll failed with HTTP', res.status);
        if (failCount >= 3) { setDisplay('connLost', 'block'); document.body.style.paddingTop = '48px'; const hdr = document.querySelector('.header'); if (hdr) hdr.style.top = '48px'; }
        return;
      }
      d = await res.json();
    }
    failCount = 0;
    document.querySelectorAll('.loading-pulse').forEach(el => el.classList.remove('loading-pulse'));
    setDisplay('connLost', 'none');
    const header = document.querySelector('.header');
    if (header) header.style.top = '0';
    document.body.style.paddingTop = '';

    // Show empty state if API returns error (no log file) AND rclone is NOT running
    if (d.error && !d.rclone_running) {
      document.getElementById('emptyState').style.display = 'block';
      ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
      });
      ['sessionBadge','btnPause2','btnResume2','btnCancel2','btnNewTransfer2'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
      });
      { const cb = document.getElementById('controlBar'); if (cb) cb.style.display = 'none'; }
      updateStatusDot('idle');
      setText('statusText', 'Idle');
      return;
    }
    // If rclone is running but log not ready yet, show Starting state
    if (d.error && d.rclone_running) {
      document.getElementById('emptyState').style.display = 'none';
      ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
      });
      ['sessionBadge','btnCancel2','btnNewTransfer2'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
      });
      { const cb = document.getElementById('controlBar'); if (cb) cb.style.display = 'flex'; }
      updateStatusDot('active');
      setText('statusText', 'Starting...');
      updateButtons(true);
      return;
    }

    // Status
    if (d.finished && d.global_pct >= 100) {
      updateStatusDot('complete');
      document.getElementById('statusText').textContent = 'Complete';
      updateButtons(false);
      const btnResume2 = document.getElementById('btnResume2');
      if (btnResume2) btnResume2.style.display = 'none';
      const btnPause2 = document.getElementById('btnPause2');
      if (btnPause2) btnPause2.style.display = 'none';
      // Show persistent completion banner on dashboard
      const cBanner = document.getElementById('completionBanner');
      if (cBanner) {
        cBanner.style.display = '';
        const cMsg = document.getElementById('completionBannerMsg');
        if (cMsg) cMsg.textContent = (d.global_files_done ? d.global_files_done.toLocaleString() : '0') + ' files (' + (d.global_transferred || '--') + ') copied successfully. You can close this window or start a new transfer.';
      }
      if (!completionShown && d.global_pct >= 100) {
          completionShown = true;
          showCompletionScreen(d);
      }
      ensurePolling(30000);
    } else if (d.rclone_running && !d.speed && !d.session_num) {
      updateStatusDot('active');
      document.getElementById('statusText').textContent = 'Starting...';
      updateButtons(true);
    } else if (d.just_started && !d.rclone_running) {
      // Grace period: rclone RC server not yet responding, show Starting
      updateStatusDot('active');
      document.getElementById('statusText').textContent = 'Starting...';
      updateButtons(true);
    } else if (d.finished && !d.rclone_running && d.global_pct < 100 && !d.just_started) {
      updateStatusDot('stopped');
      document.getElementById('statusText').textContent = 'Stopped';
      updateButtons(false);
    } else if (d.finished) {
      updateStatusDot('paused');
      document.getElementById('statusText').textContent = 'Paused';
      updateButtons(false);
    } else if (!d.speed && !d.session_num) {
      updateStatusDot('idle');
      document.getElementById('statusText').textContent = 'Idle';
      updateButtons(false);
    } else {
      updateStatusDot('active');
      // Smart status: show what rclone is actually doing
      const hasActiveFiles = d.active && d.active.length > 0;
      const isChecking = d.checks_done > 0 && !hasActiveFiles;
      const speedVal = parseSpeed(d.speed || '');
      if (isChecking) {
        document.getElementById('statusText').textContent = 'Scanning files...';
      } else if (speedVal < 0.01 && d.listed > 0) {
        document.getElementById('statusText').textContent = 'Listing files...';
      } else {
        document.getElementById('statusText').textContent = 'Transferring';
      }
      updateButtons(true);
      ensurePolling(5000);
    }

    // Empty state: show when truly no transfer (not running, no data)
    const isEmpty = !d.rclone_running && !d.session_num && (d.global_total_bytes === undefined || d.global_total_bytes === 0) && !d.speed;
    document.getElementById('emptyState').style.display = isEmpty ? 'block' : 'none';
    ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = isEmpty ? 'none' : '';
    });
    ['btnCancel','btnNewTransfer','sessionBadge','btnCancel2','btnNewTransfer2'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = isEmpty ? 'none' : '';
    });
    {const cb=document.getElementById('controlBar');if(cb)cb.style.display=isEmpty?'none':'flex';}
    if (isEmpty) return;

    // Session badge
    document.getElementById('sessionBadge').textContent = `Session ${d.session_num || 1}`;
    if (d.transfer_label) document.getElementById('transferTitle').textContent = d.transfer_label;

    // Mode badge
    const modeBadge = document.getElementById('modeBadge');
    if (modeBadge) {
      const mode = d.mode || 'copy';
      const modeLabels = {copy: 'COPY', sync: 'SYNC', bisync: 'BISYNC'};
      const modeColors = {copy: 'var(--green)', sync: 'var(--orange)', bisync: 'var(--blue)'};
      modeBadge.textContent = modeLabels[mode] || 'COPY';
      modeBadge.style.color = modeColors[mode] || 'var(--green)';
      modeBadge.style.borderColor = modeColors[mode] || 'var(--green)';
      modeBadge.style.display = 'inline-flex';
    }

    // Initialize bandwidth dropdown from current transfer state
    if (d.bw_limit) {
      const bwSel = document.getElementById('bwLimit');
      if (bwSel && !bwSel._initialized) {
        bwSel.value = d.bw_limit;
        bwSel._initialized = true;
      }
    }

    if (d.speed_history && d.speed_history.length > 0) {
      speedHistory = d.speed_history;
    }
    if (d.pct_history && d.pct_history.length > 0) {
      progressHistory = d.pct_history;
    }
    // Build files history locally from global_files_done (backend cumulative is buggy with multi-session)
    if (d.global_files_done !== undefined && d.global_files_done > 0) {
      filesLocalHistory.push(d.global_files_done);
      if (filesLocalHistory.length > 200) filesLocalHistory = filesLocalHistory.slice(-200);
      try { sessionStorage.setItem('cloudhop_chartHistory', JSON.stringify(filesLocalHistory)); } catch(e) {}
    }

    // Wall clock + uptime
    if (d.wall_clock) document.getElementById('wallClock').textContent = d.wall_clock;
    const uptimeEl = document.getElementById('uptimePct');
    if (d.uptime_pct !== undefined && uptimeEl) uptimeEl.textContent = d.uptime_pct + '%';

    // Big progress - GLOBAL
    let pct = d.global_pct || 0;
    // Reset peak speed and progress when a new transfer starts
    if (d.session_num === 1 && pct < 5) { peakSpeedVal = 0; peakSpeedTime = ''; peakProgressPct = 0; try { sessionStorage.removeItem('cloudhop_peakSpeed'); } catch(e) {} }
    // F314: In sync mode, verification passes can reset pct to 0.
    // Keep progress bar at peak value and show verification indicator.
    const isSyncVerifying = d.mode === 'sync' && pct < peakProgressPct && peakProgressPct > 5;
    if (pct > peakProgressPct) peakProgressPct = pct;
    const displayPct = Math.max(pct, peakProgressPct);
    document.getElementById('bigPct').textContent = displayPct;
    document.getElementById('bigBar').style.width = Math.max(displayPct, 0.2) + '%';
    document.getElementById('bigBar').setAttribute('aria-valuenow', displayPct);
    const glowEl = document.getElementById('progressGlow');
    if (glowEl) glowEl.style.width = Math.max(displayPct, 0.2) + '%';
    // Show verification indicator during sync multi-pass
    const verifyIndicator = document.getElementById('syncVerifyIndicator');
    if (isSyncVerifying) {
      if (!verifyIndicator) {
        const bar = document.getElementById('bigBar')?.parentElement;
        if (bar) {
          const ind = document.createElement('div');
          ind.id = 'syncVerifyIndicator';
          ind.style.cssText = 'font-size:0.75rem;color:var(--orange);font-weight:600;margin-top:4px;display:flex;align-items:center;gap:6px;';
          ind.innerHTML = '<span class="spinner" style="width:12px;height:12px;border-width:2px;"></span> Verifying integrity...';
          bar.parentElement.insertBefore(ind, bar.nextSibling);
        }
      }
    } else if (verifyIndicator) {
      verifyIndicator.remove();
    }
    if (d.global_transferred) document.getElementById('bpTransferred').textContent = d.global_transferred;
    if (d.global_total) document.getElementById('bpTotal').textContent = d.global_total;
    // ETA is computed by the smoothed average-speed block below (near end of refresh).

    // Session note
    const sn = document.getElementById('sessionNote');
    if (!d.session_num || d.global_total_bytes === 0) {
      sn.textContent = 'Waiting for transfer to start...';
    } else if (d.session_num > 1) {
      sn.textContent = `This session: ${d.session_transferred || '--'} / ${d.session_total || '--'} (${d.session_pct || 0}%)`;
    } else {
      sn.textContent = '';
    }

    // Files
    if (d.global_files_done !== undefined) {
      document.getElementById('filesDone').textContent = d.global_files_done.toLocaleString();
      document.getElementById('filesTotal').textContent = d.global_files_total.toLocaleString();
      document.getElementById('filesPct').textContent = d.global_files_pct;
      document.getElementById('filesBar').style.width = Math.max(d.global_files_pct, 0.2) + '%';
    }

    // Checks
    if (d.checks_done !== undefined) {
      document.getElementById('checksDone').textContent = d.checks_done.toLocaleString();
      document.getElementById('checksTotal').textContent = d.checks_total.toLocaleString();
      const cpct = d.checks_total ? (d.checks_done / d.checks_total * 100) : 0;
      document.getElementById('checksBar').style.width = Math.max(cpct, 0.2) + '%';
    }

    // Speed display
    const speedMbs = parseSpeed(d.speed || '');
    if (d.speed && !d.finished) {
      document.getElementById('speed').style.fontSize = '';
      document.getElementById('speed').textContent = fmtSpeed(speedMbs);
      const realSpeeds = speedHistory.filter(v => v !== null);
      if (realSpeeds.length >= 2) {
        const prev = realSpeeds[realSpeeds.length - 2];
        const diff = speedMbs - prev;
        const arrow = diff > 0.05 ? '\u2191' : diff < -0.05 ? '\u2193' : '\u2192';
        const diffColor = diff > 0 ? 'var(--green)' : diff < 0 ? 'var(--red)' : 'var(--text-secondary)';
        document.getElementById('speedSub').innerHTML = `<span style="color:${diffColor}">${arrow} ${Math.abs(diff).toFixed(2)} MiB/s</span>`;
      }
      if (speedMbs > peakSpeedVal) {
        peakSpeedVal = speedMbs;
        peakSpeedTime = new Date().toLocaleTimeString();
        console.log('[F508] Peak speed updated: %s', fmtSpeed(peakSpeedVal));
        try { sessionStorage.setItem('cloudhop_peakSpeed', JSON.stringify({val: peakSpeedVal, time: peakSpeedTime})); } catch(e) {}
      }
    } else if (d.finished) {
      const isComplete = d.global_pct >= 100 || (!d.rclone_running && d.global_files_total > 0 && d.global_files_done >= d.global_files_total);
      if (isComplete) {
        document.getElementById('speed').textContent = 'Complete';
        document.getElementById('speed').style.fontSize = '1rem';
        document.getElementById('speed').style.color = 'var(--green, #4caf50)';
        document.getElementById('speedSub').textContent = 'all files transferred';
      } else if (speedMbs < 0.01 && d.rclone_running) {
        document.getElementById('speed').textContent = 'Calculating...';
        document.getElementById('speed').style.fontSize = '1rem';
        document.getElementById('speed').style.color = 'var(--text-tertiary)';
        document.getElementById('speedSub').textContent = '';
      } else {
        document.getElementById('speed').textContent = 'Paused';
        document.getElementById('speed').style.fontSize = '1rem';
        document.getElementById('speed').style.color = 'var(--orange, #f59e0b)';
        document.getElementById('speedSub').textContent = 'transfer paused';
      }
    }

    // Avg speed
    if (d.global_transferred_bytes > 0 && d.global_elapsed_sec > 0) {
      const avgMbs = (d.global_transferred_bytes / 1024 / 1024) / d.global_elapsed_sec;
      document.getElementById('avgSpeed').textContent = fmtSpeed(avgMbs);
      document.getElementById('avgSpeedSub').textContent = `across ${d.sessions ? d.sessions.length : (d.session_num || 1)} session(s)`;
    }

    // Peak
    document.getElementById('peakSpeed').textContent = fmtSpeed(peakSpeedVal);
    document.getElementById('peakTime').textContent = peakSpeedTime ? 'at ' + peakSpeedTime : '--';

    // Total active time
    if (d.global_elapsed) {
      document.getElementById('elapsed').textContent = d.global_elapsed;
      document.getElementById('elapsedSub').textContent = `this session: ${d.session_elapsed || '--'}`;
    }

    // Files/min
    if (d.global_files_done && d.global_elapsed_sec > 0) {
      const rate = (d.global_files_done / (d.global_elapsed_sec / 60)).toFixed(1);
      document.getElementById('filesRate').textContent = rate;
      const remaining = (d.global_files_total || 0) - d.global_files_done;
      document.getElementById('filesRateSub').textContent = `~${remaining.toLocaleString()} remaining`;
    }

    // Total copied
    if (d.total_copied_count) {
      document.getElementById('totalCopied').textContent = d.total_copied_count.toLocaleString();
    }

    // Downtime
    let totalDown = 0;
    if (d.downtimes) {
      d.downtimes.forEach(dt => totalDown += dt.duration_sec || 0);
    }
    document.getElementById('downtime').textContent = fmtDuration(totalDown);
    document.getElementById('downtimeSub').textContent = d.downtimes && d.downtimes.length > 0 ? `${d.downtimes.length} pause(s)` : 'no interruptions';

    // Errors
    if (d.errors !== undefined) {
      const el = document.getElementById('errors');
      el.textContent = d.errors;
      el.style.color = d.errors > 0 ? 'var(--red)' : 'var(--green)';
      document.getElementById('errorSub').textContent = d.errors > 0 ? 'retrying may help' : 'none';
    }
    if (d.error_messages && d.error_messages.length > 0) {
      document.getElementById('errorSection').classList.add('show');
      document.getElementById('errorList').innerHTML = d.error_messages.map(e => {
        const friendly = friendlyError(e);
        const isAuth = /token|oauth|expired/i.test(e);
        return `<div class="error-item">${esc(friendly)}${isAuth ? ' <a href="/wizard" style="color:var(--orange);text-decoration:underline;font-size:0.7rem;">Reconnect</a>' : ''}</div>`;
      }).join('');
    } else {
      document.getElementById('errorSection').classList.remove('show');
    }

    // Session timeline - show only last 5 by default
    if (d.sessions && d.sessions.length > 0) {
      const ts = document.getElementById('timelineSection');
      ts.style.display = 'block';
      const totalSessions = d.sessions.length;
      const showAll = window._showAllSessions || false;
      const visibleStart = showAll ? 0 : Math.max(0, totalSessions - 5);
      let html = '';
      if (totalSessions > 5 && !showAll) {
        html += `<div style="text-align:center;margin-bottom:12px;">
          <button onclick="window._showAllSessions=true;refresh();" style="background:var(--bg-card);border:1px solid var(--border);color:var(--text-primary);padding:6px 16px;border-radius:8px;cursor:pointer;font-size:0.75rem;">Show all ${totalSessions} sessions</button>
        </div>`;
      } else if (totalSessions > 5 && showAll) {
        html += `<div style="text-align:center;margin-bottom:12px;">
          <button onclick="window._showAllSessions=false;refresh();" style="background:var(--bg-card);border:1px solid var(--border);color:var(--text-primary);padding:6px 16px;border-radius:8px;cursor:pointer;font-size:0.75rem;">Show last 5 sessions</button>
        </div>`;
      }
      d.sessions.forEach((s, idx) => {
        if (idx < visibleStart) return;
        const isLast = idx === d.sessions.length - 1;
        const dotClass = isLast ? (d.finished ? 'done' : 'active') : 'done';
        const label = isLast && !d.finished ? 'Current Session' : `Session ${s.num}`;
        html += `<div class="tl-item">
          <div class="tl-dot ${dotClass}"></div>
          <div class="tl-header">
            <div class="tl-title">${label}</div>
            <div class="tl-time">${esc(s.start || '--')} \u2192 ${isLast && !d.finished ? 'now' : esc(s.end || '--')}</div>
          </div>
          <div class="tl-stats">
            Transferred: <span>${esc(s.transferred)}</span> \u00b7
            Files: <span>${s.files.toLocaleString()}</span> \u00b7
            Duration: <span>${esc(s.elapsed)}</span>
          </div>
        </div>`;

        if (d.downtimes) {
          const dt = d.downtimes.find(x => x.after_session === idx + 1);
          if (dt) {
            html += `<div class="tl-pause">
              <div class="tl-dot pause" style="left:-20px"></div>
              <div class="tl-pause-inner">Paused for ${esc(dt.duration)}</div>
            </div>`;
          }
        }
      });
      document.getElementById('timeline').innerHTML = html;
    }

    // Charts
    drawAreaChart('speedChart', speedHistory, '#6366f1', 'speedGrad', fmtSpeedShort, true);
    drawAreaChart('progressChart', progressHistory, '#22d3ee', 'progGrad', v => v.toFixed(0) + '%', true, 100);
    drawAreaChart('filesChart', filesLocalHistory, '#818cf8', 'filesGrad', fmtFilesShort, true);

    // Active transfers — clear stale list when transfer is done
    if (d.global_pct >= 100 || d.finished) {
      d.active = [];
    }
    const list = document.getElementById('transfersList');
    document.getElementById('transferCount').textContent = (d.active ? d.active.length : 0) + ' active';
    if (d.active && d.active.length) {
      const sorted = [...d.active].sort((a, b) => {
        const aActive = a.pct > 0 && a.speed && a.speed !== '0/s' && a.speed !== '0 B/s';
        const bActive = b.pct > 0 && b.speed && b.speed !== '0/s' && b.speed !== '0 B/s';
        if (aActive && !bActive) return -1;
        if (!aActive && bActive) return 1;
        return b.pct - a.pct;
      });
      list.innerHTML = sorted.map(t => {
        const isStalled = t.pct > 0 && (!t.speed || t.speed === '0/s' || t.speed === '0 B/s');
        const isQueued = t.pct === 0 && (!t.speed || t.speed === '--');
        let eta = t.eta || '';
        if (isStalled || (eta && /^\d{4,}h/.test(eta))) eta = '';
        let statusHtml = esc(t.speed || '--');
        let barColor = 'var(--primary)';
        if (isStalled) {
          statusHtml = '<span style="color:var(--orange);font-size:0.65rem;font-weight:600">STALLED</span>';
          barColor = 'var(--orange)';
        } else if (isQueued) {
          statusHtml = '<span style="color:var(--text-tertiary);font-size:0.65rem;font-weight:600">QUEUED</span>';
          barColor = 'var(--text-tertiary)';
        }
        return `<div class="transfer-item">
          <div class="fname" title="${esc(t.name)}">${esc(t.name)}${t.size ? ' <span style="color:var(--text-secondary);font-size:0.65rem">(' + esc(t.size) + ')</span>' : ''}</div>
          <div class="mini-bar"><div class="mini-fill" style="width:${t.pct}%;background:${barColor}"></div></div>
          <div class="tpct">${t.pct}%</div>
          <div class="tspeed">${statusHtml}</div>
          <div class="teta">${esc(eta)}</div>
        </div>`;
      }).join('');
    } else {
      list.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-secondary);font-size:0.8rem;">No active transfers</div>';
    }

    // Recent files
    if (d.recent_files && d.recent_files.length > 0) {
      document.getElementById('recentFiles').innerHTML = d.recent_files.map(f => {
        const ext = getExtension(f.name);
        return `<div class="recent-file">
          <div class="rf-name" title="${esc(f.name)}">${esc(f.name)}</div>
          <span class="rf-ext" style="background:${getTypeColor(ext)}22;color:${getTypeColor(ext)}">${esc(ext)}</span>
          <div class="rf-time">${esc(f.time)}</div>
        </div>`;
      }).join('');
    } else {
      document.getElementById('recentFiles').innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-secondary);font-size:0.8rem;">No recent completions</div>';
    }

    // File types
    const ftData = d.all_file_types || {};
    if (Object.keys(ftData).length > 0) {
      const sorted = Object.entries(ftData).sort((a,b) => b[1]-a[1]);
      const maxC = sorted[0][1];
      if (maxC === 0) return;
      // Gradient palette matching prototype: deep blue/indigo → cyan/teal
      const gradientColors = [
        ['#6366f1','#22d3ee'], ['#818cf8','#22d3ee'], ['#7c3aed','#06b6d4'],
        ['#6366f1','#14b8a6'], ['#4f46e5','#22d3ee'], ['#8b5cf6','#06b6d4'],
        ['#6366f1','#2dd4bf'], ['#7c3aed','#22d3ee']
      ];
      document.getElementById('fileTypes').innerHTML = '<div class="types-grid">' +
        sorted.slice(0, 24).map(([ext, count], idx) => {
          const barPct = Math.max(5, (count / maxC) * 100);
          const [c1, c2] = gradientColors[idx % gradientColors.length];
          return `<div class="type-badge">
            <span class="type-name">.${esc(ext)}</span>
            <div class="type-bar" style="width:${barPct}%;background:linear-gradient(90deg, ${c1}, ${c2});border-radius:4px;"></div>
            <span class="type-count">${count.toLocaleString()}</span>
          </div>`;
        }).join('') + '</div>';
    }

    const lastUpdateEl = document.getElementById('lastUpdate');
    if (lastUpdateEl) lastUpdateEl.textContent = new Date().toLocaleTimeString();

    updateFavicon(displayPct);

    document.title = (displayPct > 0 && displayPct < 100) ? '[' + Math.round(displayPct) + '%] CloudHop' : 'CloudHop';

    // Smoothed ETA based on backend EMA or average speed
    if (pct >= 100) {
        document.getElementById('bpEta').textContent = 'Complete';
        document.getElementById('finishTime').textContent = '';
    } else if (d.smoothed_eta_sec && d.smoothed_eta_sec > 0) {
        // B1: Use backend-smoothed ETA with frontend throttling
        const now = Date.now();
        let etaSec = d.smoothed_eta_sec;
        if (lastEtaValue > 0 && now - lastEtaUpdate < 10000) {
            // Don't update ETA more than once per 10 seconds
        } else {
            // Clamp: max 20% shift per update
            if (lastEtaValue > 0) {
                const maxShift = lastEtaValue * 0.2;
                const diff = etaSec - lastEtaValue;
                if (Math.abs(diff) > maxShift) {
                    etaSec = lastEtaValue + (diff > 0 ? maxShift : -maxShift);
                }
            }
            lastEtaValue = etaSec;
            lastEtaUpdate = now;
            document.getElementById('bpEta').textContent = fmtDuration(etaSec);
            const finish = new Date(Date.now() + etaSec * 1000);
            document.getElementById('finishTime').textContent = 'Finish: ' + finish.toLocaleDateString(undefined, {weekday:'short', day:'numeric', month:'short'}) + ', ' + finish.toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
        }
    } else if (d.global_transferred_bytes > 0 && d.global_total_bytes > 0 && d.global_elapsed_sec > 0) {
        // Fallback: average speed ETA
        const avgBps = d.global_transferred_bytes / d.global_elapsed_sec;
        const remaining = d.global_total_bytes - d.global_transferred_bytes;
        if (avgBps > 0 && remaining > 0) {
            const etaSec = remaining / avgBps;
            document.getElementById('bpEta').textContent = fmtDuration(etaSec);
            const finish = new Date(Date.now() + etaSec * 1000);
            document.getElementById('finishTime').textContent = 'Finish: ' + finish.toLocaleDateString(undefined, {weekday:'short', day:'numeric', month:'short'}) + ', ' + finish.toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
        }
    }

    // B3: Rate limit banner
    const rlBanner = document.getElementById('rateLimitBanner');
    if (d.rate_limited === true) {
        if (!rlBanner) {
            const banner = document.createElement('div');
            banner.id = 'rateLimitBanner';
            banner.style.cssText = 'position:fixed;top:0;left:0;right:0;padding:10px 20px;background:rgba(245,158,11,0.15);border-bottom:1px solid rgba(245,158,11,0.3);color:var(--orange);text-align:center;font-size:0.85rem;font-weight:600;z-index:999;';
            banner.textContent = 'Transfer speed reduced due to provider rate limiting';
            document.body.prepend(banner);
            document.body.style.paddingTop = '44px';
            const hdr = document.querySelector('.header');
            if (hdr) hdr.style.top = '44px';
        }
    } else if (rlBanner) {
        rlBanner.remove();
        document.body.style.paddingTop = '';
        const hdr = document.querySelector('.header');
        if (hdr) hdr.style.top = '0';
    }

    // Daily transfer bar chart
    if (d.daily_stats && d.daily_stats.length > 0) {
      document.getElementById('dailyChartSection').style.display = '';
      const maxGib = Math.max(...d.daily_stats.map(x => x.gib));
      const container = document.getElementById('dailyBars');
      container.innerHTML = d.daily_stats.map(ds => {
        const h = maxGib > 0 ? Math.max(4, (ds.gib / maxGib) * 100) : 4;
        const dayLabel = ds.day.slice(5);
        const now = new Date();
        const localToday = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0') + '-' + String(now.getDate()).padStart(2,'0');
        const isToday = ds.day === localToday;
        const color = isToday ? 'var(--green)' : 'var(--primary)';
        return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <span style="font-size:0.65rem;color:var(--text-primary)">${esc(ds.gib + ' GiB')}</span>
          <div style="width:100%;height:${h}px;background:${color};border-radius:4px 4px 0 0;opacity:0.7;"></div>
          <span style="font-size:0.6rem;color:var(--text-secondary)">${esc(dayLabel)}</span>
        </div>`;
      }).join('');
    }

    if (d.listed) document.getElementById('footerInfo').textContent = `Listed: ${d.listed.toLocaleString()} objects`;

    checkNotifications(d);

    // Fetch schedule status (every 30s is enough)
    if (!window._lastScheduleFetch || Date.now() - window._lastScheduleFetch > 30000) {
      window._lastScheduleFetch = Date.now();
      fetch('/api/schedule')
        .then(r => r.json())
        .then(sched => {
          const badge = document.getElementById('scheduleBadge');
          const dot = document.getElementById('scheduleDot');
          const text = document.getElementById('scheduleText');
          if (!badge || !sched.enabled) {
            if (badge) badge.style.display = 'none';
            return;
          }
          badge.style.display = 'flex';
          if (sched.in_window) {
            dot.style.background = '#22c55e';
            text.textContent = 'Scheduled: ' + sched.start_time + ' - ' + sched.end_time;
            text.style.color = 'var(--text-dim)';
          } else {
            dot.style.background = '#f59e0b';
            text.textContent = 'Paused until ' + sched.start_time;
            text.style.color = '#f59e0b';
          }
        })
        .catch(() => {});
    }

  } catch(e) {
    console.error('Refresh error:', e);
    failCount++;
    if (failCount >= 3) { setDisplay('connLost', 'block'); document.body.style.paddingTop = '48px'; const hdr = document.querySelector('.header'); if (hdr) hdr.style.top = '48px'; }
  }
}

// Pause / Resume
function showToast(msg, color) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  const dismiss = document.createElement('span');
  dismiss.textContent = '\u00d7';
  dismiss.style.cssText = 'margin-left:12px;cursor:pointer;font-size:1.1rem;font-weight:700;opacity:0.7;';
  dismiss.onclick = () => t.classList.remove('show');
  t.appendChild(dismiss);
  t.style.borderColor = color || 'var(--primary)';
  t.classList.add('show');
  const isError = color && (color.includes('red') || color.includes('orange'));
  if (showToast._timer) clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.remove('show'), isError ? 7000 : 4000);
}

async function cancelTransfer() {
  return new Promise((resolve) => {
    if (document.getElementById('_cm_cancel_overlay')) return resolve();
    const overlay = document.createElement('div');
    overlay.id = '_cm_cancel_overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:9999;';
    overlay.innerHTML = `<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:28px 32px;max-width:420px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.3);">
      <p style="margin:0 0 20px;font-size:0.95rem;color:var(--text-primary);">Are you sure you want to cancel this transfer?</p>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
        <button id="_cm_dismiss" style="padding:8px 18px;border-radius:8px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-primary);cursor:pointer;">Keep Running</button>
        <button id="_cm_cancel_stay" style="padding:8px 18px;border-radius:8px;border:1px solid var(--red);background:rgba(239,68,68,0.1);color:var(--red);cursor:pointer;font-weight:600;">Cancel Transfer</button>
        <button id="_cm_cancel_new" style="padding:8px 18px;border-radius:8px;border:none;background:var(--primary);color:#fff;cursor:pointer;font-weight:600;">Start New</button>
      </div></div>`;
    document.body.appendChild(overlay);
    function cleanup() { overlay.remove(); document.removeEventListener('keydown', escHandler); }
    function escHandler(e) { if (e.key === 'Escape') { cleanup(); resolve(); } }
    document.addEventListener('keydown', escHandler);
    overlay.querySelector('#_cm_dismiss').onclick = () => { cleanup(); resolve(); };
    overlay.addEventListener('click', (e) => { if (e.target === overlay) { cleanup(); resolve(); } });
    async function doCancel(goToWizard) {
      cleanup();
      try {
        const res = await fetch('/api/pause', {method:'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}});
        if (res.ok) {
          // Immediately clear active transfers display
          const list = document.getElementById('transfersList');
          if (list) list.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-secondary);font-size:0.8rem;">No active transfers</div>';
          document.getElementById('transferCount').textContent = '0 active';
          updateStatusDot('stopped');
          setText('statusText', 'Cancelled');
          updateButtons(false);
          if (goToWizard) {
            window.location.href = '/wizard?new=1';
          } else {
            setTimeout(refresh, 2000);
          }
        } else {
          showToast('Failed to cancel transfer.', 'var(--red)');
        }
      } catch(e) {
        showToast('Error: ' + e.message, 'var(--red)');
      }
      resolve();
    }
    overlay.querySelector('#_cm_cancel_stay').onclick = () => doCancel(false);
    overlay.querySelector('#_cm_cancel_new').onclick = () => doCancel(true);
  });
}

async function doAction(action) {
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
  const barBtn = document.getElementById(action === 'pause' ? 'btnPause2' : 'btnResume2');
  const origBarHTML = barBtn ? barBtn.innerHTML : '';
  if (barBtn) {
    barBtn.disabled = true;
    barBtn.innerHTML = `<span class="spinner"></span>${action === 'pause' ? 'Stopping...' : 'Starting...'}`;
  }
  try {
    const res = await fetch(`/api/${action}`, { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()} });
    const d = await res.json();
    if (d.ok) {
      showToast(d.msg, action === 'pause' ? 'var(--orange)' : 'var(--green)');
      setTimeout(refresh, 2000);
    } else {
      showToast(d.msg, 'var(--red)');
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'var(--red)');
  }
  if (barBtn) { barBtn.disabled = false; barBtn.innerHTML = origBarHTML; }
}

function updateButtons(isRunning) {
  const btnPause2 = document.getElementById('btnPause2');
  const btnResume2 = document.getElementById('btnResume2');
  const showPause = isRunning;
  const showResume = !isRunning;
  if (btnPause2) btnPause2.style.display = showPause ? '' : 'none';
  if (btnResume2) btnResume2.style.display = showResume ? '' : 'none';
}

// Favicon with progress
// Theme toggle (dark/light)
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  // Disable transitions to prevent grey flash during theme switch
  document.body.style.transition = 'none';
  document.querySelectorAll('.card, .header').forEach(el => el.style.transition = 'none');
  html.setAttribute('data-theme', next);
  localStorage.setItem('cloudhop-theme', next);
  // Re-enable transitions after paint
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      document.body.style.transition = '';
      document.querySelectorAll('.card, .header').forEach(el => el.style.transition = '');
    });
  });
  document.getElementById('theme-icon-dark').style.display = next === 'light' ? 'none' : 'block';
  document.getElementById('theme-icon-light').style.display = next === 'light' ? 'block' : 'none';
  // Clear chart cache so they redraw with new theme colors
  if (drawAreaChart._cache) drawAreaChart._cache = {};
  // Redraw charts with new colors
  drawAreaChart('speedChart', speedHistory, '#6366f1', 'speedGrad', fmtSpeedShort, true);
  drawAreaChart('progressChart', progressHistory, '#22d3ee', 'progGrad', v => v.toFixed(0) + '%', true, 100);
  drawAreaChart('filesChart', filesLocalHistory, '#818cf8', 'filesGrad', fmtFilesShort, true);
}
// Load saved theme
(function() {
  const saved = localStorage.getItem('cloudhop-theme');
  if (saved) {
    console.log('[F308] Theme loaded from localStorage:', saved);
    document.documentElement.setAttribute('data-theme', saved);
    document.getElementById('theme-icon-dark').style.display = saved === 'dark' ? 'block' : 'none';
    document.getElementById('theme-icon-light').style.display = saved === 'light' ? 'block' : 'none';
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.setAttribute('data-theme', 'light');
    document.getElementById('theme-icon-dark').style.display = 'none';
    document.getElementById('theme-icon-light').style.display = 'block';
  }
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem('cloudhop-theme')) {
      document.documentElement.setAttribute('data-theme', e.matches ? 'light' : 'dark');
      document.getElementById('theme-icon-dark').style.display = e.matches ? 'none' : 'block';
      document.getElementById('theme-icon-light').style.display = e.matches ? 'block' : 'none';
      if (drawAreaChart._cache) drawAreaChart._cache = {};
    }
  });
})();

// Sound mute toggle
let _soundMuted = localStorage.getItem('cloudhop-muted') === 'true';
function toggleMute() {
  _soundMuted = !_soundMuted;
  localStorage.setItem('cloudhop-muted', _soundMuted);
  document.getElementById('muteIconOn').style.display = _soundMuted ? 'none' : '';
  document.getElementById('muteIconOff').style.display = _soundMuted ? '' : 'none';
  showToast(_soundMuted ? 'Sound off' : 'Sound on', 'var(--text-secondary)');
}
// Restore mute state on load
if (_soundMuted) {
  const onEl = document.getElementById('muteIconOn');
  const offEl = document.getElementById('muteIconOff');
  if (onEl) onEl.style.display = 'none';
  if (offEl) offEl.style.display = '';
}

let _faviconCanvas = null;
let _lastFaviconPct = -1;
function updateFavicon(pct) {
  pct = Math.round(pct);
  if (pct === _lastFaviconPct) return;
  _lastFaviconPct = pct;
  if (!_faviconCanvas) { _faviconCanvas = document.createElement('canvas'); _faviconCanvas.width = 32; _faviconCanvas.height = 32; }
  const canvas = _faviconCanvas;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#0d1220';
  ctx.beginPath(); ctx.arc(16, 16, 16, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = '#6366f1';
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.arc(16, 16, 12, -Math.PI/2, -Math.PI/2 + (pct/100) * Math.PI * 2);
  ctx.stroke();
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 11px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(Math.round(pct), 16, 17);
  let link = document.querySelector('link[rel="icon"]');
  if (!link) { link = document.createElement('link'); link.rel = 'icon'; document.head.appendChild(link); }
  link.href = canvas.toDataURL();
}

// Timeline collapse/expand
let tlCollapsed = false;
function toggleTimeline() {
  tlCollapsed = !tlCollapsed;
  document.getElementById('timeline').style.display = tlCollapsed ? 'none' : '';
  document.getElementById('tlToggle').innerHTML = tlCollapsed ? '&#9654;' : '&#9660;';
}

// Sound notification when transfer completes, hits milestones, or errors appear
let prevPct = 0;
let prevErrors = -1;
const _notifiedMilestones = new Set();
function checkNotifications(d) {
  const pct = d.global_pct || 0;

  // Milestone notifications (25%, 50%, 75%)
  [25, 50, 75].forEach(milestone => {
    if (pct >= milestone && prevPct < milestone && prevPct > 0 && !_notifiedMilestones.has(milestone)) {
      _notifiedMilestones.add(milestone);
      playNotifSound(600, 0.15);
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('CloudHop - ' + milestone + '% Complete', {
          body: d.global_transferred + ' transferred so far.'
        });
      }
      showToast(milestone + '% complete!', 'var(--primary)');
    }
  });

  // Completion notification
  if (pct >= 100 && prevPct < 100 && prevPct > 0) {
    playNotifSound(800, 0.3);
    setTimeout(() => playNotifSound(1000, 0.3), 200);
    setTimeout(() => playNotifSound(1200, 0.3), 400);
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('CloudHop - Transfer Complete!', { body: 'All files have been transferred.' });
    }
  }
  const errs = d.errors || 0;
  if (errs > prevErrors && prevErrors >= 0) {
    playNotifSound(400, 0.2);
    setTimeout(() => playNotifSound(300, 0.2), 150);
  }
  prevPct = pct;
  prevErrors = errs;
}
let _audioCtx = null;
function getAudioCtx() {
  if (!_audioCtx) _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  return _audioCtx;
}
function playNotifSound(freq, dur) {
  if (_soundMuted) return;
  try {
    const ctx = getAudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.value = freq;
    gain.gain.value = 0.08;
    osc.start();
    osc.stop(ctx.currentTime + dur);
  } catch(e) {}
}

async function exportErrorLog() {
  try {
    const res = await fetch('/api/error-log');
    const d = await res.json();
    const lines = [
      'CloudHop Error Report',
      '=====================',
      'Version: ' + d.version,
      'Platform: ' + d.platform,
      'Python: ' + d.python,
      'Date: ' + new Date().toISOString(),
      '',
      'Errors (' + d.errors.length + '):',
      '---',
      ...d.errors,
    ];
    const blob = new Blob([lines.join('\n')], {type: 'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'CloudHop-ErrorLog-' + new Date().toISOString().slice(0,10) + '.txt';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Error log downloaded', 'var(--green)');
  } catch(e) {
    showToast('Could not export logs', 'var(--red)');
  }
}

async function reportError() {
  const proceed = await showConfirmModal(
    'This will open a page where you can describe your problem. ' +
    'Your CloudHop version and recent error messages will be included (no personal files or paths). ' +
    'You will be able to review everything before sending.'
  );
  if (!proceed) return;
  try {
    const res = await fetch('/api/error-log');
    const d = await res.json();
    const lastErrors = d.errors.slice(-5).join('\n');
    const title = encodeURIComponent('Bug report - CloudHop ' + d.version);
    const body = encodeURIComponent(
      '## Environment\n' +
      '- CloudHop: ' + d.version + '\n' +
      '- Platform: ' + d.platform + '\n' +
      '- Python: ' + d.python + '\n\n' +
      '## What happened?\n' +
      '_Please describe what you were doing when the error occurred._\n\n' +
      '## Recent errors\n' +
      '```\n' + (lastErrors || 'No errors found') + '\n```\n'
    );
    window.open('https://github.com/ozymandiashh/cloudhop/issues/new?title=' + title + '&body=' + body, '_blank');
  } catch(e) {
    window.open('https://github.com/ozymandiashh/cloudhop/issues/new', '_blank');
  }
}

async function showHistory() {
  try {
    const existing = document.querySelector('[data-history-modal]');
    if (existing) existing.remove();
    const res = await fetch('/api/history');
    const data = await res.json();
    if (!data.length) { showToast('No transfer history found.', 'var(--text-secondary)'); return; }
    let html = '<div data-history-modal style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:300;display:flex;align-items:center;justify-content:center;" onclick="if(event.target===this)this.remove()">';
    html += '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:16px;padding:24px;max-width:600px;width:90%;max-height:80vh;overflow-y:auto;">';
    html += '<h3 style="font-size:1rem;font-weight:700;color:var(--text-primary);margin-bottom:16px;">Transfer History</h3>';
    data.forEach(h => {
      const hasCmd = h.cmd && h.cmd.length > 0;
      const size = h.total_size || '--';
      const files = h.total_files || 0;
      const lastRun = h.last_run ? h.last_run.replace(/\//g, '-') : '';
      html += '<div style="padding:12px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:12px;">';
      html += '<div style="min-width:0;flex:1;"><div style="font-weight:600;color:var(--text-primary);font-size:0.85rem;">' + esc(h.label) + '</div>';
      html += '<div style="font-size:0.7rem;color:var(--text-secondary);">' + esc(size) + ' &middot; ' + files.toLocaleString() + ' files &middot; ' + h.sessions + ' session(s)';
      if (lastRun) html += ' &middot; ' + esc(lastRun);
      html += '</div></div>';
      if (hasCmd) {
        html += '<button class="history-resume-btn" style="padding:6px 14px;border-radius:8px;border:1px solid rgba(52,211,153,0.3);background:rgba(52,211,153,0.08);color:var(--green);cursor:pointer;font-size:0.75rem;font-weight:600;white-space:nowrap;flex-shrink:0;">Resume</button>';
      }
      html += '</div>';
    });
    html += '<button onclick="this.parentElement.parentElement.remove()" style="margin-top:16px;padding:10px 24px;border-radius:8px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-primary);cursor:pointer;font-size:0.85rem;">Close</button>';
    html += '</div></div>';
    document.body.insertAdjacentHTML('beforeend', html);
    const histModal = document.querySelector('[data-history-modal]');
    const resumeData = data.filter(h => h.cmd && h.cmd.length > 0);
    histModal.querySelectorAll('.history-resume-btn').forEach((btn, i) => {
      btn.addEventListener('click', () => resumeFromHistory(resumeData[i].id));
    });
    function histEsc(e) { if (e.key === 'Escape' && histModal) { histModal.remove(); document.removeEventListener('keydown', histEsc); } }
    document.addEventListener('keydown', histEsc);
  } catch(e) { showToast('Could not load history.', 'var(--red)'); }
}

async function resumeFromHistory(id) {
  if (!await showConfirmModal('Resume this transfer? Any current transfer will be replaced.')) return;
  try {
    const res = await fetch('/api/history/resume', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify({id: id})
    });
    const d = await res.json();
    if (d.ok) {
      showToast('Transfer resumed!', 'var(--green)');
      const modal = document.querySelector('[data-history-modal]');
      if (modal) modal.remove();
      completionShown = false;
      _notifiedMilestones.clear();
      setTimeout(refresh, 2000);
    } else {
      showToast(d.msg || 'Failed to resume', 'var(--red)');
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'var(--red)');
  }
}

// Bandwidth limit dropdown handler
(function() {
  const sel = document.getElementById('bwLimit');
  if (sel) {
    sel.addEventListener('change', async function() {
      const rate = this.value || 'off';
      try {
        const res = await fetch('/api/bwlimit', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
          body: JSON.stringify({rate: rate})
        });
        const d = await res.json();
        if (d.ok) {
          showToast('Speed limit: ' + (rate === 'off' ? 'unlimited' : rate.replace('M', ' MB/s')), 'var(--green)');
        } else {
          showToast(d.msg || 'Failed to change speed', 'var(--red)');
        }
      } catch(e) {
        showToast('Error: ' + e.message, 'var(--red)');
      }
    });
  }
})();

// Demo mode: simulate a transfer in progress for preview purposes
const _isDemo = new URLSearchParams(window.location.search).has('demo');
let _demoPct = 67;
let _demoInterval = null;

function getDemoData() {
  _demoPct = Math.min(_demoPct + 0.08 + Math.random() * 0.12, 99.5);
  const spd = 28 + Math.random() * 12;
  const totalGiB = 58.0;
  const transferred = _demoPct / 100 * totalGiB;
  const total = totalGiB * 1024 * 1024 * 1024;
  const filesTotal = 3612;
  const files = Math.floor(_demoPct / 100 * filesTotal);
  const etaSec = Math.round((100 - _demoPct) / 100 * totalGiB * 1024 / spd);
  const etaMin = Math.floor(etaSec / 60);
  const etaStr = etaMin > 0 ? etaMin + 'm ' + (etaSec % 60) + 's' : etaSec + 's';
  return {
    global_pct: Math.round(_demoPct * 10) / 10,
    global_transferred: transferred.toFixed(2) + ' GiB',
    global_transferred_bytes: transferred * 1024 * 1024 * 1024,
    global_total: totalGiB.toFixed(2) + ' GiB',
    global_total_bytes: total,
    global_files_done: files,
    global_files_total: filesTotal,
    global_files_pct: Math.round(files / filesTotal * 100 * 10) / 10,
    global_elapsed: '28m 15s',
    global_elapsed_sec: 1695,
    session_elapsed: '28m 15s',
    session_elapsed_sec: 1695,
    session_num: 1,
    session_transferred: transferred.toFixed(2) + ' GiB',
    session_total: totalGiB.toFixed(2) + ' GiB',
    session_pct: Math.round(_demoPct * 10) / 10,
    speed: spd.toFixed(1) + ' MiB/s',
    eta: etaStr,
    errors: 0,
    checks_done: 0,
    checks_total: 0,
    listed: filesTotal,
    finished: false,
    rclone_running: true,
    transfer_label: 'Google Drive -> Dropbox',
    active: [
      {name: 'Photos/IMG_4521.heic', pct: 82, size: '48.2MiB', speed: '11.4MiB/s', eta: '1s'},
      {name: 'Documents/Budget-2026.xlsx', pct: 45, size: '8.7MiB', speed: '6.2MiB/s', eta: '3s'},
      {name: 'Videos/birthday-party.mp4', pct: 12, size: '1.8GiB', speed: '18.3MiB/s', eta: '1m32s'},
      {name: 'Work/presentation-final.pptx', pct: 94, size: '156MiB', speed: '9.8MiB/s', eta: '1s'},
    ],
    recent_files: [
      {name: 'Photos/IMG_4520.heic', time: '14:32:01'},
      {name: 'Documents/invoice-march.pdf', time: '14:31:58'},
      {name: 'Photos/IMG_4519.heic', time: '14:31:55'},
      {name: 'Music/playlist-summer.m3u', time: '14:31:52'},
      {name: 'Documents/notes-meeting.txt', time: '14:31:48'},
    ],
    error_messages: [],
    speed_history: Array.from({length: 80}, () => 22 + Math.random() * 18),
    pct_history: Array.from({length: 80}, (_, i) => i * 0.85),
    all_file_types: {heic: 1240, pdf: 185, xlsx: 42, mp4: 18, pptx: 31, txt: 290, jpg: 680, png: 410, docx: 95, zip: 24},
    total_copied_count: files,
    sessions: [
      {num: 1, start: '2026/03/21 14:04:00', end: '', transferred: transferred.toFixed(2) + ' GiB', files: files, elapsed: '28m 15s', elapsed_sec: 1695},
    ],
    downtimes: [],
    wall_clock: '28m 15s',
    uptime_pct: 100,
    daily_stats: [
      {day: '2026-03-21', bytes: transferred * 1024**3, gib: transferred},
    ],
  };
}

if (_isDemo) {
  const _cleanDemo = new URLSearchParams(window.location.search).has('clean');
  if (!_cleanDemo) {
    // Show demo banner
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:linear-gradient(90deg,var(--primary),var(--secondary));color:#fff;text-align:center;padding:8px;font-size:0.8rem;font-weight:600;z-index:200;';
    banner.innerHTML = 'DEMO MODE - This is a simulated transfer preview. <a href="/dashboard" style="color:#fff;text-decoration:underline;margin-left:8px;">Exit demo</a>';
    document.body.prepend(banner);
    document.body.style.paddingTop = '36px';
  }
}

// F322: Bind Transfer History link explicitly
(function() {
  const link = document.getElementById('historyLink');
  if (link) {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      console.log('[F322] Transfer History link activated');
      showHistory();
    });
  }
})();

refresh();
refreshQueue();
refreshPresets();
ensurePolling(_isDemo ? 2000 : 5000);
setInterval(refreshQueue, _isDemo ? 5000 : 5000);
setInterval(refreshPresets, 10000);
window.addEventListener('resize', () => {
  if (drawAreaChart._cache) drawAreaChart._cache = {};
  drawAreaChart('speedChart', speedHistory, '#6366f1', 'speedGrad', fmtSpeedShort, true);
  drawAreaChart('progressChart', progressHistory, '#22d3ee', 'progGrad', v => v.toFixed(0) + '%', true, 100);
  drawAreaChart('filesChart', filesLocalHistory, '#818cf8', 'filesGrad', fmtFilesShort, true);
});

// Auto-update check (every 30 minutes)
(function checkForUpdates() {
  fetch('/api/check-update').then(r => r.json()).then(d => {
    if (d.update_available) {
      const banner = document.getElementById('updateBanner');
      const msg = document.getElementById('updateMsg');
      const action = document.getElementById('updateAction');
      if (banner && msg && action) {
        msg.textContent = 'CloudHop ' + d.latest + ' is available (you have ' + d.current + ')';
        if (d.download_url && isSafeUrl(d.download_url)) {
          action.textContent = 'Download update';
          action.href = d.download_url;
          action.target = '_blank';
        } else {
          if (d.download_url) {
            console.error('CloudHop: update download URL rejected by validation:', d.download_url);
          }
          if (d.pip_command) {
            action.textContent = 'Update: ' + d.pip_command;
            action.href = '#';
            action.onclick = function(e) {
              e.preventDefault();
              navigator.clipboard.writeText(d.pip_command);
              action.textContent = 'Copied to clipboard!';
            };
          }
        }
        banner.style.display = 'block';
      }
    }
  }).catch(() => {});
  setTimeout(checkForUpdates, 1800000);
})();

// ========== TRANSFER QUEUE ==========

async function refreshQueue() {
  try {
    const res = await fetch('/api/queue');
    if (!res.ok) return;
    const data = await res.json();
    const items = data.queue || [];
    const section = document.getElementById('queueSection');
    const list = document.getElementById('queueList');
    const empty = document.getElementById('queueEmpty');
    const btnStart = document.getElementById('btnStartNext');
    if (!section || !list) return;

    // Filter to show only waiting/active/failed (hide completed)
    const visible = items.filter(i => i.status !== 'completed');
    if (visible.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = '';
    const hasWaiting = visible.some(i => i.status === 'waiting');
    const hasActive = visible.some(i => i.status === 'active');
    if (btnStart) btnStart.style.display = (hasWaiting && !hasActive) ? '' : 'none';

    if (visible.length === 0) {
      list.innerHTML = '';
      if (empty) empty.style.display = '';
      return;
    }
    if (empty) empty.style.display = 'none';

    let html = '';
    visible.forEach((item, idx) => {
      const cfg = item.config || {};
      const src = esc(cfg.source || '?');
      const dst = esc(cfg.dest || '?');
      const status = item.status || 'waiting';
      const addedAt = item.added_at ? new Date(item.added_at).toLocaleTimeString() : '';
      const qid = item.queue_id || '';
      const canRemove = status === 'waiting' || status === 'failed';
      const canMoveUp = status === 'waiting' && idx > 0 && visible[idx - 1].status === 'waiting';
      const canMoveDown = status === 'waiting' && idx < visible.length - 1 && visible[idx + 1].status === 'waiting';

      html += '<div class="queue-item" data-qid="' + esc(qid) + '">';
      html += '<div class="queue-item-info">';
      html += '<span class="queue-badge ' + status + '">' + esc(status) + '</span>';
      html += '<span class="queue-item-path">' + src + ' &rarr; ' + dst + '</span>';
      if (addedAt) html += '<span class="queue-item-time">' + esc(addedAt) + '</span>';
      html += '</div>';
      html += '<div class="queue-item-actions">';
      if (canMoveUp) html += '<button class="queue-btn" onclick="queueMove(\'' + esc(qid) + '\',' + (idx - 1) + ')" title="Move up">&uarr;</button>';
      if (canMoveDown) html += '<button class="queue-btn" onclick="queueMove(\'' + esc(qid) + '\',' + (idx + 1) + ')" title="Move down">&darr;</button>';
      if (canRemove) html += '<button class="queue-btn remove" onclick="queueRemove(\'' + esc(qid) + '\')" title="Remove">&times;</button>';
      html += '</div></div>';
    });
    list.innerHTML = html;
  } catch (e) {
    console.error('Queue refresh error:', e);
  }
}

async function queueRemove(queueId) {
  try {
    await fetch('/api/queue/' + queueId, {
      method: 'DELETE',
      headers: { 'X-CSRF-Token': getCsrfToken(), 'Content-Type': 'application/json' }
    });
    refreshQueue();
  } catch (e) { console.error('Queue remove error:', e); }
}

async function queueMove(queueId, position) {
  try {
    await fetch('/api/queue/' + queueId + '/reorder', {
      method: 'PUT',
      headers: { 'X-CSRF-Token': getCsrfToken(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ position: position })
    });
    refreshQueue();
  } catch (e) { console.error('Queue reorder error:', e); }
}

async function queueStartNext() {
  try {
    await fetch('/api/queue/start-next', {
      method: 'POST',
      headers: { 'X-CSRF-Token': getCsrfToken(), 'Content-Type': 'application/json' },
      body: '{}'
    });
    refreshQueue();
    refresh();
  } catch (e) { console.error('Queue start-next error:', e); }
}

// ── Presets ──────────────────────────────────────────────────────────
let _deletePresetId = null;

async function refreshPresets() {
  try {
    const res = await fetch('/api/presets');
    const data = await res.json();
    const presets = data.presets || [];
    const section = document.getElementById('presetsSection');
    const list = document.getElementById('presetsList');
    const empty = document.getElementById('presetsEmpty');
    if (!section) return;
    if (presets.length === 0) {
      section.style.display = 'block';
      list.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    section.style.display = 'block';
    empty.style.display = 'none';
    list.innerHTML = presets.map(p => {
      const cfg = p.config || {};
      const srcLabel = (cfg.source || '').split('/').pop() || cfg.source || '?';
      const dstLabel = (cfg.dest || '').split('/').pop() || cfg.dest || '?';
      const mode = cfg.mode || 'copy';
      const lastUsed = p.last_used ? new Date(p.last_used).toLocaleDateString() : 'Never';
      return '<div class="preset-item" style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--card-border,#333);">' +
        '<div style="flex:1;min-width:0;">' +
          '<div style="font-weight:600;font-size:0.9rem;color:var(--text-primary,#e0e0f0);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(p.name) + '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-secondary,#888);margin-top:2px;">' +
            esc(srcLabel) + ' \u2192 ' + esc(dstLabel) +
            ' <span style="display:inline-block;padding:1px 6px;border-radius:4px;background:var(--bg,#0d0d1a);font-size:0.7rem;margin-left:4px;">' + esc(mode) + '</span>' +
            ' &middot; Used ' + p.use_count + 'x &middot; Last: ' + esc(lastUsed) +
          '</div>' +
        '</div>' +
        '<button onclick="runPreset(\'' + p.preset_id + '\')" style="padding:6px 16px;border-radius:8px;border:none;background:linear-gradient(135deg,var(--primary,#6366f1),var(--secondary,#8b5cf6));color:#fff;cursor:pointer;font-size:0.8rem;font-weight:600;white-space:nowrap;">Run</button>' +
        '<button onclick="promptDeletePreset(\'' + p.preset_id + '\')" style="padding:6px 12px;border-radius:8px;border:1px solid var(--card-border,#333);background:transparent;color:var(--text-secondary,#888);cursor:pointer;font-size:0.8rem;" onmouseover="this.style.borderColor=\'#ef4444\';this.style.color=\'#ef4444\'" onmouseout="this.style.borderColor=\'var(--card-border,#333)\';this.style.color=\'var(--text-secondary,#888)\'">Delete</button>' +
      '</div>';
    }).join('');
  } catch (e) { console.error('Presets refresh error:', e); }
}

async function runPreset(presetId) {
  try {
    const res = await fetch('/api/presets/' + presetId + '/run', {
      method: 'POST',
      headers: { 'X-CSRF-Token': getCsrfToken(), 'Content-Type': 'application/json' },
      body: '{}'
    });
    const data = await res.json();
    if (data.ok) {
      refresh();
      refreshPresets();
    } else {
      alert(data.msg || 'Failed to run preset');
    }
  } catch (e) { alert('Error running preset: ' + e.message); }
}

function promptDeletePreset(presetId) {
  _deletePresetId = presetId;
  document.getElementById('deletePresetModal').style.display = 'block';
}

function closeDeletePresetModal() {
  _deletePresetId = null;
  document.getElementById('deletePresetModal').style.display = 'none';
}

async function confirmDeletePreset() {
  if (!_deletePresetId) return;
  try {
    await fetch('/api/presets/' + _deletePresetId, {
      method: 'DELETE',
      headers: { 'X-CSRF-Token': getCsrfToken() }
    });
    closeDeletePresetModal();
    refreshPresets();
  } catch (e) { console.error('Delete preset error:', e); }
}
