const API = 'http://localhost:8000';

// ─── State ──────────────────────────────────────────────────────────────────
let radarItems = [];
let cveOnlyMode = false;
let currentAlertSev = '';
let trackerAlerts = [];
let threatMap = null;
let mapMarkers = [];

// ─── Module Navigation ────────────────────────────────────────────────────────
function showModule(name) {
  ['radar','scanner','tracker','map','scheduler','darkweb','supplychain','attackpath','compliance'].forEach(m => {
    document.getElementById(`module-${m}`)?.classList.add('hidden');
    document.getElementById(`tab-${m}`)?.classList.remove('active');
  });
  document.getElementById(`module-${name}`)?.classList.remove('hidden');
  document.getElementById(`tab-${name}`)?.classList.add('active');
  if (name === 'map') initMap();
  if (name === 'scheduler') loadScheduler();
  if (name === 'scanner') loadScanHistory();
  if (name === 'darkweb') { loadDarkwebTargets(); loadDarkwebFindings(); }
  if (name === 'attackpath') loadAttackPath();
  if (name === 'compliance') initNIS2Tab();
}

// ─── Toast ────────────────────────────────────────────────────────────────────
let toastTimer = null;
function toast(msg, type = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast ${type}`;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3500);
}

// ─── Health Check ─────────────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const r = await fetch(`${API}/api/health`);
    const data = await r.json();
    if (data.status === 'online') {
      document.getElementById('status-dot').style.background = '#10b981';
      document.getElementById('status-text').textContent = 'SYSTEM ONLINE';
    }
  } catch {
    document.getElementById('status-dot').style.background = '#f43f5e';
    document.getElementById('status-text').textContent = 'BACKEND OFFLINE';
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// RADAR MODULE
// ══════════════════════════════════════════════════════════════════════════════

async function loadRadar(cveOnly = false) {
  const feed = document.getElementById('radar-feed');
  feed.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Fetching threat intelligence...</span></div>`;
  try {
    const r = await fetch(`${API}/api/radar?limit=60&cves_only=${cveOnly}`);
    const data = await r.json();
    radarItems = data.items || [];
    renderRadar(radarItems);
    buildSourceFilter(radarItems);
  } catch (e) {
    feed.innerHTML = `<div class="empty-state"><p>⚠ Unable to reach backend. Make sure the server is running on port 8000.</p></div>`;
  }
}

async function loadRadarStats() {
  try {
    const r = await fetch(`${API}/api/radar/stats`);
    const data = await r.json();
    document.getElementById('stat-total').textContent = data.total_items || 0;
    document.getElementById('stat-cve-items').textContent = data.items_with_cves || 0;
    document.getElementById('stat-sources').textContent = (data.sources || []).length;
    const top = data.top_cves?.[0];
    document.getElementById('stat-top-cve').textContent = top ? top.cve : '—';
    buildTicker(data.top_cves || []);
  } catch {}
}

function buildTicker(topCves) {
  const track = document.getElementById('ticker-content');
  if (!topCves.length) { track.innerHTML = '<span class="text-gray-500 text-xs">No CVEs detected yet. Refresh feeds.</span>'; return; }
  const doubled = [...topCves, ...topCves];
  track.innerHTML = doubled.map(c =>
    `<span class="ticker-cve" title="${c.mentions} mentions">${c.cve} <span style="color:#6b7280">(${c.mentions})</span></span>`
  ).join('');
}

function buildSourceFilter(items) {
  const sel = document.getElementById('radar-source-filter');
  const sources = [...new Set(items.map(i => i.source))].sort();
  sel.innerHTML = '<option value="">All Sources</option>' +
    sources.map(s => `<option value="${s}">${s}</option>`).join('');
}

function renderRadar(items) {
  const feed = document.getElementById('radar-feed');
  if (!items.length) {
    feed.innerHTML = `<div class="empty-state"><p>No items found. Try refreshing the feeds.</p></div>`;
    return;
  }
  feed.innerHTML = items.map(item => {
    const hasCves = item.cves && item.cves.length > 0;
    const cveBadges = hasCves
      ? item.cves.map(c => `<span class="badge-cve" onclick="searchCVE('${c}')">${c}</span>`).join('')
      : '';
    const dateStr = item.published ? formatDate(item.published) : '';
    return `
      <div class="radar-item ${hasCves ? 'has-cves' : ''}" onclick="window.open('${item.link}','_blank')">
        <div class="radar-item-title">${escHtml(item.title)}</div>
        <div class="radar-item-meta">
          <span class="source-badge">${escHtml(item.source)}</span>
          ${dateStr ? `<span class="radar-date">${dateStr}</span>` : ''}
          ${cveBadges}
        </div>
      </div>`;
  }).join('');
}

function radarFilter() {
  const q = document.getElementById('radar-search').value.toLowerCase();
  const src = document.getElementById('radar-source-filter').value;
  let filtered = radarItems;
  if (q) filtered = filtered.filter(i =>
    i.title.toLowerCase().includes(q) || (i.cves || []).some(c => c.toLowerCase().includes(q))
  );
  if (src) filtered = filtered.filter(i => i.source === src);
  renderRadar(filtered);
}

function radarToggleCVEOnly() {
  cveOnlyMode = !cveOnlyMode;
  const btn = document.getElementById('btn-cve-only');
  btn.classList.toggle('active', cveOnlyMode);
  loadRadar(cveOnlyMode);
}

async function radarRefresh() {
  const btn = document.getElementById('btn-radar-refresh');
  btn.disabled = true;
  btn.textContent = 'Refreshing...';
  try {
    await fetch(`${API}/api/radar/refresh`, { method: 'POST' });
    toast('Feed refresh triggered. Results update in ~15s.', 'success');
    setTimeout(() => { loadRadar(cveOnlyMode); loadRadarStats(); }, 15000);
  } catch {
    toast('Failed to reach backend.', 'error');
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = `<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Refresh Feeds`;
    }, 3000);
  }
}

function searchCVE(cve) {
  event.stopPropagation();
  window.open(`https://nvd.nist.gov/vuln/detail/${cve}`, '_blank');
}

// ══════════════════════════════════════════════════════════════════════════════
// SCANNER MODULE
// ══════════════════════════════════════════════════════════════════════════════

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
}

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) uploadFile(file);
}

async function uploadFile(file) {
  const loading = document.getElementById('scanner-loading');
  const results = document.getElementById('scanner-results');
  loading.classList.remove('hidden');
  results.classList.add('hidden');

  const form = new FormData();
  form.append('file', file);
  try {
    const r = await fetch(`${API}/api/scanner/analyze`, { method: 'POST', body: form });
    if (!r.ok) {
      const err = await r.json();
      toast(err.detail || 'Scan failed.', 'error');
      loading.classList.add('hidden');
      return;
    }
    const data = await r.json();
    renderScannerResults(data);
  } catch (e) {
    toast('Cannot connect to backend.', 'error');
  } finally {
    loading.classList.add('hidden');
  }
}

function renderScannerResults(data) {
  const summary = document.getElementById('scanner-summary');
  const vulnList = document.getElementById('scanner-vulns');
  const results = document.getElementById('scanner-results');
  results.classList.remove('hidden');

  // Count by severity
  const sevCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  (data.vulnerabilities || []).forEach(v => { sevCount[v.severity] = (sevCount[v.severity] || 0) + 1; });

  summary.innerHTML = `
    <div class="stat-card"><div class="stat-value text-violet-400">${data.packages_scanned}</div><div class="stat-label">Pkgs Scanned</div></div>
    <div class="stat-card"><div class="stat-value text-amber-400">${data.total_vulns}</div><div class="stat-label">Vulnerabilities</div></div>
    <div class="stat-card"><div class="stat-value text-rose-400">${sevCount.CRITICAL + sevCount.HIGH}</div><div class="stat-label">Critical/High</div></div>
    <div class="stat-card"><div class="stat-value text-rose-500">${data.actively_exploited}</div><div class="stat-label">Actively Exploited</div></div>
  `;

  if (!data.vulnerabilities.length) {
    vulnList.innerHTML = `<div class="glass-card p-8 text-center text-emerald-400 font-semibold">✓ No known vulnerabilities found in ${data.ecosystem} dependencies.</div>`;
    return;
  }

  vulnList.innerHTML = data.vulnerabilities.map(v => {
    const cveLinks = (v.cve_ids || []).map(c =>
      `<a href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank" class="badge-cve">${c}</a>`
    ).join('');
    const exploited = v.actively_exploited
      ? `<span class="badge-exploited">🔥 ACTIVELY EXPLOITED</span>` : '';
    const score = v.cvss_score ? `<span class="text-xs font-mono text-gray-400">CVSS ${v.cvss_score}</span>` : '';
    return `
      <div class="vuln-card ${v.severity}">
        <div class="flex flex-wrap items-center gap-2 mb-2">
          <span class="font-mono font-bold text-white">${escHtml(v.package)}</span>
          ${v.version ? `<span class="text-xs text-gray-500 font-mono">v${escHtml(v.version)}</span>` : ''}
          <span class="severity-badge ${v.severity}">${v.severity}</span>
          ${score}
          ${exploited}
          ${cveLinks}
        </div>
        <p class="text-sm text-gray-300 leading-relaxed">${escHtml(v.summary || v.details || 'No description available.')}</p>
        <div class="mt-2 text-xs text-gray-500 font-mono">${escHtml(v.osv_id || '')}</div>
      </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════════════════════
// TRACKER MODULE
// ══════════════════════════════════════════════════════════════════════════════

async function loadStack() {
  try {
    const r = await fetch(`${API}/api/tracker/stack`);
    const data = await r.json();
    renderStack(data.stack || []);
  } catch {}
}

function renderStack(stack) {
  const el = document.getElementById('stack-list');
  if (!stack.length) {
    el.innerHTML = `<p class="text-xs text-gray-600 text-center mt-2">No technologies added yet.</p>`;
    return;
  }
  el.innerHTML = stack.map(s => `
    <div class="stack-tag">
      <span>${escHtml(s.name)}${s.version ? ` <span class="text-xs text-emerald-600 font-mono">v${escHtml(s.version)}</span>` : ' <span class="text-xs text-gray-600 italic">all versions</span>'}</span>
      <button class="remove-btn" onclick="removeStackItem('${escHtml(s.name)}')" title="Remove">×</button>
    </div>`).join('');
}

async function addStackItem() {
  const input = document.getElementById('stack-input');
  const versionInput = document.getElementById('stack-version-input');
  const name = input.value.trim();
  const version = versionInput ? versionInput.value.trim() : '';
  if (!name) return;
  try {
    const r = await fetch(`${API}/api/tracker/stack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, version })
    });
    if (!r.ok) { const e = await r.json(); toast(e.detail, 'error'); return; }
    input.value = '';
    if (versionInput) versionInput.value = '';
    const label = version ? `${name} v${version}` : name;
    toast(`Added "${label}" to stack`, 'success');
    loadStack();
  } catch { toast('Backend unreachable.', 'error'); }
}

async function removeStackItem(name) {
  try {
    await fetch(`${API}/api/tracker/stack/${encodeURIComponent(name)}`, { method: 'DELETE' });
    toast(`Removed "${name}"`, '');
    loadStack();
    loadAlerts();
  } catch {}
}

function quickAdd(name) { document.getElementById('stack-input').value = name; const vi = document.getElementById('stack-version-input'); if(vi) vi.value = ''; addStackItem(); }

async function trackerScan() {
  const btn = document.getElementById('btn-tracker-scan');
  btn.disabled = true;
  btn.textContent = 'Scanning NVD...';
  try {
    const r = await fetch(`${API}/api/tracker/scan`, { method: 'POST' });
    if (!r.ok) { const e = await r.json(); toast(e.detail, 'error'); return; }
    toast('NVD scan started. Alerts appear in ~30s.', 'success');
    setTimeout(loadAlerts, 30000);
  } catch { toast('Backend unreachable.', 'error'); }
  finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = `<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Scan Stack`;
    }, 4000);
  }
}

async function loadAlerts(sev = '') {
  try {
    const url = sev ? `${API}/api/tracker/alerts?severity=${sev}` : `${API}/api/tracker/alerts`;
    const r = await fetch(url);
    const data = await r.json();
    trackerAlerts = data.alerts || [];
    renderAlerts(trackerAlerts);
    // Stats
    const s = data.stats || {};
    document.getElementById('sev-critical').textContent = s.CRITICAL || 0;
    document.getElementById('sev-high').textContent = s.HIGH || 0;
    document.getElementById('sev-medium').textContent = s.MEDIUM || 0;
    document.getElementById('sev-low').textContent = s.LOW || 0;
  } catch {}
}

function renderAlerts(alerts) {
  const el = document.getElementById('tracker-alerts');
  if (!alerts.length) {
    el.innerHTML = `<div class="empty-state"><p>No alerts yet. Add technologies and click <strong>Scan Stack</strong>.</p></div>`;
    return;
  }
  el.innerHTML = alerts.map(a => {
    const inRadar = a.in_radar
      ? `<span class="badge-exploited" title="Seen in OSINT feeds">🔥 IN RADAR</span>` : '';
    const score = a.cvss_score ? `<span class="font-mono text-xs text-gray-400">CVSS ${a.cvss_score}</span>` : '';
    const pub = a.published ? formatDate(a.published) : '';
    return `
      <div class="alert-card ${a.severity || 'UNKNOWN'}">
        <div class="flex flex-wrap items-center gap-2 mb-1">
          <a href="https://nvd.nist.gov/vuln/detail/${a.cve_id}" target="_blank" class="badge-cve">${escHtml(a.cve_id)}</a>
          <span class="severity-badge ${a.severity || 'UNKNOWN'}">${a.severity || 'UNKNOWN'}</span>
          ${score}
          <span class="text-xs text-cyan-700 font-semibold">${escHtml(a.stack_item)}</span>
          ${inRadar}
          ${pub ? `<span class="text-xs text-gray-600">${pub}</span>` : ''}
        </div>
        <p class="text-xs text-gray-400 leading-relaxed">${escHtml((a.description || '').substring(0, 200))}${(a.description || '').length > 200 ? '…' : ''}</p>
      </div>`;
  }).join('');
}

function filterAlerts(btn) {
  document.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const sev = btn.dataset.sev;
  currentAlertSev = sev;
  loadAlerts(sev);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatDate(raw) {
  if (!raw) return '';
  try {
    return new Date(raw).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  } catch { return raw.substring(0, 10); }
}

// ══════════════════════════════════════════════════════════════════════════════
// THREAT MAP MODULE
// ══════════════════════════════════════════════════════════════════════════════

const SEV_COLORS = {CRITICAL:'#f43f5e',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#22c55e',UNKNOWN:'#6b7280'};
let currentMapSev = '';

function initMap() {
  if (threatMap) { refreshThreatMap(); return; }
  threatMap = L.map('threat-map', {zoomControl:true, attributionControl:true}).setView([20, 10], 2);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OSM', maxZoom: 18
  }).addTo(threatMap);
  loadThreatMap();
}

async function loadThreatMap(sev='') {
  const url = sev ? `${API}/api/threatmap/events?limit=200&severity=${sev}` : `${API}/api/threatmap/events?limit=200`;
  try {
    const [evRes, stRes] = await Promise.all([fetch(url), fetch(`${API}/api/threatmap/stats`)]);
    const evData = await evRes.json();
    const stData = await stRes.json();
    renderMapEvents(evData.events || []);
    renderMapStats(stData);
    renderTopCountries(evData.top_countries || []);
    renderLiveFeed(evData.events || []);
    renderAttackTypes(stData.top_attack_types || []);
  } catch(e) { toast('Map load error','error'); }
}

function renderMapEvents(events) {
  mapMarkers.forEach(m => threatMap.removeLayer(m));
  mapMarkers = [];
  events.forEach(ev => {
    const col = SEV_COLORS[ev.severity] || '#6b7280';
    const r = ev.severity==='CRITICAL'?10:ev.severity==='HIGH'?8:6;
    const circle = L.circleMarker([ev.lat, ev.lon], {
      radius: r, color: col, fillColor: col, fillOpacity: 0.6,
      weight: 1, opacity: 0.9
    });
    circle.bindPopup(`
      <div style="font-family:Inter,sans-serif;min-width:180px">
        <div style="font-weight:700;color:${col};margin-bottom:6px">${ev.severity} — ${ev.attack_type||'Unknown'}</div>
        <div style="color:#94a3b8;font-size:12px">📍 ${ev.country}</div>
        ${ev.cve_id?`<div style="color:#f59e0b;font-size:11px;font-family:monospace;margin-top:4px">${ev.cve_id}</div>`:''}
        ${ev.source_ip?`<div style="color:#6b7280;font-size:11px">${ev.source_ip}</div>`:''}
        <div style="color:#4b5563;font-size:10px;margin-top:4px">${ev.timestamp?ev.timestamp.substring(0,16):''}</div>
      </div>`);
    circle.addTo(threatMap);
    mapMarkers.push(circle);
  });
}

function renderMapStats(s) {
  document.getElementById('map-stat-total').textContent = s.total_events||0;
  document.getElementById('map-stat-critical').textContent = s.critical||0;
  document.getElementById('map-stat-high').textContent = s.high||0;
  document.getElementById('map-stat-countries').textContent = s.countries_affected||0;
}

function renderTopCountries(countries) {
  const el = document.getElementById('top-countries-list');
  if (!countries.length) { el.innerHTML='<p class="text-xs text-gray-600 text-center py-4">No data</p>'; return; }
  const max = countries[0]?.count || 1;
  el.innerHTML = countries.map((c,i) => `
    <div class="country-rank-item">
      <span style="font-size:11px;color:#6b7280;width:16px">${i+1}</span>
      <div style="flex:1">
        <div style="font-size:12px;font-weight:600;color:#e2e8f0;margin-bottom:3px">${escHtml(c.country)} <span style="color:#f43f5e;font-size:10px">${c.critical>0?'🔴':''}</span></div>
        <div class="country-rank-bar" style="width:${Math.round((c.count/max)*100)}%"></div>
      </div>
      <span style="font-size:11px;color:#f97316;font-weight:700;min-width:24px;text-align:right">${c.count}</span>
    </div>`).join('');
}

function renderLiveFeed(events) {
  const el = document.getElementById('map-live-feed');
  const recent = events.slice(0,20);
  if (!recent.length) { el.innerHTML='<p class="text-xs text-gray-600 text-center">No events</p>'; return; }
  el.innerHTML = recent.map(e => `
    <div class="live-event">
      <div class="live-event-dot ${e.severity}"></div>
      <div>
        <div style="color:#e2e8f0;font-weight:600">${escHtml(e.attack_type||'Attack')} · ${escHtml(e.country)}</div>
        ${e.cve_id?`<div style="color:#f59e0b;font-family:monospace;font-size:10px">${e.cve_id}</div>`:''}
      </div>
    </div>`).join('');
}

function renderAttackTypes(types) {
  const el = document.getElementById('attack-types-bar');
  if (!types.length) return;
  const max = types[0]?.cnt || 1;
  el.innerHTML = types.map(t => `
    <div class="attack-bar-item">
      <span style="font-size:11px;color:#94a3b8;width:130px;white-space:nowrap">${escHtml(t.attack_type)}</span>
      <div style="flex:1"><div class="attack-bar-fill" style="width:${Math.round((t.cnt/max)*100)}%"></div></div>
      <span style="font-size:11px;color:#6b7280;min-width:24px;text-align:right">${t.cnt}</span>
    </div>`).join('');
}

function filterMapSev(btn) {
  document.querySelectorAll('.map-sev-filter').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  currentMapSev = btn.dataset.sev;
  loadThreatMap(currentMapSev);
}

function refreshThreatMap() { loadThreatMap(currentMapSev); }

// ══════════════════════════════════════════════════════════════════════════════
// SCHEDULER MODULE
// ══════════════════════════════════════════════════════════════════════════════

async function loadScheduler() {
  try {
    const r = await fetch(`${API}/api/scheduler/status`);
    const data = await r.json();
    const running = data.scheduler_running;
    const dot = document.getElementById('sched-status-dot');
    const txt = document.getElementById('sched-status-text');
    dot.style.background = running ? '#22c55e' : '#6b7280';
    txt.textContent = running ? 'RUNNING' : 'STOPPED';
    txt.style.color = running ? '#22c55e' : '#6b7280';
    const badge = document.getElementById('scheduler-badge');
    if (badge) { badge.classList.toggle('hidden', !running); badge.classList.toggle('flex', running); }
    renderJobs(data.jobs||[]);
    renderSchedLog(data.log||[]);
  } catch { toast('Cannot reach scheduler','error'); }
}

function renderJobs(jobs) {
  const el = document.getElementById('jobs-table');
  if (!jobs.length) { el.innerHTML='<p class="text-xs text-gray-600 text-center">No jobs found</p>'; return; }
  const icons = {radar_refresh:'🔄',nvd_stack_scan:'🛡️'};
  const intervals = {radar_refresh:'Every 6 hours',nvd_stack_scan:'Every 12 hours'};
  el.innerHTML = jobs.map(j => `
    <div class="job-card">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="job-indicator active"></div>
          <div>
            <div style="font-weight:600;color:#e2e8f0">${icons[j.id]||'⚙️'} ${escHtml(j.name)}</div>
            <div style="font-size:11px;color:#6b7280">${intervals[j.id]||''}</div>
          </div>
        </div>
        <div style="text-align:right">
          <div style="font-size:10px;color:#4b5563;text-transform:uppercase;letter-spacing:.08em">Next Run</div>
          <div style="font-size:12px;color:#38bdf8;font-family:monospace">${j.next_run ? new Date(j.next_run).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'}) : '—'}</div>
        </div>
      </div>
    </div>`).join('');
}

function renderSchedLog(logs) {
  const el = document.getElementById('sched-log');
  if (!logs.length) { el.innerHTML='<p class="text-xs text-gray-600 text-center py-4">No executions yet.</p>'; return; }
  const names = {radar_refresh:'Radar Refresh',nvd_stack_scan:'NVD Stack Scan'};
  el.innerHTML = logs.map(l => `
    <div class="log-row ${l.status||'ok'}">
      <span style="font-size:16px">${l.status==='error'?'❌':'✅'}</span>
      <div style="flex:1">
        <div style="font-weight:600;color:#e2e8f0;font-size:13px">${names[l.job]||l.job}</div>
        <div style="font-size:11px;color:#6b7280">${escHtml(l.detail||'')}</div>
      </div>
      <div style="font-size:11px;color:#4b5563;font-family:monospace;white-space:nowrap">${l.last_run?l.last_run.substring(0,16):''}</div>
    </div>`).join('');
}

async function triggerJob(jobId) {
  const btn = document.getElementById(`btn-trigger-${jobId==='radar_refresh'?'radar':'nvd'}`);
  if(btn){btn.disabled=true;btn.textContent='Running...'}
  try {
    const r = await fetch(`${API}/api/scheduler/trigger/${jobId}`, {method:'POST'});
    const d = await r.json();
    toast(d.message||'Job triggered','success');
    setTimeout(loadScheduler, 3000);
  } catch { toast('Error triggering job','error'); }
  finally { setTimeout(()=>{ if(btn){btn.disabled=false;btn.innerHTML=jobId==='radar_refresh'?'<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Run Radar Refresh Now':'<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Run NVD Stack Scan Now'} },3000); }
}

// ══════════════════════════════════════════════════════════════════════════════
// SBOM SCAN HISTORY
// ══════════════════════════════════════════════════════════════════════════════

async function loadScanHistory() {
  try {
    const r = await fetch(`${API}/api/scanner/history`);
    const d = await r.json();
    const el = document.getElementById('scan-history');
    if (!d.history?.length) { el.innerHTML='<p class="text-xs text-gray-600 text-center py-4">No scans yet.</p>'; return; }
    const parserColors = {NPM:'#f97316',pip:'#38bdf8',Dockerfile:'#06b6d4',Composer:'#a78bfa',Cargo:'#fb7185','Go Modules':'#10b981',Gemfile:'#f59e0b',Maven:'#fbbf24'};
    el.innerHTML = d.history.map(s => {
      const col = parserColors[s.parser]||'#6b7280';
      return `<div class="history-row">
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;border:1px solid ${col}33;color:${col};background:${col}11">${escHtml(s.parser)}</span>
          <span style="font-size:13px;color:#e2e8f0;font-weight:500">${escHtml(s.filename)}</span>
        </div>
        <div style="display:flex;gap:16px;align-items:center">
          <span style="font-size:11px;color:#6b7280">${s.packages_found} pkgs</span>
          <span style="font-size:11px;font-weight:700;color:${s.vulns_found>0?'#f97316':'#10b981'}">${s.vulns_found} vulns</span>
          <span style="font-size:10px;color:#4b5563;font-family:monospace">${s.scanned_at?s.scanned_at.substring(0,16):''}</span>
        </div>
      </div>`;
    }).join('');
  } catch {}
}

// ══════════════════════════════════════════════════════════════════════════════
// DARK WEB MONITOR — Enhanced
// ══════════════════════════════════════════════════════════════════════════════

let dwAllFindings = [];
let dwCurrentRisk = '';
let dwCurrentType = '';
let dwScanProgressTimer = null;

const DW_PROGRESS_STEPS = [
  'Connecting to threat feeds',
  'Querying paste intelligence...',
  'Checking CISA KEV database...',
  'Scanning Bleeping Computer feed...',
  'Scanning SANS ISC feed...',
  'Scanning The Hacker News...',
  'Scanning Krebs on Security...',
  'Scanning CISA Alerts...',
  'Correlating ransomware signatures...',
  'Deduplicating findings...',
  'Building risk scores...',
  'Analysis complete ✓',
];

async function loadDarkwebTargets() {
  try {
    const r = await fetch(`${API}/api/darkweb/targets`);
    const d = await r.json();
    const el = document.getElementById('darkweb-targets');
    if (!d.targets?.length) {
      el.innerHTML = '<p class="text-xs text-gray-600 text-center mt-2">No keywords monitored yet.</p>';
      return;
    }
    el.innerHTML = d.targets.map(t => `
      <div class="dw-target-tag">
        <span>🔍 ${escHtml(t.keyword)}</span>
        <button class="remove-btn" onclick="removeDarkwebTarget('${escHtml(t.keyword)}')">×</button>
      </div>`).join('');
  } catch {}
}

async function addDarkwebTarget() {
  const inp = document.getElementById('darkweb-input');
  const kw = inp.value.trim();
  if (!kw) return;
  try {
    const r = await fetch(`${API}/api/darkweb/targets`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({keyword: kw})
    });
    if (!r.ok) { const e = await r.json(); toast(e.detail, 'error'); return; }
    inp.value = '';
    toast(`Now monitoring "${kw}"`, 'success');
    loadDarkwebTargets();
  } catch { toast('Backend unreachable', 'error'); }
}

async function removeDarkwebTarget(kw) {
  await fetch(`${API}/api/darkweb/targets/${encodeURIComponent(kw)}`, {method: 'DELETE'});
  toast(`Removed "${kw}"`, '');
  loadDarkwebTargets();
}

function quickAddDarkweb(kw) {
  document.getElementById('darkweb-input').value = kw;
  addDarkwebTarget();
}

async function darkwebScan() {
  const btn = document.getElementById('btn-darkweb-scan');
  const overlay = document.getElementById('dw-scan-overlay');
  btn.disabled = true;
  btn.classList.add('scanning');
  btn.innerHTML = `<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="10" stroke-width="1.5"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 6v6l4 2"/></svg> Scanning...`;

  overlay.classList.remove('hidden');
  let stepIdx = 0;
  const progressEl = document.getElementById('dw-scan-progress');
  dwScanProgressTimer = setInterval(() => {
    if (stepIdx < DW_PROGRESS_STEPS.length - 1) {
      stepIdx++;
      if (progressEl) progressEl.textContent = DW_PROGRESS_STEPS[stepIdx];
    }
  }, 2800);

  try {
    const r = await fetch(`${API}/api/darkweb/scan`, {method: 'POST'});
    if (!r.ok) {
      const e = await r.json();
      toast(e.detail || 'Scan failed', 'error');
      _dwScanCleanup(btn, overlay);
      return;
    }
    toast('Dark web scan initiated — results in ~30s', 'success');
    setTimeout(() => {
      loadDarkwebFindings();
      _dwScanCleanup(btn, overlay);
    }, 30000);
  } catch {
    toast('Backend unreachable', 'error');
    _dwScanCleanup(btn, overlay);
  }
}

function _dwScanCleanup(btn, overlay) {
  clearInterval(dwScanProgressTimer);
  if (overlay) overlay.classList.add('hidden');
  btn.disabled = false;
  btn.classList.remove('scanning');
  btn.innerHTML = `<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Scan Dark Web`;
}

async function loadDarkwebFindings() {
  try {
    const params = new URLSearchParams();
    if (dwCurrentRisk) params.set('risk', dwCurrentRisk);
    if (dwCurrentType) params.set('type', dwCurrentType);
    const r = await fetch(`${API}/api/darkweb/findings?${params}`);
    const d = await r.json();

    document.getElementById('dw-stat-critical').textContent = d.stats?.critical || 0;
    document.getElementById('dw-stat-high').textContent = d.stats?.high || 0;
    document.getElementById('dw-stat-total').textContent = d.stats?.total || 0;
    document.getElementById('dw-stat-kev').textContent = d.stats?.kev || 0;
    document.getElementById('dw-stat-intel').textContent = d.stats?.intel || 0;
    document.getElementById('dw-stat-ransomware').textContent = d.stats?.ransomware_mentions || 0;

    dwAllFindings = d.findings || [];

    const lastScanEl = document.getElementById('dw-last-scan');
    if (lastScanEl && dwAllFindings.length) {
      lastScanEl.textContent = `Updated ${new Date().toLocaleTimeString('en-GB', {hour:'2-digit', minute:'2-digit'})}`;
    }

    renderDarkwebFindings(dwAllFindings);
    renderDWSourceBreakdown(dwAllFindings);
  } catch {}
}

function renderDarkwebFindings(findings) {
  const el = document.getElementById('darkweb-findings');
  const searchQ = (document.getElementById('dw-findings-search')?.value || '').toLowerCase();

  let filtered = findings;
  if (searchQ) {
    filtered = filtered.filter(f =>
      (f.title || '').toLowerCase().includes(searchQ) ||
      (f.source || '').toLowerCase().includes(searchQ) ||
      (f.matched_keywords || []).some(k => k.toLowerCase().includes(searchQ)) ||
      (f.cves || []).some(c => c.toLowerCase().includes(searchQ))
    );
  }

  if (!filtered.length) {
    el.innerHTML = `<div class="dw-empty"><div class="dw-empty-icon">🕸️</div><p>${findings.length ? 'No findings match your filters.' : 'Add keywords and click <strong>Scan Dark Web</strong>'}</p><p class="text-xs mt-1">Monitors paste sites, CISA KEV &amp; 6 threat intelligence feeds</p></div>`;
    return;
  }

  el.innerHTML = filtered.map(f => {
    const typeBadge = f.type === 'kev'
      ? '<span class="dw-kev-badge">🔴 CISA KEV</span>'
      : f.type === 'intel'
        ? '<span class="dw-intel-badge">📡 Intel</span>'
        : '<span class="dw-paste-badge">📋 Paste</span>';

    const kws = (f.matched_keywords || []).filter(k => k).map(k =>
      `<span class="badge-cve" style="border-color:rgba(139,92,246,.3);color:#a78bfa;background:rgba(139,92,246,.1)">${escHtml(k)}</span>`
    ).join('');

    const cves = (f.cves || []).filter(c => c).map(c =>
      `<a href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank" class="badge-cve">${escHtml(c)}</a>`
    ).join('');

    const groups = (f.ransomware_groups || []).map(g =>
      `<span class="dw-ransomware-tag">⚠ ${escHtml(g)}</span>`
    ).join('');

    const kevDue = f.due_date ? `<span style="font-size:.68rem;color:#6b7280;font-family:'JetBrains Mono',monospace">Due: ${f.due_date}</span>` : '';
    const pubDate = f.published ? `<span style="font-size:.65rem;color:#374151">${formatDate(f.published)}</span>` : '';

    return `<div class="dw-finding ${f.risk}">
      <div class="flex flex-wrap items-center gap-2 mb-2">
        <span class="severity-badge ${f.risk}">${f.risk}</span>
        ${typeBadge}
        <span style="font-size:11px;color:#a78bfa;font-weight:600">${escHtml(f.source)}</span>
        ${pubDate}
        ${kws}${cves}${groups}${kevDue}
      </div>
      <p class="text-sm text-gray-300 leading-relaxed">${escHtml(f.title || '')}</p>
      ${f.link ? `<a href="${escHtml(f.link)}" target="_blank" style="font-size:11px;color:#4b5563;text-decoration:underline;display:block;margin-top:6px;word-break:break-all">${escHtml(f.link.substring(0,90))}${f.link.length > 90 ? '…' : ''}</a>` : ''}
    </div>`;
  }).join('');
}

function renderDWSourceBreakdown(findings) {
  const el = document.getElementById('dw-source-breakdown');
  if (!el) return;
  if (!findings.length) {
    el.innerHTML = '<div class="text-xs text-gray-600 text-center py-3">Run a scan to see source breakdown</div>';
    return;
  }
  const sourceCounts = {};
  findings.forEach(f => { sourceCounts[f.source] = (sourceCounts[f.source] || 0) + 1; });
  const sorted = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]);
  const max = sorted[0]?.[1] || 1;
  el.innerHTML = sorted.map(([src, cnt]) => `
    <div>
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span style="font-size:.72rem;color:#9ca3af;font-weight:500">${escHtml(src)}</span>
        <span style="font-size:.72rem;color:#a78bfa;font-family:'JetBrains Mono',monospace">${cnt}</span>
      </div>
      <div class="dw-source-bar">
        <div class="dw-source-fill" style="width:${Math.round((cnt/max)*100)}%"></div>
      </div>
    </div>`).join('');
}

function filterDarkwebRisk(btn) {
  document.querySelectorAll('.dw-risk-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  dwCurrentRisk = btn.dataset.risk;
  loadDarkwebFindings();
}

function filterDarkwebType(btn) {
  document.querySelectorAll('.dw-type-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  dwCurrentType = btn.dataset.type;
  loadDarkwebFindings();
}

function filterDarkwebFindings() {
  renderDarkwebFindings(dwAllFindings);
}

async function runBreachCheck() {
  const inp = document.getElementById('breach-check-input');
  const target = inp.value.trim();
  if (!target) return;
  const btn = document.getElementById('btn-breach-check');
  const resultEl = document.getElementById('breach-check-result');
  btn.disabled = true;
  btn.textContent = 'Checking...';
  resultEl.classList.add('hidden');
  try {
    const r = await fetch(`${API}/api/darkweb/breach-check`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target})
    });
    const d = await r.json();
    resultEl.classList.remove('hidden');

    const kevBlock = d.kev_count > 0
      ? `<div style="margin-top:8px">
          <div style="font-size:.72rem;font-weight:700;color:#f43f5e;margin-bottom:4px">⚠ ${d.kev_count} CISA KEV Match${d.kev_count > 1 ? 'es' : ''}</div>
          ${(d.kev_hits || []).map(h => `<div class="dw-breach-kev-item">
            <span style="font-family:'JetBrains Mono',monospace;color:#fda4af">${escHtml(h.cve)}</span>
            <span style="color:#6b7280">${escHtml((h.name||'').substring(0,50))}</span>
          </div>`).join('')}
        </div>`
      : `<div style="color:#22c55e;font-size:.78rem;margin-top:6px">✓ No direct KEV matches found</div>`;

    resultEl.innerHTML = `
      <div style="font-weight:700;color:#e2e8f0;margin-bottom:6px">🔍 ${escHtml(d.target)}</div>
      <div style="font-size:.72rem;color:#6b7280;margin-bottom:4px">Type: ${d.type} · Domain: ${escHtml(d.domain)}</div>
      ${kevBlock}
      <div style="margin-top:10px;display:flex;flex-direction:column;gap:4px">
        <a href="${escHtml(d.hibp_url)}" target="_blank" style="font-size:.72rem;color:#4b5563;text-decoration:underline">→ Check HaveIBeenPwned</a>
        <a href="${escHtml(d.shodan_url)}" target="_blank" style="font-size:.72rem;color:#4b5563;text-decoration:underline">→ Shodan Search</a>
        <a href="${escHtml(d.osint_url)}" target="_blank" style="font-size:.72rem;color:#4b5563;text-decoration:underline">→ Censys OSINT</a>
      </div>`;
  } catch { toast('Breach check failed', 'error'); }
  finally { btn.disabled = false; btn.textContent = 'Check'; }
}

function exportDarkwebCSV() {
  if (!dwAllFindings.length) { toast('No findings to export', ''); return; }
  const header = ['Risk', 'Type', 'Source', 'Title', 'CVEs', 'Keywords', 'Published', 'Link'];
  const rows = dwAllFindings.map(f => [
    f.risk, f.type, f.source,
    `"${(f.title || '').replace(/"/g, '""')}"`,
    (f.cves || []).join(';'),
    (f.matched_keywords || []).join(';'),
    f.published || '',
    f.link || ''
  ].join(','));
  const csv = [header.join(','), ...rows].join('\n');
  const blob = new Blob([csv], {type: 'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `darkweb_findings_${new Date().toISOString().slice(0,10)}.csv`;
  a.click(); URL.revokeObjectURL(url);
  toast('CSV exported', 'success');
}



// ══════════════════════════════════════════════════════════════════════════════
// SUPPLY CHAIN DETECTOR
// ══════════════════════════════════════════════════════════════════════════════

function handleSCDrop(e) {
  e.preventDefault();
  document.getElementById('sc-drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) uploadSCFile(file);
}
function handleSCFile(e) { if(e.target.files[0]) uploadSCFile(e.target.files[0]); }

async function uploadSCFile(file) {
  const loading = document.getElementById('sc-loading');
  const results = document.getElementById('sc-results');
  loading.classList.remove('hidden'); results.classList.add('hidden');
  const form = new FormData();
  form.append('file', file);
  try {
    const r = await fetch(`${API}/api/supply-chain/analyze`, {method:'POST', body:form});
    if (!r.ok) { const e=await r.json(); toast(e.detail||'Scan failed','error'); return; }
    const d = await r.json();
    renderSCResults(d);
  } catch { toast('Cannot connect to backend','error'); }
  finally { loading.classList.add('hidden'); }
}

function renderSCResults(d) {
  const results = document.getElementById('sc-results');
  results.classList.remove('hidden');
  document.getElementById('sc-summary').innerHTML = `
    <div class="stat-card"><div class="stat-value" style="color:#f97316">${d.packages_checked}</div><div class="stat-label">Checked</div></div>
    <div class="stat-card"><div class="stat-value text-rose-400">${d.risky}</div><div class="stat-label">High Risk</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#f59e0b">${d.medium_risk}</div><div class="stat-label">Medium Risk</div></div>`;
  const el = document.getElementById('sc-findings');
  if (!d.findings?.length) { el.innerHTML='<div class="empty-state">No packages to display.</div>'; return; }
  el.innerHTML = d.findings.map(f => {
    const tsq = (f.typosquats||[]).map(t=>`<span style="font-size:11px;color:#f59e0b">⚠️ similar to <strong>${escHtml(t.similar_to)}</strong> (edit dist: ${t.edit_distance})</span>`).join('<br>');
    const reasons = (f.reasons||[]).map(r=>`<div style="font-size:11px;color:#94a3b8;margin-top:2px">${escHtml(r)}</div>`).join('');
    return `<div class="sc-card ${f.risk}">
      <div class="flex items-center gap-2 mb-2">
        <span class="font-mono font-bold text-white">${escHtml(f.name)}</span>
        <span class="risk-badge ${f.risk}">${f.risk}</span>
        <span style="font-size:11px;color:#4b5563">${escHtml(f.ecosystem)}</span>
        ${f.metadata?.latest ? `<span style="font-size:11px;color:#6b7280">v${escHtml(f.metadata.latest)}</span>` : ''}
      </div>
      ${tsq}${reasons}
    </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK PATH VISUALIZER
// ══════════════════════════════════════════════════════════════════════════════

async function loadAttackPath() {
  const loading=document.getElementById('ap-loading');
  const results=document.getElementById('ap-results');
  const empty=document.getElementById('ap-empty');
  loading.classList.remove('hidden'); results.classList.add('hidden'); empty.classList.add('hidden');
  try {
    const r = await fetch(`${API}/api/attack-path`);
    if (!r.ok) { const e=await r.json(); toast(e.detail,'error'); empty.classList.remove('hidden'); return; }
    const d = await r.json();
    renderAttackPath(d);
    results.classList.remove('hidden');
  } catch { toast('Error loading attack path','error'); empty.classList.remove('hidden'); }
  finally { loading.classList.add('hidden'); }
}

function renderAttackPath(d) {
  const riskColor = {CRITICAL:'#f43f5e',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#10b981'}[d.overall_risk]||'#6b7280';
  document.getElementById('ap-summary').innerHTML = `
    <div class="stat-card"><div class="stat-value" style="color:${riskColor}">${d.overall_risk}</div><div class="stat-label">Overall Risk</div></div>
    <div class="stat-card"><div class="stat-value text-rose-400">${d.total_techniques}</div><div class="stat-label">Techniques</div></div>
    <div class="stat-card"><div class="stat-value text-amber-400">${d.tactics_covered}</div><div class="stat-label">Tactics</div></div>
    <div class="stat-card"><div class="stat-value text-cyan-400">${d.stack_analyzed?.length||0}</div><div class="stat-label">Stack Items</div></div>`;

  document.getElementById('ap-killchain').innerHTML = (d.kill_chain||[]).map(stage => {
    const col = stage.tactic.color;
    const techs = stage.techniques.map(t => {
      const pct = Math.round(t.likelihood*100);
      return `<div class="technique-pill" style="border-color:${col}33;color:${col};background:${col}11" title="${(t.triggered_by||[]).join(', ')}">
        <div>
          <div>${escHtml(t.name)}</div>
          <div class="likelihood-bar" style="width:${pct}px;max-width:80px;background:${col};opacity:.7"></div>
        </div>
        <span style="font-size:10px;opacity:.7">${pct}%</span>
      </div>`;
    }).join('');
    return `<div class="killchain-stage">
      <div class="killchain-header" style="background:${col}15;color:${col}">
        <span style="width:8px;height:8px;border-radius:50%;background:${col};display:inline-block"></span>
        <span>${escHtml(stage.tactic.name)}</span>
        <span style="margin-left:auto;font-size:10px;opacity:.6">${stage.techniques.length} technique${stage.techniques.length!==1?'s':''}</span>
      </div>
      <div class="killchain-techniques">${techs}</div>
    </div>`;
  }).join('');

  document.getElementById('ap-high').innerHTML = (d.high_likelihood||[]).map(t => {
    const col = t.tactic_color||'#f43f5e';
    return `<div class="glass-card p-4">
      <div class="flex items-center gap-2 mb-1">
        <span style="font-size:11px;padding:2px 8px;border-radius:4px;border:1px solid ${col}33;color:${col};background:${col}11;font-weight:700">${escHtml(t.id)}</span>
        <span style="font-size:12px;color:#e2e8f0;font-weight:600">${escHtml(t.name)}</span>
      </div>
      <div style="font-size:11px;color:#6b7280">${escHtml(t.tactic_name)} · ${Math.round(t.likelihood*100)}% likelihood</div>
      <div style="font-size:10px;color:#4b5563;margin-top:4px">Triggered by: ${(t.triggered_by||[]).join(', ')}</div>
    </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════════════════════
// NIS2 COMPLIANCE ANALYZER (ENHANCED)
// ══════════════════════════════════════════════════════════════════════════════

let _nis2Data = null;
let _nis2Filter = 'all';

function initNIS2Tab() {
  // Show results if a previous analysis exists, otherwise show the CTA
  const hasData = !!_nis2Data;
  document.getElementById('nis2-results')?.classList.toggle('hidden', !hasData);
  document.getElementById('nis2-empty')?.classList.toggle('hidden', hasData);
}

async function runNIS2() {
  const loading=document.getElementById('nis2-loading');
  const results=document.getElementById('nis2-results');
  const empty=document.getElementById('nis2-empty');
  const btn=document.getElementById('btn-run-nis2');
  loading.classList.remove('hidden');
  results.classList.add('hidden');
  empty?.classList.add('hidden');
  if(btn){ btn.disabled=true; btn.textContent='Analyzing...'; }
  try {
    const r = await fetch(`${API}/api/compliance/nis2`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        has_mfa:     document.getElementById('nis2-mfa')?.checked||false,
        has_backups: document.getElementById('nis2-backup')?.checked||false,
        has_ir_plan: document.getElementById('nis2-ir')?.checked||false,
        has_encrypt: document.getElementById('nis2-encrypt')?.checked||false,
        has_siem:    document.getElementById('nis2-siem')?.checked||false,
        has_pentest: document.getElementById('nis2-pentest')?.checked||false,
        has_training:document.getElementById('nis2-training')?.checked||false,
        has_acl:     document.getElementById('nis2-acl')?.checked||false,
        has_vuln:    document.getElementById('nis2-vuln')?.checked||false,
        has_sbom:    document.getElementById('nis2-sbom')?.checked||false,
        has_risk:    document.getElementById('nis2-risk')?.checked||false,
        has_csirt:   document.getElementById('nis2-csirt')?.checked||false,
      })
    });
    if (!r.ok) {
      const err = await r.json().catch(()=>({detail:'Compliance analysis failed'}));
      toast(err.detail || 'Compliance analysis failed', 'error');
      return;
    }
    const d = await r.json();
    // Supplement backend data with extra controls from UI
    _nis2Data = enrichNIS2Data(d);
    renderNIS2(_nis2Data);
    results.classList.remove('hidden');
  } catch(e) {
    toast('Cannot connect to backend. Is the server running on port 8000?', 'error');
    console.error('[NIS2]', e);
    if(!_nis2Data) empty?.classList.remove('hidden');
  } finally {
    loading.classList.add('hidden');
    if(btn){ btn.disabled=false; btn.innerHTML='<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Run Analysis'; }
  }
}

/** Enrich backend response with extra control signals from checkboxes */
function enrichNIS2Data(d) {
  const extraControls = {
    has_encrypt: document.getElementById('nis2-encrypt')?.checked,
    has_siem:    document.getElementById('nis2-siem')?.checked,
    has_pentest: document.getElementById('nis2-pentest')?.checked,
    has_training:document.getElementById('nis2-training')?.checked,
    has_acl:     document.getElementById('nis2-acl')?.checked,
    has_vuln:    document.getElementById('nis2-vuln')?.checked,
    has_sbom:    document.getElementById('nis2-sbom')?.checked,
    has_risk:    document.getElementById('nis2-risk')?.checked,
    has_csirt:   document.getElementById('nis2-csirt')?.checked,
  };

  // Control → article mapping (for client-side enhancement)
  const ctrlMap = {
    has_encrypt: ['encryption','tls_policy','key_management'],
    has_siem:    ['siem','log_monitoring'],
    has_pentest: ['penetration_testing','security_audits'],
    has_training:['security_training'],
    has_acl:     ['access_control','least_privilege','identity_management'],
    has_vuln:    ['vulnerability_scanning'],
    has_sbom:    ['sbom','dependency_scanning','supplier_assessment'],
    has_risk:    ['risk_assessment','security_policy','asset_management'],
    has_csirt:   ['csirt_contact'],
  };

  // Build a set of present controls from extra UI flags
  const presentExtras = new Set();
  for(const [flag, ctrls] of Object.entries(ctrlMap)) {
    if(extraControls[flag]) ctrls.forEach(c => presentExtras.add(c));
  }

  // Update article scores to reflect extra controls
  const articles = (d.articles||[]).map(a => {
    const newPresent = a.controls.filter(c =>
      presentExtras.has(c) || a.missing_controls.indexOf(c) === -1
    );
    const stillMissing = a.controls.filter(c => !presentExtras.has(c) && a.missing_controls.includes(c));
    const pct = a.controls.length === 0 ? 100 : Math.min(100, Math.round((newPresent.length / a.controls.length) * 100));
    const status = pct >= 70 ? 'COMPLIANT' : pct >= 40 ? 'PARTIAL' : 'GAP';
    const color = status === 'COMPLIANT' ? '#10b981' : status === 'PARTIAL' ? '#f59e0b' : '#f43f5e';
    return { ...a, score: pct, status, color, missing_controls: stillMissing };
  });

  // Recompute overall
  const totalWeight = articles.reduce((s,a) => s + (a.weight||1), 0);
  const weightedScore = articles.reduce((s,a) => s + a.score * (a.weight||1) / 100, 0);
  const overall_score = Math.min(100, Math.round((weightedScore / totalWeight) * 100));
  const overall_status = overall_score >= 70 ? 'LARGELY COMPLIANT' : overall_score >= 40 ? 'PARTIAL COMPLIANCE' : 'SIGNIFICANT GAPS';
  const overall_color = overall_score >= 70 ? '#10b981' : overall_score >= 40 ? '#f59e0b' : '#f43f5e';
  const gaps = articles.filter(a => a.status === 'GAP');
  const partials = articles.filter(a => a.status === 'PARTIAL');

  return {
    ...d, articles,
    overall_score, overall_status, overall_color,
    critical_gaps: gaps.length,
    partial_gaps: partials.length,
    compliant_articles: articles.filter(a => a.status === 'COMPLIANT').length,
    top_gaps: [...gaps].sort((a,b) => (b.weight||1) - (a.weight||1)).slice(0,5),
  };
}

function renderNIS2(d) {
  const entityType = document.querySelector('input[name="nis2-entity"]:checked')?.value || 'essential';
  const entityLabel = entityType === 'essential' ? '⚡ Essential Entity' : '🏭 Important Entity';
  const score = d.overall_score;
  const color = d.overall_color;

  // ── Score Ring animation ──
  const ring = document.getElementById('nis2-ring-circle');
  const circumference = 326.7;
  const offset = circumference - (score / 100) * circumference;
  if(ring) {
    ring.style.strokeDashoffset = offset;
    ring.style.stroke = color;
  }
  const scoreDisplay = document.getElementById('nis2-score-display');
  const statusLabel = document.getElementById('nis2-status-label');
  if(scoreDisplay) scoreDisplay.style.color = color;
  // Animate count-up
  if(scoreDisplay) animateCount(scoreDisplay, score, '%');
  if(statusLabel) statusLabel.textContent = d.overall_status;

  // ── Hero stats ──
  document.getElementById('nis2-stat-compliant').textContent = d.compliant_articles ?? '—';
  document.getElementById('nis2-stat-partial').textContent = d.partial_gaps ?? '—';
  document.getElementById('nis2-stat-gap').textContent = d.critical_gaps ?? '—';
  document.getElementById('nis2-stat-cves').textContent = d.cve_count ?? '—';
  document.getElementById('nis2-entity-label').textContent = entityLabel;

  // ── Hero bar ──
  const barFill = document.getElementById('nis2-hero-bar-fill');
  if(barFill) setTimeout(() => { barFill.style.width = score + '%'; }, 100);

  // ── Top Gaps Alert ──
  const gapBanner = document.getElementById('nis2-top-gaps');
  const gapList   = document.getElementById('nis2-top-gaps-list');
  if(d.top_gaps?.length && gapBanner && gapList) {
    gapBanner.classList.remove('hidden');
    gapList.innerHTML = d.top_gaps.map(g => `
      <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(244,63,94,.1)">
        <span style="font-size:10px;font-weight:700;color:#f43f5e;background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.2);padding:2px 8px;border-radius:4px;white-space:nowrap">${escHtml(g.article)}</span>
        <span style="font-size:12px;font-weight:600;color:#e2e8f0">${escHtml(g.title)}</span>
        <span style="margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;color:#f43f5e">${g.score}%</span>
      </div>`).join('');
  } else if(gapBanner) gapBanner.classList.add('hidden');

  // ── Articles ──
  _renderNIS2Articles(d.articles||[]);

  // ── Remediation Roadmap ──
  renderNIS2Roadmap(d);
}

function _renderNIS2Articles(articles) {
  const filtered = _nis2Filter === 'all' ? articles : articles.filter(a => a.status === _nis2Filter);
  const el = document.getElementById('nis2-articles');
  if(!filtered.length) {
    el.innerHTML = '<div class="empty-state"><p>No articles match this filter.</p></div>';
    return;
  }
  el.innerHTML = filtered.map(a => {
    const presentControls = a.controls.filter(c => !a.missing_controls.includes(c));
    const presentPills = presentControls.map(c =>
      `<span class="nis2-present-pill">✓ ${escHtml(c)}</span>`
    ).join('');
    const missingPills = (a.missing_controls||[]).map(c =>
      `<span class="nis2-missing-pill">✗ ${escHtml(c)}</span>`
    ).join('');
    const statusIcon = a.status === 'COMPLIANT' ? '✅' : a.status === 'PARTIAL' ? '⚠️' : '❌';
    return `
    <div class="nis2-article" style="border-left:3px solid ${a.color}">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:10px">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-size:10px;font-weight:800;color:${a.color};text-transform:uppercase;letter-spacing:.1em;background:${a.color}15;border:1px solid ${a.color}33;padding:2px 8px;border-radius:4px">${escHtml(a.article)}</span>
            <span style="font-size:13px;font-weight:600;color:#e2e8f0">${escHtml(a.title)}</span>
          </div>
          <p style="font-size:11px;color:#6b7280;margin-top:6px;line-height:1.5">${escHtml(a.description)}</p>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0">
          <span class="nis2-score" style="color:${a.color}">${a.score}%</span>
          <span class="severity-badge ${a.status==='COMPLIANT'?'LOW':a.status==='PARTIAL'?'MEDIUM':'CRITICAL'}">${statusIcon} ${a.status}</span>
        </div>
      </div>
      <div style="height:5px;border-radius:3px;background:rgba(255,255,255,.05);margin-bottom:10px;overflow:hidden">
        <div class="nis2-bar" style="width:${a.score}%;background:${a.color}"></div>
      </div>
      ${presentPills || missingPills ? `
      <div style="display:flex;flex-wrap:wrap;gap:5px">
        ${presentPills}${missingPills}
      </div>` : ''}
    </div>`;
  }).join('');
}

function filterNIS2Articles(btn) {
  document.querySelectorAll('.nis2-art-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  _nis2Filter = btn.dataset.filter;
  if(_nis2Data) _renderNIS2Articles(_nis2Data.articles||[]);
}

function renderNIS2Roadmap(d) {
  const el = document.getElementById('nis2-roadmap');
  const gaps = (d.articles||[]).filter(a => a.status !== 'COMPLIANT');

  if(!gaps.length) {
    el.innerHTML = `<div class="empty-state" style="padding:20px;text-align:center;color:#10b981;font-size:.85rem">🎉 All articles compliant!</div>`;
    return;
  }

  // Sort by status (GAP first) then weight
  const sorted = [...gaps].sort((a,b) => {
    const pri = {GAP:0,PARTIAL:1}; return (pri[a.status]??2) - (pri[b.status]??2) || (b.weight||1) - (a.weight||1);
  });

  el.innerHTML = sorted.slice(0,6).map((a, i) => {
    const priorityClass = a.status === 'GAP' ? 'priority-high' : i < 3 ? 'priority-medium' : 'priority-low';
    const priorityLabel = a.status === 'GAP' ? 'High' : i < 3 ? 'Medium' : 'Low';
    const topMissing = (a.missing_controls||[]).slice(0,2);
    return `
    <div class="nis2-roadmap-item ${priorityClass}">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <span style="font-size:10px;font-weight:700;color:#94a3b8">${escHtml(a.article)}</span>
        <span class="nis2-priority-badge">${priorityLabel}</span>
      </div>
      <div style="font-size:12px;font-weight:600;color:#e2e8f0;margin-bottom:4px">${escHtml(a.title)}</div>
      ${topMissing.length ? `<div style="font-size:10px;color:#6b7280">Implement: ${topMissing.map(c=>`<strong style="color:#94a3b8">${escHtml(c)}</strong>`).join(', ')}</div>` : ''}
    </div>`;
  }).join('');
}

function animateCount(el, target, suffix = '') {
  let current = 0;
  const step = Math.ceil(target / 30);
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current + suffix;
    if(current >= target) clearInterval(timer);
  }, 30);
}

function exportNIS2Report() {
  if(!_nis2Data) { toast('Run analysis first','error'); return; }
  const d = _nis2Data;
  const entityType = document.querySelector('input[name="nis2-entity"]:checked')?.value || 'essential';
  const lines = [
    `NIS2 COMPLIANCE REPORT — ${new Date().toLocaleDateString('en-GB')}`,
    `Entity Type: ${entityType === 'essential' ? 'Essential Entity' : 'Important Entity'}`,
    `Overall Score: ${d.overall_score}% — ${d.overall_status}`,
    `Compliant: ${d.compliant_articles} | Partial: ${d.partial_gaps} | Gaps: ${d.critical_gaps}`,
    `CVEs analyzed: ${d.cve_count ?? 0}`,
    '',
    '── ARTICLE BREAKDOWN ──',
    ...(d.articles||[]).map(a =>
      `${a.article} | ${a.title} | ${a.score}% | ${a.status}` +
      (a.missing_controls?.length ? ` | Missing: ${a.missing_controls.join(', ')}` : '')
    ),
    '',
    '── TOP GAPS ──',
    ...(d.top_gaps||[]).map(g => `${g.article} — ${g.title} (${g.score}%)`),
  ];
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `nis2-report-${Date.now()}.txt`;
  a.click(); URL.revokeObjectURL(url);
  toast('Report exported', 'success');
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
(async function init() {
  await checkHealth();
  loadRadar(false);
  loadRadarStats();
  loadStack();
  loadAlerts();
  setInterval(checkHealth, 30000);
  setInterval(() => { if(document.getElementById('module-map')&&!document.getElementById('module-map').classList.contains('hidden')) loadThreatMap(currentMapSev); }, 60000);
})();
