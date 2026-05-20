const API = 'http://localhost:8000/api';

// ── Canvas particle background ──────────────────────────────────────────────
(function initCanvas() {
  const canvas = document.getElementById('bg-canvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function createParticles() {
    particles = [];
    const count = Math.floor((W * H) / 18000);
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: Math.random() * 1.5 + 0.5,
        vx: (Math.random() - 0.5) * 0.25,
        vy: (Math.random() - 0.5) * 0.25,
        opacity: Math.random() * 0.5 + 0.1
      });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    // Grid
    ctx.strokeStyle = 'rgba(6,182,212,0.03)';
    ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
    for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(6,182,212,${p.opacity})`;
      ctx.fill();
    });

    requestAnimationFrame(draw);
  }

  resize();
  createParticles();
  draw();
  window.addEventListener('resize', () => { resize(); createParticles(); });
})();

// ── Footer year ──────────────────────────────────────────────────────────────
document.getElementById('footer-year').textContent = new Date().getFullYear();

// ── Live stats from API ──────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch(`${API}/radar/stats`);
    if (!res.ok) throw new Error();
    const data = await res.json();

    animateCount('hs-total', data.total_items || 0);
    animateCount('hs-cves', data.items_with_cves || 0);
    animateCount('hs-sources', (data.sources || []).length);

    document.getElementById('nav-status').textContent = 'SYSTEM ONLINE';
    document.querySelector('.status-dot').style.background = '#10b981';
  } catch {
    document.getElementById('hs-total').textContent = '—';
    document.getElementById('hs-cves').textContent = '—';
    document.getElementById('hs-sources').textContent = '—';
    document.getElementById('nav-status').textContent = 'OFFLINE';
    document.querySelector('.status-dot').style.background = '#f43f5e';
  }
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const dur = 1200, start = performance.now();
  function step(now) {
    const p = Math.min((now - start) / dur, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.floor(ease * target).toLocaleString();
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Feed preview ─────────────────────────────────────────────────────────────
async function loadFeedPreview() {
  const container = document.getElementById('feed-preview');
  try {
    const res = await fetch(`${API}/radar?limit=6`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    const items = (data.items || []).slice(0, 6);

    if (!items.length) {
      container.innerHTML = '<div class="terminal-loading"><span class="t-mono" style="color:#374151">No data yet — refresh the radar to fetch threats.</span></div>';
      return;
    }

    container.innerHTML = '';
    items.forEach((item, i) => {
      setTimeout(() => {
        const cves = (item.cves || []).slice(0, 2);
        const line = document.createElement('div');
        line.className = 'feed-line';
        line.innerHTML = `
          <span class="feed-src">${escHtml(item.source || 'FEED')}</span>
          <span class="feed-title">${escHtml(item.title || '')}</span>
          ${cves.map(c => `<span class="feed-cve">${escHtml(c)}</span>`).join('')}
        `;
        container.appendChild(line);
      }, i * 160);
    });
  } catch {
    container.innerHTML = `<div class="terminal-loading">
      <span class="t-mono" style="color:#374151">Backend offline — start the server to see live data.</span>
    </div>`;
  }
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── Init ─────────────────────────────────────────────────────────────────────
loadStats();
loadFeedPreview();
