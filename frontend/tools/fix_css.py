import re

replacements = {
    r'\.top-nav\b': '.home-nav',
    r'\.nav-inner\b': '.home-nav-inner',
    r'\.nav-logo\b': '.home-nav-logo',
    r'\.logo-radar\b': '.logo-spin',
    r'\.logo-threat\b': '.nav-brand-threat',
    r'\.logo-cc\b': '.nav-brand-cc',
    r'\.nav-right\b': '.home-nav-right',
    r'\.status-badge\b': '.nav-status-pill',
    r'\.status-dot\b': '.nav-status-dot',
    r'\.status-text\b': '.nav-status-text',
    r'\.nav-cta-btn\b': '.nav-launch-btn',

    r'\.hero\b': '.hero-section',
    r'\.hero-inner\b': '.hero-grid',
    r'\.hero-title\b': '.hero-h1',
    r'\.gradient-text\b': '.hero-gradient',
    r'\.hero-subtitle\b': '.hero-sub',
    r'\.hero-stats\b': '.hero-stats-row',
    r'\.hero-stat\b': '.hero-stat-pill',
    r'\.hero-stat-value\b': '.hsp-value',
    r'\.hero-stat-label\b': '.hsp-label',
    r'\.hero-stat-divider\b': '.hsp-sep',

    r'\.hero-actions\b': '.hero-ctas',
    r'\.btn-primary\b': '.cta-primary',
    r'\.btn-ghost\b': '.cta-ghost',

    r'\.hero-visual\b': '.hero-right',
    r'\.radar-container\b': '.radar-wrap',
    r'\.radar-ring\b': '.radar-ring',
    r'\.r1\b': '.rr1',
    r'\.r2\b': '.rr2',
    r'\.r3\b': '.rr3',
    r'\.r4\b': '.rr4',
    r'\.radar-sweep\b': '.radar-sweep-arm',
    r'\.radar-center\b': '.radar-center-dot',
    r'\.radar-center-core\b': '.radar-center-core',
    r'\.blip\b': '.rblip',
    r'\.b1\b': '.rb1',
    r'\.b2\b': '.rb2',
    r'\.b3\b': '.rb3',
    r'\.b4\b': '.rb4',
    r'\.b5\b': '.rb5',
    r'\.cve-tag\b': '.cve-float',
    r'\.tag1\b': '.cf1',
    r'\.tag2\b': '.cf2',
    r'\.tag3\b': '.cf3',
    r'\.crosshair-h\b': '.ch-h',
    r'\.crosshair-v\b': '.ch-v',

    r'\.hero-ticker\b': '.hero-ticker',
    r'\.ticker-label\b': '.ticker-lbl',
    r'\.ticker-wrap\b': '.ticker-wrap',
    r'\.ticker-content\b': '.ticker-inner',
    r'\.ticker-item\b': '.ti',

    r'\.features\b': '.modules-section',
    r'\.section-inner\b': '.section-wrap',
    r'\.section-header\b': '.section-head',
    r'\.section-eyebrow\b': '.section-eyebrow',
    r'\.section-title\b': '.section-h2',
    r'\.section-sub\b': '.section-desc',

    r'\.features-grid\b': '.modules-grid',
    r'\.feature-card\b': '.mod-card',
    r'\.card-cyan\b': '.mod-cyan',
    r'\.card-violet\b': '.mod-violet',
    r'\.card-emerald\b': '.mod-emerald',

    r'\.card-glow\b': '.mod-glow',
    r'\.cyan-glow\b': '.g-cyan',
    r'\.violet-glow\b': '.g-violet',
    r'\.emerald-glow\b': '.g-emerald',

    r'\.card-icon\b': '.mod-icon',
    r'\.cyan-icon\b': '.i-cyan',
    r'\.violet-icon\b': '.i-violet',
    r'\.emerald-icon\b': '.i-emerald',

    r'\.card-num\b': '.mod-num',
    r'\.card-title\b': '.mod-title',
    r'\.card-desc\b': '.mod-desc',

    r'\.card-badge\b': '.mod-badge',
    r'\.cyan-badge\b': '.b-cyan',
    r'\.violet-badge\b': '.b-violet',
    r'\.emerald-badge\b': '.b-emerald',

    r'\.card-arrow\b': '.mod-arrow',

    r'\.intel-preview\b': '.terminal-section',
    r'\.preview-terminal\b': '.terminal-box',
    r'\.terminal-bar\b': '.terminal-topbar',
    r'\.t-dot\b': '.tb-dot',
    r'\.red\b': '.td-red',
    r'\.yellow\b': '.td-yellow',
    r'\.green\b': '.td-green',
    r'\.t-title\b': '.tb-title',
    r'\.terminal-loading\b': '.term-loading',
    r'\.t-spinner\b': '.term-spinner',
    r'\.t-mono\b': '.term-mono',
    r'\.preview-cta\b': '.term-cta',

    r'\.site-footer\b': '.home-footer',
    r'\.footer-tags\b': '.footer-tags',
    r'\.f-tag\b': '.ftag',
    r'\.footer-note\b': '.footer-note',
    
    r'\.how-it-works\b': '.stats-banner',
    r'\.steps-grid\b': '.stats-grid',
    r'\.step\b': '.sban-item',
    r'\.step-number\b': '.sban-val',
    r'\.step h3\b': '.sban-lbl'
}

with open('home.css', 'r') as f:
    css = f.read()

for k, v in replacements.items():
    css = re.sub(k, v, css)

# add missing colors for modules
missing_colors = """
/* Missing Colors for Modules */
.mod-orange:hover { border-color: rgba(249, 115, 22, 0.5); box-shadow: 0 24px 70px rgba(249, 115, 22, 0.18); }
.g-orange { background: #f97316; }
.i-orange { background: rgba(249, 115, 22, 0.1); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.2); }
.b-orange { background: rgba(249, 115, 22, 0.1); border-color: rgba(249, 115, 22, 0.3); color: #f97316; }
.a-orange { color: rgba(249, 115, 22, 0.4); }
.mod-orange:hover .mod-arrow { color: #f97316; }

.mod-purple:hover { border-color: rgba(168, 85, 247, 0.5); box-shadow: 0 24px 70px rgba(168, 85, 247, 0.18); }
.g-purple { background: #a855f7; }
.i-purple { background: rgba(168, 85, 247, 0.1); color: #a855f7; border: 1px solid rgba(168, 85, 247, 0.2); }
.b-purple { background: rgba(168, 85, 247, 0.1); border-color: rgba(168, 85, 247, 0.3); color: #a855f7; }
.a-purple { color: rgba(168, 85, 247, 0.4); }
.mod-purple:hover .mod-arrow { color: #a855f7; }

.mod-amber:hover { border-color: rgba(245, 158, 11, 0.5); box-shadow: 0 24px 70px rgba(245, 158, 11, 0.18); }
.g-amber { background: #f59e0b; }
.i-amber { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.2); }
.b-amber { background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.3); color: #f59e0b; }
.a-amber { color: rgba(245, 158, 11, 0.4); }
.mod-amber:hover .mod-arrow { color: #f59e0b; }

.mod-rose:hover { border-color: rgba(244, 63, 94, 0.5); box-shadow: 0 24px 70px rgba(244, 63, 94, 0.18); }
.g-rose { background: #f43f5e; }
.i-rose { background: rgba(244, 63, 94, 0.1); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.2); }
.b-rose { background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.3); color: #f43f5e; }
.a-rose { color: rgba(244, 63, 94, 0.4); }
.mod-rose:hover .mod-arrow { color: #f43f5e; }

.mod-sky:hover { border-color: rgba(14, 165, 233, 0.5); box-shadow: 0 24px 70px rgba(14, 165, 233, 0.18); }
.g-sky { background: #0ea5e9; }
.i-sky { background: rgba(14, 165, 233, 0.1); color: #0ea5e9; border: 1px solid rgba(14, 165, 233, 0.2); }
.b-sky { background: rgba(14, 165, 233, 0.1); border-color: rgba(14, 165, 233, 0.3); color: #0ea5e9; }
.a-sky { color: rgba(14, 165, 233, 0.4); }
.mod-sky:hover .mod-arrow { color: #0ea5e9; }

.mod-teal:hover { border-color: rgba(20, 184, 166, 0.5); box-shadow: 0 24px 70px rgba(20, 184, 166, 0.18); }
.g-teal { background: #14b8a6; }
.i-teal { background: rgba(20, 184, 166, 0.1); color: #14b8a6; border: 1px solid rgba(20, 184, 166, 0.2); }
.b-teal { background: rgba(20, 184, 166, 0.1); border-color: rgba(20, 184, 166, 0.3); color: #14b8a6; }
.a-teal { color: rgba(20, 184, 166, 0.4); }
.mod-teal:hover .mod-arrow { color: #14b8a6; }

/* Custom Fixes */
.hero-left { display: flex; flex-direction: column; justify-content: center; }
.sban-div { width: 1px; height: 36px; background: rgba(6, 182, 212, 0.2); }
.stats-grid { display: flex; align-items: center; justify-content: center; gap: 40px; }
.sban-item { text-align: center; }
.sban-val { font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; }
.sban-val.cyan { color: var(--cyan); }
.sban-val.amber { color: var(--amber); }
.sban-val.emerald { color: var(--emerald); }
.sban-val.violet { color: var(--violet); }
.sban-lbl { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 4px; }
.stats-banner { padding: 40px 0; background: rgba(6, 182, 212, 0.025); border-top: 1px solid rgba(6, 182, 212, 0.08); border-bottom: 1px solid rgba(6, 182, 212, 0.08); }

.tb-live-pill { display: flex; align-items: center; gap: 6px; margin-left: auto; font-size: 0.65rem; font-weight: 800; color: #f43f5e; background: rgba(244, 63, 94, 0.1); padding: 4px 10px; border-radius: 20px; border: 1px solid rgba(244, 63, 94, 0.2); }
.tb-live-dot { width: 6px; height: 6px; border-radius: 50%; background: #f43f5e; animation: pulse-dot 2s infinite; }
"""

css += missing_colors

with open('home.css', 'w') as f:
    f.write(css)
