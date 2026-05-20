import re

with open('index.html', 'r') as f:
    html = f.read()

replacements = {
    r'\bhome-nav\b': 'top-nav',
    r'\bhome-nav-inner\b': 'nav-inner',
    r'\bhome-nav-logo\b': 'nav-logo',
    r'\blogo-spin\b': 'logo-radar',
    r'\bnav-brand-threat\b': 'logo-threat',
    r'\bnav-brand-cc\b': 'logo-cc',
    r'\bhome-nav-right\b': 'nav-right',
    r'\bnav-status-pill\b': 'status-badge',
    r'\bnav-status-dot\b': 'status-dot',
    r'\bnav-status-text\b': 'status-text',
    r'\bnav-launch-btn\b': 'nav-cta-btn',

    r'\bhero-section\b': 'hero',
    r'\bhero-grid\b': 'hero-inner',
    r'\bhero-eyebrow\b': 'hero-eyebrow',
    r'\beyebrow-pulse\b': 'eyebrow-dot',
    r'\bhero-h1\b': 'hero-title',
    r'\bhero-gradient\b': 'gradient-text',
    r'\bhero-sub\b': 'hero-subtitle',
    r'\bhero-stats-row\b': 'hero-stats',
    r'\bhero-stat-pill\b': 'hero-stat',
    r'\bhsp-value\b': 'hero-stat-value',
    r'\bhsp-label\b': 'hero-stat-label',
    r'\bhsp-sep\b': 'hero-stat-divider',

    r'\bhero-ctas\b': 'hero-actions',
    r'\bcta-primary\b': 'btn-primary',
    r'\bcta-ghost\b': 'btn-ghost',

    r'\bhero-right\b': 'hero-visual',
    r'\bradar-wrap\b': 'radar-container',
    r'\bradar-ring\b': 'radar-ring',
    r'\brr1\b': 'r1',
    r'\brr2\b': 'r2',
    r'\brr3\b': 'r3',
    r'\brr4\b': 'r4',
    r'\bradar-sweep-arm\b': 'radar-sweep',
    r'\bradar-center-dot\b': 'radar-center',
    r'\bradar-center-core\b': 'radar-center-core',
    r'\brblip\b': 'blip',
    r'\brb1\b': 'b1',
    r'\brb2\b': 'b2',
    r'\brb3\b': 'b3',
    r'\brb4\b': 'b4',
    r'\brb5\b': 'b5',
    r'\bcve-float\b': 'cve-tag',
    r'\bcf1\b': 'tag1',
    r'\bcf2\b': 'tag2',
    r'\bcf3\b': 'tag3',
    r'\bch-h\b': 'crosshair-h',
    r'\bch-v\b': 'crosshair-v',

    r'\bhero-ticker\b': 'hero-ticker',
    r'\bticker-lbl\b': 'ticker-label',
    r'\bticker-wrap\b': 'ticker-wrap',
    r'\bticker-inner\b': 'ticker-content',
    r'\bti cve\b': 'ticker-item cve',
    r'\bti\b': 'ticker-item',

    r'\bmodules-section\b': 'features',
    r'\bsection-wrap\b': 'section-inner',
    r'\bsection-head\b': 'section-header',
    r'\bsection-eyebrow\b': 'section-eyebrow',
    r'\bsection-h2\b': 'section-title',
    r'\bsection-desc\b': 'section-sub',

    r'\bmodules-grid\b': 'features-grid',
    r'\bmod-card\b': 'feature-card',
    r'\bmod-cyan\b': 'card-cyan',
    r'\bmod-violet\b': 'card-violet',
    r'\bmod-emerald\b': 'card-emerald',
    r'\bmod-orange\b': 'card-orange',
    r'\bmod-purple\b': 'card-purple',
    r'\bmod-amber\b': 'card-amber',
    r'\bmod-rose\b': 'card-rose',
    r'\bmod-sky\b': 'card-sky',
    r'\bmod-teal\b': 'card-teal',

    r'\bmod-glow\b': 'card-glow',
    r'\bg-cyan\b': 'cyan-glow',
    r'\bg-violet\b': 'violet-glow',
    r'\bg-emerald\b': 'emerald-glow',
    r'\bg-orange\b': 'orange-glow',
    r'\bg-purple\b': 'purple-glow',
    r'\bg-amber\b': 'amber-glow',
    r'\bg-rose\b': 'rose-glow',
    r'\bg-sky\b': 'sky-glow',
    r'\bg-teal\b': 'teal-glow',

    r'\bmod-icon\b': 'card-icon',
    r'\bi-cyan\b': 'cyan-icon',
    r'\bi-violet\b': 'violet-icon',
    r'\bi-emerald\b': 'emerald-icon',
    r'\bi-orange\b': 'orange-icon',
    r'\bi-purple\b': 'purple-icon',
    r'\bi-amber\b': 'amber-icon',
    r'\bi-rose\b': 'rose-icon',
    r'\bi-sky\b': 'sky-icon',
    r'\bi-teal\b': 'teal-icon',

    r'\bmod-num\b': 'card-num',
    r'\bmod-title\b': 'card-title',
    r'\bmod-desc\b': 'card-desc',

    r'\bmod-badge\b': 'card-badge',
    r'\bb-cyan\b': 'cyan-badge',
    r'\bb-violet\b': 'violet-badge',
    r'\bb-emerald\b': 'emerald-badge',
    r'\bb-orange\b': 'orange-badge',
    r'\bb-purple\b': 'purple-badge',
    r'\bb-amber\b': 'amber-badge',
    r'\bb-rose\b': 'rose-badge',
    r'\bb-sky\b': 'sky-badge',
    r'\bb-teal\b': 'teal-badge',

    r'\bmod-arrow\b': 'card-arrow',
    r'\ba-cyan\b': 'cyan-arrow',
    r'\ba-violet\b': 'violet-arrow',
    r'\ba-emerald\b': 'emerald-arrow',
    r'\ba-orange\b': 'orange-arrow',
    r'\ba-purple\b': 'purple-arrow',
    r'\ba-amber\b': 'amber-arrow',
    r'\ba-rose\b': 'rose-arrow',
    r'\ba-sky\b': 'sky-arrow',
    r'\ba-teal\b': 'teal-arrow',

    r'\bterminal-section\b': 'intel-preview',
    r'\bterminal-box\b': 'preview-terminal',
    r'\bterminal-topbar\b': 'terminal-bar',
    r'\btb-dot\b': 't-dot',
    r'\btd-red\b': 'red',
    r'\btd-yellow\b': 'yellow',
    r'\btd-green\b': 'green',
    r'\btb-title\b': 't-title',
    r'\bterminal-body\b': 'terminal-body',
    r'\bterm-loading\b': 'terminal-loading',
    r'\bterm-spinner\b': 't-spinner',
    r'\bterm-mono\b': 't-mono',
    r'\bterm-cta\b': 'preview-cta',

    r'\bhome-footer\b': 'site-footer',
    r'\bfooter-tags\b': 'footer-tags',
    r'\bftag\b': 'f-tag',

    r'\bstats-banner\b': 'how-it-works',
    r'\bstats-grid\b': 'steps-grid',
    r'\bsban-item\b': 'step',
    r'\bsban-val\b': 'step-number',
    r'\bsban-lbl\b': 'step-title', # step h3 is used in css but we can't do that easily as class, wait! I will fix this separately.
}

for k, v in replacements.items():
    html = re.sub(k, v, html)

# Fix the card-footer wrapping
html = re.sub(r'<div class="card-badge([^>]+)>([^<]+)</div>\s*<div class="card-arrow([^>]+)>([^<]+)</div>', 
              r'<div class="card-footer">\n            <div class="card-badge\1>\2</div>\n            <div class="card-arrow\3>\4</div>\n          </div>', 
              html)

# Fix stats banner
html = re.sub(r'<div class="step-title">', r'<h3>', html)
html = re.sub(r'</div>\s*(<!-- ── FOOTER ── -->)', r'</h3>\n        </div>\n      </div>\n    </div>\n  </section>\n\n  \1', html)
# Actually it's easier to just do it via regex
html = html.replace('<div class="step-title">', '<h3>')
html = html.replace('<div class="sban-div"></div>', '<div class="step-connector"></div>')

with open('index.html', 'w') as f:
    f.write(html)
