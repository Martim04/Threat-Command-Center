import re

replacements = {
    r'\.hero-section-inner\b': '.hero-grid',
    r'\.hero-section-eyebrow\b': '.hero-eyebrow',
    r'\.hero-section-title\b': '.hero-h1',
    r'\.hero-section-subtitle\b': '.hero-sub',
    r'\.hero-section-stats\b': '.hero-stats-row',
    r'\.hero-section-stat\b': '.hero-stat-pill',
    r'\.hero-section-stat-value\b': '.hsp-value',
    r'\.hero-section-stat-label\b': '.hsp-label',
    r'\.hero-section-stat-divider\b': '.hsp-sep',
    r'\.hero-section-actions\b': '.hero-ctas',
    r'\.hero-section-visual\b': '.hero-right',
    r'\.hero-section-ticker\b': '.hero-ticker',
    r'\.hero-section-stat-pill\b': '.hero-stat-pill'
}

with open('home.css', 'r') as f:
    css = f.read()

for k, v in replacements.items():
    css = re.sub(k, v, css)

with open('home.css', 'w') as f:
    f.write(css)
