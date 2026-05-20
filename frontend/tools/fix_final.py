with open('index.html', 'r') as f:
    html = f.read()

# Fix the broken <h3></div> tags and change to <div class="step-title">
html = html.replace('<h3>Threats Indexed</div>', '<div class="step-title">Threats Indexed</div>')
html = html.replace('<h3>CVEs Tracked</div>', '<div class="step-title">CVEs Tracked</div>')
html = html.replace('<h3>Intel Sources</div>', '<div class="step-title">Intel Sources</div>')
html = html.replace('<h3>Security Modules</div>', '<div class="step-title">Security Modules</div>')

with open('index.html', 'w') as f:
    f.write(html)


with open('home.css', 'r') as f:
    css = f.read()

# Fix the grid columns
css = css.replace('grid-template-columns: repeat(3, 1fr);', 'grid-template-columns: repeat(4, 1fr);')

# Add the step-title
css += """
.step-title {
  font-size: 0.75rem;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-top: 4px;
}
"""

with open('home.css', 'w') as f:
    f.write(css)
