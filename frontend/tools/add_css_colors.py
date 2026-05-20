missing_colors = """
/* Missing Colors for Modules */
.card-orange:hover { border-color: rgba(249, 115, 22, 0.5); box-shadow: 0 24px 70px rgba(249, 115, 22, 0.18); }
.orange-glow { background: #f97316; }
.orange-icon { background: rgba(249, 115, 22, 0.1); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.2); }
.orange-badge { background: rgba(249, 115, 22, 0.1); border-color: rgba(249, 115, 22, 0.3); color: #f97316; }
.orange-arrow { color: rgba(249, 115, 22, 0.4); }
.card-orange:hover .card-arrow { color: #f97316; transform: translateX(4px); opacity: 1; }

.card-purple:hover { border-color: rgba(168, 85, 247, 0.5); box-shadow: 0 24px 70px rgba(168, 85, 247, 0.18); }
.purple-glow { background: #a855f7; }
.purple-icon { background: rgba(168, 85, 247, 0.1); color: #a855f7; border: 1px solid rgba(168, 85, 247, 0.2); }
.purple-badge { background: rgba(168, 85, 247, 0.1); border-color: rgba(168, 85, 247, 0.3); color: #a855f7; }
.purple-arrow { color: rgba(168, 85, 247, 0.4); }
.card-purple:hover .card-arrow { color: #a855f7; transform: translateX(4px); opacity: 1; }

.card-amber:hover { border-color: rgba(245, 158, 11, 0.5); box-shadow: 0 24px 70px rgba(245, 158, 11, 0.18); }
.amber-glow { background: #f59e0b; }
.amber-icon { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.2); }
.amber-badge { background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.3); color: #f59e0b; }
.amber-arrow { color: rgba(245, 158, 11, 0.4); }
.card-amber:hover .card-arrow { color: #f59e0b; transform: translateX(4px); opacity: 1; }

.card-rose:hover { border-color: rgba(244, 63, 94, 0.5); box-shadow: 0 24px 70px rgba(244, 63, 94, 0.18); }
.rose-glow { background: #f43f5e; }
.rose-icon { background: rgba(244, 63, 94, 0.1); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.2); }
.rose-badge { background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.3); color: #f43f5e; }
.rose-arrow { color: rgba(244, 63, 94, 0.4); }
.card-rose:hover .card-arrow { color: #f43f5e; transform: translateX(4px); opacity: 1; }

.card-sky:hover { border-color: rgba(14, 165, 233, 0.5); box-shadow: 0 24px 70px rgba(14, 165, 233, 0.18); }
.sky-glow { background: #0ea5e9; }
.sky-icon { background: rgba(14, 165, 233, 0.1); color: #0ea5e9; border: 1px solid rgba(14, 165, 233, 0.2); }
.sky-badge { background: rgba(14, 165, 233, 0.1); border-color: rgba(14, 165, 233, 0.3); color: #0ea5e9; }
.sky-arrow { color: rgba(14, 165, 233, 0.4); }
.card-sky:hover .card-arrow { color: #0ea5e9; transform: translateX(4px); opacity: 1; }

.card-teal:hover { border-color: rgba(20, 184, 166, 0.5); box-shadow: 0 24px 70px rgba(20, 184, 166, 0.18); }
.teal-glow { background: #14b8a6; }
.teal-icon { background: rgba(20, 184, 166, 0.1); color: #14b8a6; border: 1px solid rgba(20, 184, 166, 0.2); }
.teal-badge { background: rgba(20, 184, 166, 0.1); border-color: rgba(20, 184, 166, 0.3); color: #14b8a6; }
.teal-arrow { color: rgba(20, 184, 166, 0.4); }
.card-teal:hover .card-arrow { color: #14b8a6; transform: translateX(4px); opacity: 1; }

/* Also ensure step-number colors match cyan, amber, emerald, violet */
.step-number.cyan { color: var(--cyan); }
.step-number.amber { color: var(--amber); }
.step-number.emerald { color: var(--emerald); }
.step-number.violet { color: var(--violet); }
"""

with open('home.css', 'a') as f:
    f.write(missing_colors)
