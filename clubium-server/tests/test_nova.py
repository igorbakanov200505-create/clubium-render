from pathlib import Path
root=Path(__file__).resolve().parents[1]
base=(root/'templates/base.html').read_text(encoding='utf-8')
login=(root/'templates/login.html').read_text(encoding='utf-8')
js=(root/'static/nova.js').read_text(encoding='utf-8')
css=(root/'static/nova.css').read_text(encoding='utf-8')
sw=(root/'static/nova-sw.js').read_text(encoding='utf-8')
assert '/static/nova.css' in base and '/static/nova.js' in base
assert '/static/nova.css' in login
assert 'nova-command-palette' in base and 'nova-mobile-nav' in base
assert 'Ctrl+K' in base and "e.ctrlKey||e.metaKey" in js
assert 'clubium:language-changed' in js
assert 'prefers-reduced-motion' in css
assert "u.pathname.startsWith('/static/')" in sw
assert "u.pathname.startsWith('/api/')" not in sw
assert 'data-toggle-password="login-password"' in login
print('PASS Clubium NOVA layouts, command palette, flags, password eye, static-only PWA cache')
