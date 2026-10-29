"""Lightweight source-level checks without browser or network dependencies."""
from pathlib import Path
root=Path(__file__).resolve().parents[1]
login=(root/'templates/login.html').read_text(encoding='utf-8')
base=(root/'templates/base.html').read_text(encoding='utf-8')
js=(root/'static/i18n.js').read_text(encoding='utf-8')
passjs=(root/'static/password-visibility.js').read_text(encoding='utf-8')
css=(root/'static/styles.css').read_text(encoding='utf-8')
assert '🇷🇺' in js and '🇰🇿' in js and '🇬🇧' in js
assert 'clubium.language' in js
assert 'data-i18n-original-' in js
assert 'data-toggle-password="login-password"' in login
assert 'aria-pressed' in passjs and 'eyeOff' in passjs
assert 'premium-ui.js' in base
assert 'prefers-reduced-motion' in css
assert 'class="login-panel' in login
print('PASS: flags RU/KZ/EN, saved language, eye toggle, adaptive UI and reduced motion')
