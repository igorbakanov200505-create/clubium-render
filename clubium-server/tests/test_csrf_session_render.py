"""Regression: expired forms should never show raw JSON, and CSRF stays mandatory."""
import os
import re
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


def csrf_token(html):
    match = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert match, "Missing anti-CSRF token"
    return match.group(1)


def main():
    with tempfile.TemporaryDirectory(prefix='clubium-session-test-') as tmp:
        os.environ['SMARTCLUB_DATA_DIR'] = tmp
        os.environ['SMARTCLUB_OWNER_INITIAL_PASSWORD'] = 'DevTestOwnerPassword-2026!'
        os.environ['CLUBIUM_SESSION_SECRET'] = 'stable-secret-value-for-regression-test-at-least-32-characters'
        os.environ.pop('SMARTCLUB_HTTPS', None)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import app, bootstrap
        assert app.SECRET == os.environ['CLUBIUM_SESSION_SECRET']
        bootstrap.setup()

        with TestClient(app.app) as c:
            # Missing token must not accidentally compare equal to an empty session token.
            bad = c.post('/login',data={'username':'AzraelLone','password':'DevTestOwnerPassword-2026!'},follow_redirects=False)
            assert bad.status_code == 403 and '<html' in bad.text.lower(), bad.text[:250]
            assert 'CSRF token invalid' not in bad.text
            assert 'Сессия входа устарела' in bad.text
            # The observed production failure: POST /logout with an invalid token.
            logout = c.post('/logout',data={'_csrf':'stale'},follow_redirects=False)
            assert logout.status_code == 303 and logout.headers['location'] == '/login?session_expired=1', logout.text[:250]
            assert 'Сессия устарела' in c.get('/login?session_expired=1').text

            fresh = csrf_token(c.get('/login').text)
            auth = c.post('/login',data={'username':'AzraelLone','password':'DevTestOwnerPassword-2026!','_csrf':fresh},follow_redirects=False)
            assert auth.status_code == 303 and auth.headers['location'] == '/password'
            invalid = c.post('/password',data={'current':'DevTestOwnerPassword-2026!','new_password':'UpdatedPassword-2026!','_csrf':'stale'},follow_redirects=False)
            assert invalid.status_code == 303 and invalid.headers['location'] == '/password?session_expired=1'
            assert 'Сессия формы устарела' in c.get(invalid.headers['location']).text
            goodcsrf = csrf_token(c.get('/password').text)
            valid = c.post('/password',data={'current':'DevTestOwnerPassword-2026!','new_password':'UpdatedPassword-2026!','_csrf':goodcsrf},follow_redirects=False)
            assert valid.status_code==303
            assert c.get('/dashboard').status_code == 200
            before = app.one('SELECT count(*) as n FROM users')['n']
            mismatch = c.post('/users/create',data={'_csrf':'incorrect','username':'hijacked','display_name':'Hijacked','new_password':'PasswordToNeverApply123','role':'teacher'},follow_redirects=False)
            assert mismatch.status_code == 303 and mismatch.headers['location'] == '/dashboard', mismatch.text[:300]
            assert app.one('SELECT count(*) as n FROM users')['n'] == before
            assert 'Сессия формы устарела' in c.get('/dashboard').text
            response = c.post('/chat/api/send',json={'room':'general','text':'attempt'},headers={'x-csrf-token':'stale'})
            assert response.status_code == 403 and response.json()['detail'] == 'CSRF token invalid'
            logout = c.post('/logout',data={'_csrf':'invalid'},follow_redirects=False)
            assert logout.status_code == 303 and logout.headers['location']=='/login?session_expired=1'
            assert c.get('/dashboard',follow_redirects=False).status_code == 303
        print('PASS: expired logout/login/password/form, no raw JSON on browser pages, strict CSRF and API security')


if __name__ == '__main__':
    main()
