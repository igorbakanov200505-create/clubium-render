"""Direct-link auth regressions: browser redirects; JSON APIs remain protected."""
import os
import re
import sys
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

def token(html):
    found = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert found, 'missing CSRF'
    return found.group(1)

def main():
    with tempfile.TemporaryDirectory(prefix='clubium-deeplink-') as tmp:
        os.environ['SMARTCLUB_DATA_DIR'] = tmp
        os.environ['SMARTCLUB_OWNER_INITIAL_PASSWORD'] = 'TemporaryOwnerPassword-2026!'
        os.environ.pop('SMARTCLUB_HTTPS',None)
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        import app, bootstrap
        bootstrap.setup()
        with TestClient(app.app) as guest:
            for path in ('/dashboard','/chat','/students','/users','/portfolio','/reports','/schedule', '/chat?room=general'):
                response=guest.get(path,follow_redirects=False)
                assert response.status_code == 303,(path,response.status_code,response.text[:180])
                assert response.headers['location'] == '/login'
                assert 'no-store' in response.headers.get('cache-control','')
            for path in ('/api/v1/me', '/chat/api/rooms', '/chat/api/messages?room=general'):
                response=guest.get(path,follow_redirects=False)
                assert response.status_code == 401,(path,response.status_code,response.text[:180])
                assert 'application/json' in response.headers.get('content-type','')
            assert guest.get('/login').status_code == 200
            assert guest.get('/health').status_code == 200
            # Deep-link login, first password rotation, welcome return target.
            guest.get('/chat?room=general',follow_redirects=False)
            csrf=token(guest.get('/login').text)
            login=guest.post('/login',data={'username':'AzraelLone','password':'TemporaryOwnerPassword-2026!','_csrf':csrf},follow_redirects=False)
            assert login.status_code == 303 and login.headers['location']=='/password'
            csrf=token(guest.get('/password').text)
            result=guest.post('/password',data={'current':'TemporaryOwnerPassword-2026!','new_password':'NewOwnerPassword-2026!','_csrf':csrf},follow_redirects=False)
            assert result.status_code == 303 and result.headers['location']=='/welcome'
            welcome=guest.get('/welcome')
            assert welcome.status_code == 200
            assert 'href="/chat?room=general"' in welcome.text
            assert guest.get('/chat?room=general').status_code == 200
            # An authenticated student's forbidden admin route must NOT turn into a sign-in redirect.
            with app.conn() as db:
                db.execute('INSERT INTO users(username,display_name,password_hash,role,must_change_password) VALUES(?,?,?,?,0)',('studenttester','Student Test',app.password_hash('StudentPassword2026!'),'student'))
            with TestClient(app.app) as student:
                csrf=token(student.get('/login').text)
                assert student.post('/login',data={'username':'studenttester','password':'StudentPassword2026!','_csrf':csrf},follow_redirects=False).status_code==303
                denied=student.get('/users',follow_redirects=False)
                assert denied.status_code==403,(denied.status_code,denied.text)
                assert student.get('/chat/api/messages?room=admins').status_code==403
            # Anonymous API requests that accept JSON must not redirect; nor should a POST to a protected page.
        with TestClient(app.app) as stranger:
            assert stranger.post('/clubs/save',data={},follow_redirects=False).status_code==401
            response=stranger.get('/chat',headers={'Accept':'application/json'},follow_redirects=False)
            assert response.status_code==401
            # Normal sign-in without a deeplink keeps the dashboard target.
            csrf=token(stranger.get('/login').text)
            assert stranger.post('/login',data={'username':'AzraelLone','password':'NewOwnerPassword-2026!','_csrf':csrf},follow_redirects=False).status_code==303
            assert 'href="/dashboard"' in stranger.get('/welcome').text
        print('PASS: direct links, expired browser sessions, JSON endpoints, 403 roles, CSRF, first password rotation, welcome deep-link')

if __name__ == '__main__':main()
