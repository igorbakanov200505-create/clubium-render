"""Owner-only bootstrap and safe cleanup regression test."""
import os
import re
import sys
import sqlite3
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient


def csrf(html):
    match = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert match, 'Missing CSRF input'
    return match.group(1)


def main():
    with tempfile.TemporaryDirectory(prefix='clubium-azraellone-') as tmp:
        os.environ['SMARTCLUB_DATA_DIR'] = tmp
        os.environ.pop('SMARTCLUB_OWNER_INITIAL_PASSWORD', None)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import app, bootstrap, keep_only_azrael
        bootstrap.setup()
        user_list = app.rows('SELECT username, role, is_service_admin FROM users')
        assert user_list == [{'username': 'AzraelLone', 'role': 'admin', 'is_service_admin': 1}], user_list
        assert app.one('SELECT COUNT(*) AS n FROM clubs')['n'] == 0
        assert app.one('SELECT COUNT(*) AS n FROM students')['n'] == 0
        password_file = Path(tmp) / 'СЛУЖЕБНЫЙ_АДМИН_ПЕРВЫЙ_ПАРОЛЬ.txt'
        assert password_file.exists()
        oldpass = re.search('Временный пароль: ([^\\n]+)',password_file.read_text(encoding='utf-8')).group(1)
        assert len(oldpass) > 24
        with TestClient(app.app) as c:
            assert c.get('/login').status_code==200
            enter = c.post('/login',data={'username':'AzraelLone','password':oldpass,'_csrf':csrf(c.get('/login').text)},follow_redirects=False)
            assert enter.status_code == 303 and enter.headers['location'] == '/password', enter.text
            newpass = 'StrongOwnerPassword2026!'
            password_change = c.post('/password', data={'current':oldpass,'new_password':newpass,'_csrf':csrf(c.get('/password').text)}, follow_redirects=False)
            assert password_change.status_code==303
            assert c.get('/dashboard').status_code==200
            assert c.get('/reports/export/summary').status_code==200
            token=c.post('/api/v1/token',data={'username':'AzraelLone','password':newpass})
            assert token.status_code==200,token.text
            access={'Authorization':'Bearer '+token.json()['access_token']}
            assert c.get('/api/v1/users',headers=access).json()==[]
            assert c.get('/api/v1/me',headers=access).json()['username']=='AzraelLone'
            assert c.post('/api/v1/token',data={'username':'igor','password':'anything'}).status_code==401
        # Simulate pre-existing accounts and school records.
        with app.conn() as db:
            db.execute("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)",('igor','Баканов Игорь',app.password_hash('OldPassword1234!'),'admin'))
            teacher=db.execute("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)",('teacher1','Учитель',app.password_hash('TeacherPassword1234!'),'teacher')).lastrowid
            student_user=db.execute("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)",('student1','Ученик',app.password_hash('StudentPassword1234!'),'student')).lastrowid
            db.execute("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)",('elmira','Эльмира',app.password_hash('OtherPassword1234!'),'admin'))
            club=db.execute("INSERT INTO clubs(title,direction,teacher_id) VALUES(?,?,?)",('Робототехника','Техническое',teacher)).lastrowid
            student=db.execute("INSERT INTO students(fullname,school_class,student_user_id) VALUES(?,?,?)",('Тестовый Ученик','7А',student_user)).lastrowid
            db.execute("INSERT INTO enrollments(club_id,student_id) VALUES(?,?)",(club,student))
            db.execute("INSERT INTO attendance(club_id,student_id,lesson_date,status,author_id) VALUES(?,?,?,?,?)",(club,student,'2026-10-10','present',teacher))
        bootstrap.setup()  # must not silently remove anyone or re-add igor/elmira
        assert app.one('SELECT COUNT(*) AS n FROM users')['n']==5
        preview=keep_only_azrael.cleanup(apply=False)
        assert set(preview['preview'])=={'igor','elmira','teacher1','student1'}
        assert app.one('SELECT COUNT(*) AS n FROM users')['n']==5
        (Path(tmp)/'ПЕРВЫЕ_ПАРОЛИ_СОХРАНИТЬ_И_УДАЛИТЬ.txt').write_text('old bootstrapped passwords',encoding='utf-8')
        result=keep_only_azrael.cleanup(apply=True)
        assert result['deleted']==4
        assert Path(result['backup']).is_file()
        with sqlite3.connect(result['backup']) as old:
            assert old.execute('SELECT COUNT(*) FROM users').fetchone()[0]==5
        assert app.one('SELECT COUNT(*) AS n FROM users')['n']==1
        assert app.one('SELECT username FROM users')['username']=='AzraelLone'
        assert app.one('SELECT teacher_id FROM clubs WHERE id=?',(club,))['teacher_id'] is None
        assert app.one('SELECT student_user_id FROM students WHERE id=?',(student,))['student_user_id'] is None
        assert app.one('SELECT COUNT(*) AS n FROM attendance')['n']==1
        assert app.one('SELECT COUNT(*) AS n FROM enrollments')['n']==1
        assert not (Path(tmp)/'ПЕРВЫЕ_ПАРОЛИ_СОХРАНИТЬ_И_УДАЛИТЬ.txt').exists()
        bootstrap.setup()
        assert app.one('SELECT COUNT(*) AS n FROM users')['n']==1
        assert app.password_ok(newpass,app.one('SELECT password_hash FROM users WHERE username=?',('AzraelLone',))['password_hash'])
    print('PASS: one owner, secure bootstrap, login, role, export, API, explicit cleanup, backup, linked school records preserved')

if __name__=='__main__':main()
