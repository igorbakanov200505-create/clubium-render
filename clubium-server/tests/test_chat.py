"""Integration/regression tests for messaging security and persistence."""
import os
import re
import sys
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient


def get_csrf(html):
    found=re.search(r'name="_csrf" value="([^"]+)"',html)
    assert found, 'No CSRF form token in HTML'
    return found.group(1)


def main():
    with tempfile.TemporaryDirectory(prefix='clubium-chat-test-') as tmp:
        os.environ['SMARTCLUB_DATA_DIR']=tmp
        os.environ['SMARTCLUB_OWNER_INITIAL_PASSWORD']='PrivateTestPassword2026!'
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        import app,bootstrap
        bootstrap.setup()
        owner=app.one('SELECT * FROM users WHERE username=?',('AzraelLone',))
        assert owner and owner['role']=='admin' and owner['is_service_admin']==1
        assert app.rows('SELECT id FROM chat_messages')==[]
        pw='TestAccountPassword2026!'
        users={}
        with app.conn() as db:
            for username,role in [('admin2','admin'),('teacher1','teacher'),('student1','student'),('parent1','parent')]:
                uid=db.execute('INSERT INTO users(username,display_name,password_hash,role,must_change_password) VALUES(?,?,?,?,0)',(username,'Тест '+username,app.password_hash(pw),role)).lastrowid
                users[username]=uid
        # The owner must rotate temporary password on first login.
        ownerpass='PrivateTestPassword2026!'
        with TestClient(app.app) as admin, TestClient(app.app) as teacher, TestClient(app.app) as student, TestClient(app.app) as admin2, TestClient(app.app) as parent:
            def sign_in(c,name,password):
                response=c.post('/login',data={'username':name,'password':password,'_csrf':get_csrf(c.get('/login').text)},follow_redirects=False)
                assert response.status_code==303,(name,response.status_code,response.text[:300])
                return response
            assert sign_in(admin,'AzraelLone',ownerpass).headers['location']=='/password'
            token=get_csrf(admin.get('/password').text)
            assert admin.post('/password',data={'current':ownerpass,'new_password':pw,'_csrf':token},follow_redirects=False).status_code==303
            sign_in(teacher,'teacher1',pw)
            sign_in(student,'student1',pw)
            sign_in(admin2,'admin2',pw)
            sign_in(parent,'parent1',pw)
            admin_token=get_csrf(admin.get('/chat').text)
            teacher_token=get_csrf(teacher.get('/chat').text)
            student_token=get_csrf(student.get('/chat').text)
            admin2_token=get_csrf(admin2.get('/chat').text)
            parent_token=get_csrf(parent.get('/chat').text)
            def post(c,route,payload,token):
                return c.post(route,json=payload,headers={'x-csrf-token':token})
            assert admin.get('/chat').status_code==200
            assert '/static/chat.js' in admin.get('/chat').text
            assert '✉' in student.get('/chat').text
            assert admin.get('/chat/api/rooms').json()['rooms'][1]['key']=='admins'
            assert len(student.get('/chat/api/rooms').json()['rooms'])==1
            assert all(x['key']!='admins' for x in student.get('/chat/api/rooms').json()['rooms'])
            assert teacher.get('/chat/api/messages?room=admins').status_code==403
            assert post(student,'/chat/api/send',{'room':'admins','text':'hi'},student_token).status_code==403
            assert post(student,'/chat/api/send',{'room':'general','text':'hi'},'invalid').status_code==403
            assert post(student,'/chat/api/send',{'room':'general','text':'   '},student_token).status_code==400
            assert post(student,'/chat/api/send',{'room':'general','text':'a'*1201},student_token).status_code==400
            assert post(student,'/chat/api/send',{'room':'dm:99999','text':'hello'},student_token).status_code==404
            public=post(admin,'/chat/api/send',{'room':'general','text':'Добро пожаловать в Клубиум!'},admin_token)
            assert public.status_code==201, public.text
            public_id=public.json()['id']
            assert teacher.get('/chat/api/messages?room=general').json()['messages'][0]['body'].startswith('Добро')
            assert student.get('/chat/api/unread').json()['unread']==1
            assert post(student,'/chat/api/read',{'room':'general'},student_token).status_code==200
            assert student.get('/chat/api/unread').json()['unread']==0
            admins=post(admin,'/chat/api/send',{'room':'admins','text':'Заметка для администраторов'},admin_token)
            assert admins.status_code==201
            assert admin2.get('/chat/api/messages?room=admins').json()['messages'][0]['id']==admins.json()['id']
            assert teacher.get('/chat/api/messages?room=admins').status_code==403
            # Private conversations cannot be read/deleted by others, not even by a superadmin.
            private=post(student,'/chat/api/send',{'room':'dm:'+str(users['teacher1']),'text':'Личное сообщение'},student_token)
            assert private.status_code==201,private.text
            msg_id=private.json()['id']
            assert teacher.get('/chat/api/messages?room=dm:'+str(users['student1'])).json()['messages'][0]['body']=='Личное сообщение'
            assert teacher.get('/chat/api/unread').json()['unread']>=2
            assert admin.get('/chat/api/messages?room=dm:'+str(users['student1'])).json()['messages']==[]
            assert admin2.post(f'/chat/api/messages/{msg_id}/delete',headers={'x-csrf-token':admin2_token}).status_code==404
            assert parent.get('/chat/api/messages?room=dm:'+str(users['teacher1'])).json()['messages']==[]
            assert post(teacher,f'/chat/api/messages/{msg_id}/report',{'reason':'Подозрительное сообщение'},teacher_token).status_code==201
            assert student.get('/chat/api/reports').status_code==403
            reports=admin.get('/chat/api/reports').json()['reports']
            assert reports and reports[0]['message_id']==msg_id and reports[0]['reason']=='Подозрительное сообщение'
            assert admin.post(f'/chat/api/messages/{msg_id}/delete',headers={'x-csrf-token':admin_token}).status_code==404
            assert student.post(f'/chat/api/messages/{msg_id}/delete',headers={'x-csrf-token':student_token}).status_code==200
            assert teacher.get('/chat/api/messages?room=dm:'+str(users['student1'])).json()['messages'][0]['deleted']
            assert app.one('SELECT body FROM chat_messages WHERE id=?',(msg_id,))['body']=='Сообщение удалено'
            # Group moderation: admin can delete a teacher's public post.
            group=post(teacher,'/chat/api/send',{'room':'general','text':'Пост педагога'},teacher_token)
            assert group.status_code==201
            group_id=group.json()['id']
            assert student.post(f'/chat/api/messages/{group_id}/delete',headers={'x-csrf-token':student_token}).status_code==403
            assert admin.post(f'/chat/api/messages/{group_id}/delete',headers={'x-csrf-token':admin_token}).status_code==200
            assert group_id in student.get('/chat/api/messages?room=general').json()['deleted_ids']
            # Paginated history, message order and rate limiting across DB.
            for i in range(6):
                response=post(parent,'/chat/api/send',{'room':'general','text':str(i)},parent_token)
                assert response.status_code==201,(i,response.text)
            assert post(parent,'/chat/api/send',{'room':'general','text':'7'},parent_token).status_code==429
            texts=[m['body'] for m in admin.get('/chat/api/messages?room=general').json()['messages']]
            assert texts[-1]=='5',texts
            assert admin.get('/chat/api/messages?room=general&after=-1').status_code==400
            assert admin.get('/chat/api/messages?room=general&before=1&after=2').status_code==400
            assert admin.get('/chat/api/messages?room=dm:'+str(users['teacher1'])).json()['messages']==[]
            # A removed account cannot be a DM target; foreign-key cleanup should work.
            app.run('UPDATE users SET active=0 WHERE id=?',(users['teacher1'],))
            assert post(student,'/chat/api/send',{'room':'dm:'+str(users['teacher1']),'text':'No'},student_token).status_code==404
            assert 'SMARTCLUB_OWNER_INITIAL_PASSWORD' not in app.one('SELECT body FROM chat_messages WHERE id=?',(public_id,))['body']
        print('PASS: private DM confidentiality, admin-only room, shared chat, CSRF, unread, delete, reports, audit, throttling, deactivate')

if __name__=='__main__':main()
