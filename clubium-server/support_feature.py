"""ÜiirmeHub confidential support inbox shared by all administrators.

All users may create tickets, but only the author and admins may read a ticket.
Every POST requires CSRF and every database read checks actor authorization.
"""
from __future__ import annotations
import re
from fastapi import Request, Form, HTTPException
from fastapi.responses import RedirectResponse

MAX_SUBJECT = 140
MAX_MESSAGE = 3500


def install(ns):
    app = ns['app']
    require = ns['require']
    conn = ns['conn']
    rows = ns['rows']
    one = ns['one']
    csrf = ns['csrf']
    check_csrf = ns['check_csrf']
    templates = ns['templates']
    flash = ns['flash']
    go = ns['go']

    with conn() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY,
            creator_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            subject TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Вопрос',
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY,
            ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
            sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            sender_label TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS support_ticket_owner_idx ON support_tickets(creator_id,updated_at)')
        db.execute('CREATE INDEX IF NOT EXISTS support_message_ticket_idx ON support_messages(ticket_id,id)')

    def page(request, file, user, **data):
        result=templates.TemplateResponse(request,file,dict(
            request=request,user=user,csrf=csrf(request),current='support',
            notice=request.session.pop('notice',None),page_title='Поддержка',**data))
        result.headers['Cache-Control']='no-store, private'
        return result

    def ticket_access(user, ticket_id):
        t=one('''SELECT t.id,t.subject,t.category,t.status,t.creator_id,t.created_at,t.updated_at,
                     u.display_name AS creator_name,u.username AS creator_login
                 FROM support_tickets t JOIN users u ON t.creator_id=u.id WHERE t.id=?''',(ticket_id,))
        if not t or (user['role']!='admin' and t['creator_id']!=user['id']):
            raise HTTPException(404,'Обращение не найдено')
        return t

    @app.get('/support')
    def support_index(request:Request):
        user=require(request)
        if user['role']=='admin':
            tickets=rows('''SELECT t.id,t.subject,t.category,t.status,t.updated_at,
                         u.display_name AS creator_name,u.username AS creator_login,
                         (SELECT COUNT(*) FROM support_messages m WHERE m.ticket_id=t.id) AS message_count
                         FROM support_tickets t JOIN users u ON u.id=t.creator_id
                         ORDER BY CASE WHEN t.status='open' THEN 0 ELSE 1 END,t.updated_at DESC LIMIT 300''')
        else:
            tickets=rows('''SELECT t.id,t.subject,t.category,t.status,t.updated_at,
                         u.display_name AS creator_name,u.username AS creator_login,
                         (SELECT COUNT(*) FROM support_messages m WHERE m.ticket_id=t.id) AS message_count
                         FROM support_tickets t JOIN users u ON u.id=t.creator_id
                         WHERE t.creator_id=? ORDER BY t.updated_at DESC LIMIT 100''',(user['id'],))
        return page(request,'support_index.html',user,tickets=tickets)

    @app.post('/support/new')
    def create_ticket(request:Request,csrf_token:str=Form('',alias='_csrf'),
                      subject:str=Form(''),category:str=Form('Вопрос'),message:str=Form('')):
        user=require(request)
        check_csrf(request,csrf_token)
        subject=subject.strip();message=message.strip();category=category.strip()
        if not 3<=len(subject)<=MAX_SUBJECT or not 5<=len(message)<=MAX_MESSAGE:
            raise HTTPException(400,'Тема: 3–140 символов, сообщение: 5–3500 символов')
        if category not in ('Вопрос','Помощь','Ошибка','Предложение','Другое'):
            raise HTTPException(400,'Неверная категория обращения')
        with conn() as db:
            # Avoid automated flooding from one account.
            quota=db.execute("SELECT COUNT(*) AS n FROM support_tickets WHERE creator_id=? AND created_at>=datetime('now','-1 day')",(user['id'],)).fetchone()['n']
            if quota>=12:
                raise HTTPException(429,'Не больше 12 новых обращений за сутки')
            cur=db.execute('INSERT INTO support_tickets(creator_id,subject,category) VALUES(?,?,?)',
                           (user['id'],subject,category))
            tid=cur.lastrowid
            db.execute('INSERT INTO support_messages(ticket_id,sender_id,sender_label,body) VALUES(?,?,?,?)',
                       (tid,user['id'],user['display_name'],message))
        flash(request,'Обращение отправлено в поддержку')
        return go(f'/support/{tid}')

    @app.get('/support/{ticket_id}')
    def view_ticket(request:Request,ticket_id:int):
        user=require(request)
        ticket=ticket_access(user,ticket_id)
        messages=rows('''SELECT m.id,m.sender_id,m.sender_label,m.body,m.created_at,
                      COALESCE(u.display_name,m.sender_label) AS author_name,
                      u.role AS sender_role
                      FROM support_messages m LEFT JOIN users u ON u.id=m.sender_id
                      WHERE m.ticket_id=? ORDER BY m.id ASC LIMIT 500''',(ticket_id,))
        return page(request,'support_ticket.html',user,ticket=ticket,messages=messages)

    @app.post('/support/{ticket_id}/reply')
    def reply_ticket(request:Request,ticket_id:int,csrf_token:str=Form('',alias='_csrf'),message:str=Form('')):
        user=require(request)
        check_csrf(request,csrf_token)
        msg=message.strip()
        if not 1<=len(msg)<=MAX_MESSAGE:
            raise HTTPException(400,'Сообщение должно содержать от 1 до 3500 символов')
        with conn() as db:
            ticket=db.execute('SELECT creator_id,status FROM support_tickets WHERE id=?',(ticket_id,)).fetchone()
            if not ticket or (user['role']!='admin' and ticket['creator_id']!=user['id']):
                raise HTTPException(404,'Обращение не найдено')
            if ticket['status']=='closed':
                raise HTTPException(409,'Обращение закрыто. Создайте новое или попросите администратора открыть его.')
            # A ticket has a per-account cap on replies per minute.
            n=db.execute("SELECT COUNT(*) AS n FROM support_messages WHERE ticket_id=? AND sender_id=? AND created_at>=datetime('now','-1 minute')",
                         (ticket_id,user['id'])).fetchone()['n']
            if n>=15:raise HTTPException(429,'Слишком много сообщений за минуту')
            db.execute('INSERT INTO support_messages(ticket_id,sender_id,sender_label,body) VALUES(?,?,?,?)',
                       (ticket_id,user['id'],user['display_name'],msg))
            db.execute('UPDATE support_tickets SET updated_at=CURRENT_TIMESTAMP WHERE id=?',(ticket_id,))
        flash(request,'Ответ отправлен')
        return go(f'/support/{ticket_id}')

    @app.post('/support/{ticket_id}/status')
    def change_status(request:Request,ticket_id:int,csrf_token:str=Form('',alias='_csrf'),status:str=Form('')):
        user=require(request,('admin',))
        check_csrf(request,csrf_token)
        if status not in ('open','closed'):
            raise HTTPException(400,'Неверный статус')
        with conn() as db:
            cur=db.execute('UPDATE support_tickets SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(status,ticket_id))
            if cur.rowcount!=1:raise HTTPException(404,'Обращение не найдено')
        flash(request,'Обращение открыто' if status=='open' else 'Обращение закрыто')
        return go(f'/support/{ticket_id}')

    return True
