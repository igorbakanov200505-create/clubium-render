"""Клубиум: school club management application.

SQLite + server-rendered UI + token-authenticated JSON API.
Run `python bootstrap.py` once, then `uvicorn app:app --host 127.0.0.1 --port 8000`.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
import uuid
from collections import defaultdict
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env", override=False)
INSTANCE = Path(os.environ.get('SMARTCLUB_DATA_DIR') or str(ROOT / 'instance'))
INSTANCE.mkdir(parents=True, exist_ok=True)
DB = INSTANCE / 'smartclub.sqlite3'
KEYFILE = INSTANCE / 'secret.key'
if not KEYFILE.exists():
    KEYFILE.write_text(secrets.token_urlsafe(48), encoding='utf-8')
    try: KEYFILE.chmod(0o600)
    except OSError: pass
SECRET = KEYFILE.read_text(encoding='utf-8').strip()
serializer = URLSafeTimedSerializer(SECRET, salt='smartclub-api-v1')
app = FastAPI(title='Клубиум API', version='1.0.0', docs_url='/api/docs', redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET, same_site='lax', https_only=os.environ.get('SMARTCLUB_HTTPS', '0') == '1', max_age=8 * 3600)
app.mount('/static', StaticFiles(directory=ROOT/'static'), name='static')
templates = Jinja2Templates(directory=ROOT/'templates')

SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
 display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','teacher','parent','student')),
 active INTEGER NOT NULL DEFAULT 1,
 must_change_password INTEGER NOT NULL DEFAULT 1,
 is_service_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_service_admin IN (0,1)),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS clubs (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, direction TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '', teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 weekdays TEXT NOT NULL DEFAULT 'Пн, Ср', time TEXT NOT NULL DEFAULT '15:00', room TEXT NOT NULL DEFAULT '',
 capacity INTEGER NOT NULL DEFAULT 20, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS students (
 id INTEGER PRIMARY KEY, fullname TEXT NOT NULL, school_class TEXT NOT NULL,
 interests TEXT NOT NULL DEFAULT '', parent_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 student_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS enrollments (
 club_id INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
 student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 PRIMARY KEY (club_id, student_id)
);
CREATE TABLE IF NOT EXISTS attendance (
 club_id INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
 student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 lesson_date TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('present','absent','excused')),
 author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY (club_id, student_id, lesson_date)
);
CREATE TABLE IF NOT EXISTS achievements (
 id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 club_id INTEGER REFERENCES clubs(id) ON DELETE SET NULL,
 title TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'Проект',
 event_date TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', attachment TEXT NOT NULL DEFAULT '',
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS documents (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL,
 body TEXT NOT NULL, club_id INTEGER REFERENCES clubs(id) ON DELETE SET NULL,
 author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notification_drafts (
 id INTEGER PRIMARY KEY, club_id INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
 student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 lesson_date TEXT NOT NULL, message TEXT NOT NULL,
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(lesson_date,club_id);
CREATE INDEX IF NOT EXISTS idx_achievement_student ON achievements(student_id);
'''

@contextmanager
def conn():
    con = sqlite3.connect(DB, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=10000')
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

# Safe migration for installations created before service administrator support.
with conn() as db:
    db.executescript(SCHEMA)
    if 'is_service_admin' not in {col['name'] for col in db.execute('PRAGMA table_info(users)').fetchall()}:
        db.execute('ALTER TABLE users ADD COLUMN is_service_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_service_admin IN (0,1))')
    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS one_service_admin ON users(is_service_admin) WHERE is_service_admin = 1')

def rows(sql, params=()):
    with conn() as db:
        return [dict(x) for x in db.execute(sql, params).fetchall()]

def one(sql, params=()):
    with conn() as db:
        x=db.execute(sql,params).fetchone()
        return dict(x) if x else None

def run(sql, params=()):
    with conn() as db:
        cur=db.execute(sql,params)
        return cur.lastrowid

def log(u, action, details=''):
    run('INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)',(u['id'],action,str(details)[:250]))

def password_hash(password):
    salt=os.urandom(16)
    dk=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,360000)
    return 'pbkdf2_sha256$360000$'+salt.hex()+'$'+dk.hex()

def password_ok(password, encoded):
    try:
        scheme,iterations,salt,hashval=encoded.split('$')
        if scheme!='pbkdf2_sha256': return False
        candidate=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(iterations))
        return hmac.compare_digest(candidate,bytes.fromhex(hashval))
    except (ValueError,TypeError): return False

def get_user(request):
    uid=request.session.get('uid')
    if not uid: return None
    user=one('SELECT id,username,display_name,role,active,must_change_password,is_service_admin FROM users WHERE id=?',(uid,))
    return user if user and user['active'] else None

def csrf(request):
    if not request.session.get('csrf'):
        request.session['csrf']=secrets.token_urlsafe(24)
    return request.session['csrf']

def check_csrf(request, token):
    if not hmac.compare_digest(str(request.session.get('csrf','')),str(token or '')):
        raise HTTPException(403,'CSRF token invalid')

def flash(request, message, level='success'):
    request.session['notice']=(str(message),level)

def go(path): return RedirectResponse(path,status_code=303)

def render(request, page, **ctx):
    user=get_user(request)
    if not user: return go('/login')
    if user['must_change_password'] and request.url.path!='/password': return go('/password')
    current=request.url.path.split('/')[1] or 'dashboard'
    notice=request.session.pop('notice',None)
    data=dict(request=request,user=user,csrf=csrf(request),notice=notice,current=current,page=page,today=date.today().isoformat(),page_title=ctx.pop('page_title','Клубиум'))
    data.update(ctx)
    return templates.TemplateResponse(request,'pages.html',data)

def require(request, roles=('admin','teacher','parent','student')):
    user=get_user(request)
    if not user: raise HTTPException(401,'Авторизация необходима')
    if user['role'] not in roles: raise HTTPException(403,'Недостаточно прав')
    if user['must_change_password']: raise HTTPException(303,'Сначала смените пароль',headers={'Location':'/password'})
    return user

def club_ids(user):
    if user['role']=='admin': return [x['id'] for x in rows('SELECT id FROM clubs')]
    if user['role']=='teacher': return [x['id'] for x in rows('SELECT id FROM clubs WHERE teacher_id=?',(user['id'],))]
    if user['role']=='student': return [x['club_id'] for x in rows('SELECT e.club_id FROM enrollments e JOIN students s ON s.id=e.student_id WHERE s.student_user_id=?',(user['id'],))]
    return [x['club_id'] for x in rows('SELECT DISTINCT e.club_id FROM enrollments e JOIN students s ON s.id=e.student_id WHERE s.parent_user_id=?',(user['id'],))]

def allow_club(user, club_id, editing=False):
    if editing and user['role'] not in ('admin','teacher'): raise HTTPException(403,'Только для сотрудников')
    if int(club_id) not in club_ids(user): raise HTTPException(403,'Нет доступа к кружку')

def can_student(user,sid):
    if user['role']=='admin': return True
    if user['role']=='teacher':
        return bool(one('SELECT 1 FROM enrollments e JOIN clubs c ON c.id=e.club_id WHERE e.student_id=? AND c.teacher_id=? LIMIT 1',(sid,user['id'])))
    if user['role']=='student': return bool(one('SELECT 1 FROM students WHERE id=? AND student_user_id=?',(sid,user['id'])))
    if user['role']=='parent': return bool(one('SELECT 1 FROM students WHERE id=? AND parent_user_id=?',(sid,user['id'])))
    return False

def visible_students(user):
    if user['role']=='admin': return rows('SELECT * FROM students ORDER BY fullname')
    if user['role']=='teacher': return rows('SELECT DISTINCT s.* FROM students s JOIN enrollments e ON e.student_id=s.id JOIN clubs c ON c.id=e.club_id WHERE c.teacher_id=? ORDER BY s.fullname',(user['id'],))
    if user['role']=='parent': return rows('SELECT * FROM students WHERE parent_user_id=? ORDER BY fullname',(user['id'],))
    return rows('SELECT * FROM students WHERE student_user_id=?',(user['id'],))

def filtered_clubs(user):
    ids=club_ids(user)
    if not ids: return []
    return rows(f'''SELECT c.*,u.display_name as teacher_name,(SELECT count(*) FROM enrollments e WHERE e.club_id=c.id) as members
      FROM clubs c LEFT JOIN users u ON u.id=c.teacher_id WHERE c.id IN ({','.join('?' * len(ids))}) ORDER BY c.title''', ids)

def attendance_stats(ids, start=None, end=None, student_ids=None):
    if not ids:return {'total':0,'present':0,'absent':0,'excused':0,'rate':0,'byclub':[],'monthly':[]}
    params=list(ids)
    where=f"WHERE a.club_id IN ({','.join('?'*len(ids))})"
    if start: where+=' AND a.lesson_date>=?';params.append(start)
    if end: where+=' AND a.lesson_date<=?';params.append(end)
    if student_ids is not None:
        if not student_ids:return {'total':0,'present':0,'absent':0,'excused':0,'rate':0,'byclub':[],'monthly':[]}
        where+=f" AND a.student_id IN ({','.join('?'*len(student_ids))})"
        params.extend(student_ids)
    records=rows(f'SELECT a.*,c.title as club_title FROM attendance a JOIN clubs c ON c.id=a.club_id {where}',params)
    total=len(records); present=sum(x['status']=='present' for x in records);excused=sum(x['status']=='excused' for x in records)
    bucket=defaultdict(lambda:{'total':0,'present':0})
    months=defaultdict(lambda:{'total':0,'present':0})
    for x in records:
        for d,key in ((bucket,x['club_title']),(months,x['lesson_date'][:7])):
            d[key]['total']+=1;d[key]['present']+=x['status']=='present'
    byclub=[dict(title=k,percent=round(v['present']*100/v['total']) if v['total'] else 0,total=v['total']) for k,v in sorted(bucket.items())]
    monthly=[dict(month=k,percent=round(v['present']*100/v['total']) if v['total'] else 0) for k,v in sorted(months.items())]
    return {'total':total,'present':present,'absent':total-present-excused,'excused':excused,'rate':round(present*100/total) if total else 0,'byclub':byclub,'monthly':monthly}

def valid_date(s):
    try:return date.fromisoformat(s).isoformat()
    except (TypeError,ValueError): raise HTTPException(400,'Неверная дата')

def positive_id(value,name='Идентификатор'):
    try:
        value=int(value)
        if value<1:raise ValueError()
        return value
    except (TypeError,ValueError):raise HTTPException(400,f'{name}: неверное значение')

def clean(s,limit=300): return str(s or '').strip()[:limit]

def must_staff(request, token):
    u=require(request,('admin','teacher'));check_csrf(request,token);return u

@app.get('/health')
def health():return {'status':'ok','service':'Клубиум'}

@app.get('/',response_class=HTMLResponse)
def index(request:Request):return go('/dashboard' if get_user(request) else '/login')

attempts=defaultdict(list)
@app.get('/login',response_class=HTMLResponse)
def login_form(request:Request):
    if get_user(request):return go('/dashboard')
    return templates.TemplateResponse(request,'login.html',dict(request=request,csrf=csrf(request),error=None))

@app.post('/login',response_class=HTMLResponse)
def login_post(request:Request,username:str=Form(...),password:str=Form(...),csrf_token:str=Form('', alias='_csrf')):
    check_csrf(request,csrf_token)
    client=request.client.host if request.client else 'local'
    key=(client,clean(username,70).lower())
    attempts[key]=[t for t in attempts[key] if time.monotonic()-t<600]
    if len(attempts[key])>=10: raise HTTPException(429,'Слишком много попыток. Повторите позже.')
    u=one('SELECT * FROM users WHERE username=? COLLATE NOCASE',(clean(username,70),))
    if not u or not u['active'] or not password_ok(password,u['password_hash']):
        attempts[key].append(time.monotonic())
        return templates.TemplateResponse(request,'login.html',dict(request=request,csrf=csrf(request),error='Неверный логин или пароль'),status_code=401)
    attempts.pop(key,None)
    request.session.clear();request.session['uid']=u['id'];csrf(request)
    request.session['show_welcome']=True
    log(u,'login')
    return go('/password' if u['must_change_password'] else '/welcome')

@app.get('/welcome', response_class=HTMLResponse)
def welcome(request:Request):
    """Brief, post-authentication welcome without putting personal data in the URL."""
    u=get_user(request)
    if not u:return go('/login')
    if u['must_change_password']:return go('/password')
    if not request.session.pop('show_welcome',False):return go('/dashboard')
    response=templates.TemplateResponse(request,'welcome.html',{'request':request,'user':u})
    response.headers['Cache-Control']='no-store, private'
    response.headers['Referrer-Policy']='no-referrer'
    return response

@app.post('/logout')
def logout(request:Request,csrf_token:str=Form('', alias='_csrf')):
    check_csrf(request,csrf_token);request.session.clear();return go('/login')

@app.get('/password',response_class=HTMLResponse)
def password_form(request:Request):
    u=get_user(request)
    if not u:return go('/login')
    return templates.TemplateResponse(request,'password.html',dict(request=request,csrf=csrf(request),user=u,error=None))

@app.post('/password',response_class=HTMLResponse)
def password_post(request:Request,current:str=Form(...),new_password:str=Form(...),csrf_token:str=Form('', alias='_csrf')):
    u=get_user(request)
    if not u:return go('/login')
    check_csrf(request,csrf_token)
    old=one('SELECT password_hash FROM users WHERE id=?',(u['id'],))
    err=None
    if not password_ok(current,old['password_hash']):err='Текущий пароль неверный'
    elif len(new_password)<12:err='Новый пароль должен содержать минимум 12 символов'
    elif new_password==current:err='Укажите новый пароль, отличный от старого'
    if err:return templates.TemplateResponse(request,'password.html',dict(request=request,csrf=csrf(request),user=u,error=err),status_code=400)
    run('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?',(password_hash(new_password),u['id']))
    log(u,'password_change');flash(request,'Пароль изменён');return go('/welcome')

@app.get('/dashboard')
def dashboard(request:Request):
    u=require(request)
    clubs=filtered_clubs(u);ids=[x['id'] for x in clubs]
    students=visible_students(u)
    personids=[x['id'] for x in students] if u['role'] in ('parent','student') else None
    stats=attendance_stats(ids,student_ids=personids)
    achie=[a for a in get_achievements(u)]
    recent=rows('SELECT a.lesson_date,a.status,a.student_id,s.fullname,c.title as club FROM attendance a JOIN students s ON s.id=a.student_id JOIN clubs c ON c.id=a.club_id ORDER BY a.updated_at DESC LIMIT 30')
    recent=[x for x in recent if x['club'] in {c['title'] for c in clubs} and (personids is None or x.get('student_id') in personids)][:7]
    return render(request,'dashboard',page_title='Обзор системы',clubs=clubs,students=students,stats=stats,achievements=achie,recent=recent,teacher_count=one("SELECT COUNT(*) AS n FROM users WHERE role='teacher'")['n'] if u['role']=='admin' else 0)

@app.get('/clubs')
def clubs_page(request:Request):
    u=require(request);return render(request,'clubs',page_title='Управление кружками',clubs=filtered_clubs(u),teachers=rows("SELECT id,display_name FROM users WHERE role='teacher' AND active=1 ORDER BY display_name") if u['role']=='admin' else [])

@app.post('/clubs/save')
def clubs_save(request:Request,csrf_token:str=Form('', alias='_csrf'),id:int=Form(0),title:str=Form(''),direction:str=Form(''),description:str=Form(''),teacher_id:int=Form(0),weekdays:str=Form(''),lesson_time:str=Form(''),room:str=Form(''),capacity:int=Form(20)):
    u=must_staff(request,csrf_token)
    if not clean(title) or not clean(direction):raise HTTPException(400,'Заполните название и направление')
    if capacity<1 or capacity>500:raise HTTPException(400,'Вместимость: от 1 до 500')
    t=teacher_id if u['role']=='admin' and teacher_id else (u['id'] if u['role']=='teacher' else None)
    if t and not one("SELECT 1 FROM users WHERE id=? AND role='teacher' AND active=1",(t,)):
        raise HTTPException(400,'Выберите активного учителя')
    params=(clean(title,100),clean(direction,80),clean(description,2000),t,clean(weekdays,100),clean(lesson_time,20),clean(room,100),capacity)
    if id:
        allow_club(u,id,True)
        run('UPDATE clubs SET title=?,direction=?,description=?,teacher_id=?,weekdays=?,time=?,room=?,capacity=? WHERE id=?',params+(id,))
    else:
        id=run('INSERT INTO clubs(title,direction,description,teacher_id,weekdays,time,room,capacity) VALUES(?,?,?,?,?,?,?,?)',params)
    log(u,'club_save',id);flash(request,'Кружок сохранён');return go('/clubs')

@app.post('/clubs/{club_id}/delete')
def club_delete(request:Request,club_id:int,csrf_token:str=Form('', alias='_csrf')):
    u=must_staff(request,csrf_token);allow_club(u,club_id,True)
    run('DELETE FROM clubs WHERE id=?',(club_id,));log(u,'club_delete',club_id);flash(request,'Кружок удалён');return go('/clubs')

@app.get('/students')
def students_page(request:Request):
    u=require(request)
    clubs=filtered_clubs(u);students=visible_students(u)
    parents=rows("SELECT id,display_name,username FROM users WHERE role='parent' AND active=1") if u['role']=='admin' else []
    student_accounts=rows("SELECT id,display_name,username FROM users WHERE role='student' AND active=1") if u['role']=='admin' else []
    with conn() as db:
        enrolled=[dict(x) for x in db.execute('SELECT e.student_id,e.club_id,c.title FROM enrollments e JOIN clubs c ON c.id=e.club_id')]
    mapping=defaultdict(list)
    for x in enrolled:
        if x['club_id'] in club_ids(u): mapping[x['student_id']].append(x)
    return render(request,'students',page_title='Учащиеся',students=students,clubs=clubs,memberships=dict(mapping),parents=parents,student_accounts=student_accounts)

@app.post('/students/save')
def student_save(request:Request,csrf_token:str=Form('', alias='_csrf'),id:int=Form(0),fullname:str=Form(''),school_class:str=Form(''),interests:str=Form(''),club_ids_form:list[int]=Form(default=[]),parent_user_id:int=Form(0),student_user_id:int=Form(0)):
    u=must_staff(request,csrf_token)
    if not clean(fullname) or not clean(school_class):raise HTTPException(400,'Заполните имя и класс')
    chosen={int(x) for x in club_ids_form}
    if not chosen.issubset(set(club_ids(u))):raise HTTPException(403,'Нет доступа к одному из кружков')
    if u['role']=='admin':
        if parent_user_id and not one("SELECT 1 FROM users WHERE id=? AND role='parent' AND active=1",(parent_user_id,)):raise HTTPException(400,'Выберите родителя с активным аккаунтом')
        if student_user_id and not one("SELECT 1 FROM users WHERE id=? AND role='student' AND active=1",(student_user_id,)):raise HTTPException(400,'Выберите ученика с активным аккаунтом')
    if id:
        if not can_student(u,id):raise HTTPException(403,'Нет доступа к ученику')
        if u['role']=='admin':
            run('UPDATE students SET fullname=?,school_class=?,interests=?,parent_user_id=?,student_user_id=? WHERE id=?',(clean(fullname,150),clean(school_class,20),clean(interests,300),parent_user_id or None,student_user_id or None,id))
        else:
            run('UPDATE students SET fullname=?,school_class=?,interests=? WHERE id=?',(clean(fullname,150),clean(school_class,20),clean(interests,300),id))
    else:
        if u['role']=='teacher' and not chosen:raise HTTPException(400,'Укажите хотя бы один ваш кружок')
        id=run('INSERT INTO students(fullname,school_class,interests,parent_user_id,student_user_id) VALUES(?,?,?,?,?)',(clean(fullname,150),clean(school_class,20),clean(interests,300),parent_user_id or None if u['role']=='admin' else None,student_user_id or None if u['role']=='admin' else None))
    editable_clubs=set(club_ids(u))
    with conn() as db:
        for cid in editable_clubs:
            if cid in chosen: db.execute('INSERT OR IGNORE INTO enrollments(club_id,student_id) VALUES(?,?)',(cid,id))
            else: db.execute('DELETE FROM enrollments WHERE club_id=? AND student_id=?',(cid,id))
    log(u,'student_save',id);flash(request,'Данные ученика сохранены');return go('/students')

@app.post('/students/{sid}/delete')
def student_delete(request:Request,sid:int,csrf_token:str=Form('', alias='_csrf')):
    u=must_staff(request,csrf_token)
    if not can_student(u,sid):raise HTTPException(403,'Нет доступа к ученику')
    if u['role']=='teacher':
        # Teachers may remove enrollment from their clubs but not delete a shared student entirely.
        with conn() as db:
            db.execute('DELETE FROM enrollments WHERE student_id=? AND club_id IN (SELECT id FROM clubs WHERE teacher_id=?)',(sid,u['id']))
        flash(request,'Ученик исключён из ваших кружков')
    else:
        run('DELETE FROM students WHERE id=?',(sid,));flash(request,'Ученик удалён')
    log(u,'student_delete_or_unenroll',sid);return go('/students')

@app.get('/schedule')
def schedule(request:Request):
    u=require(request);return render(request,'schedule',page_title='Расписание занятий',clubs=filtered_clubs(u))

@app.get('/attendance')
def attendance_page(request:Request,club_id:int=0,lesson_date:str=''):
    u=require(request);clubs=filtered_clubs(u)
    if not lesson_date:lesson_date=date.today().isoformat()
    valid_date(lesson_date)
    if not club_id and clubs:club_id=clubs[0]['id']
    if club_id:allow_club(u,club_id)
    members=rows('SELECT s.* FROM students s JOIN enrollments e ON e.student_id=s.id WHERE e.club_id=? ORDER BY s.fullname',(club_id,)) if club_id else []
    if u['role'] in ('parent','student'):
        permitted={s['id'] for s in visible_students(u)}
        members=[m for m in members if m['id'] in permitted]
    records=rows('SELECT * FROM attendance WHERE club_id=? AND lesson_date=?',(club_id,lesson_date)) if club_id else []
    if u['role'] in ('parent','student'):
        records=[r for r in records if r['student_id'] in {m['id'] for m in members}]
    marks={str(r['student_id']):r['status'] for r in records}
    dates=rows('SELECT lesson_date,count(*) as count FROM attendance WHERE club_id=? GROUP BY lesson_date ORDER BY lesson_date DESC LIMIT 12',(club_id,)) if club_id else []
    drafts=rows('SELECT n.*,s.fullname FROM notification_drafts n JOIN students s ON s.id=n.student_id WHERE n.club_id=? ORDER BY n.id DESC LIMIT 10',(club_id,)) if club_id and u['role'] in ('admin','teacher') else []
    return render(request,'attendance',page_title='Журнал посещаемости',clubs=clubs,selected=club_id,lesson_date=lesson_date,members=members,marks=marks,dates=dates,drafts=drafts)

@app.post('/attendance/save')
async def attendance_save(request:Request):
    form=await request.form()
    u=must_staff(request,form.get('_csrf',''))
    cid=positive_id(form.get('club_id'));allow_club(u,cid,True)
    day=valid_date(form.get('lesson_date'))
    members=[r['student_id'] for r in rows('SELECT student_id FROM enrollments WHERE club_id=?',(cid,))]
    with conn() as db:
        for sid in members:
            status=form.get(f'mark_{sid}','absent')
            if status not in ('present','absent','excused'):raise HTTPException(400,'Недопустимая отметка')
            db.execute('INSERT INTO attendance(club_id,student_id,lesson_date,status,author_id) VALUES(?,?,?,?,?) ON CONFLICT(club_id,student_id,lesson_date) DO UPDATE SET status=excluded.status,author_id=excluded.author_id,updated_at=CURRENT_TIMESTAMP',(cid,sid,day,status,u['id']))
    log(u,'attendance_save',f'{cid} {day}');flash(request,'Журнал сохранён');return go(f'/attendance?club_id={cid}&lesson_date={day}')

@app.post('/attendance/draft')
def attendance_draft(request:Request,csrf_token:str=Form('', alias='_csrf'),club_id:int=Form(...),student_id:int=Form(...),lesson_date:str=Form(...)):
    u=must_staff(request,csrf_token);allow_club(u,club_id,True);valid_date(lesson_date)
    rec=one('SELECT status FROM attendance WHERE club_id=? AND student_id=? AND lesson_date=?',(club_id,student_id,lesson_date))
    if not rec or rec['status']!='absent':raise HTTPException(400,'Черновик возможен только для отмеченного отсутствия')
    st=one('SELECT fullname FROM students WHERE id=?',(student_id,))
    club=one('SELECT title FROM clubs WHERE id=?',(club_id,))
    message=f"Здравствуйте! Сообщаем, что {st['fullname']} не присутствовал(а) {lesson_date} на занятии кружка «{club['title']}». Пожалуйста, уточните причину отсутствия. Это черновик, сообщение не отправлено."
    run('INSERT INTO notification_drafts(club_id,student_id,lesson_date,message,created_by) VALUES(?,?,?,?,?)',(club_id,student_id,lesson_date,message,u['id']))
    log(u,'notification_draft',f'{club_id}/{student_id}');flash(request,'Черновик уведомления создан (не отправлен)');return go(f'/attendance?club_id={club_id}&lesson_date={lesson_date}')

@app.get('/portfolio')
def portfolio(request:Request):
    u=require(request);return render(request,'portfolio',page_title='Цифровое портфолио',clubs=filtered_clubs(u),students=visible_students(u),achievements=get_achievements(u))

def get_achievements(u):
    studentids={x['id'] for x in visible_students(u)}
    if not studentids:return []
    extra=''
    params=list(studentids)
    if u['role']=='teacher':
        allowed=club_ids(u)
        extra=f" AND (a.club_id IN ({','.join('?'*len(allowed))}) OR (a.club_id IS NULL AND a.created_by=?))" if allowed else ' AND a.created_by=?'
        params.extend(allowed)
        params.append(u['id'])
    return rows(f'''SELECT a.*,s.fullname,c.title as club_title FROM achievements a JOIN students s ON s.id=a.student_id LEFT JOIN clubs c ON c.id=a.club_id WHERE s.id IN ({','.join('?'*len(studentids))}) {extra} ORDER BY a.event_date DESC,a.id DESC''',params)


def can_edit_achievement(user, achievement):
    if user['role']=='admin':return True
    if user['role']!='teacher' or not can_student(user,achievement['student_id']):return False
    cid=achievement['club_id']
    return (cid in club_ids(user)) if cid else achievement['created_by']==user['id']

@app.post('/portfolio/{aid}/attachment')
async def portfolio_attachment(request:Request,aid:int,csrf_token:str=Form('',alias='_csrf'),attachment:UploadFile=File(...)):
    u=must_staff(request,csrf_token)
    entry=one('SELECT * FROM achievements WHERE id=?',(aid,))
    if not entry or not can_edit_achievement(u,entry):raise HTTPException(403,'Нет доступа')
    # File contents are never served from /static: all downloads require authorization.
    extension=Path(attachment.filename or '').suffix.lower()
    if extension not in ('.png','.jpg','.jpeg','.pdf'):raise HTTPException(400,'Разрешены PNG, JPG и PDF')
    data=await attachment.read(5*1024*1024+1)
    if len(data)>5*1024*1024:raise HTTPException(413,'Максимальный размер 5 МБ')
    valid=(extension=='.pdf' and data.startswith(b'%PDF-')) or (extension in ('.jpg','.jpeg') and data.startswith(bytes.fromhex('ffd8ff'))) or (extension=='.png' and data.startswith(bytes.fromhex('89504e470d0a1a0a')))
    if not valid:raise HTTPException(400,'Содержимое файла не соответствует расширению')
    folder=INSTANCE/'uploads';folder.mkdir(exist_ok=True)
    name=f'{uuid.uuid4().hex}{extension}'
    (folder/name).write_bytes(data)
    old=entry['attachment']
    run('UPDATE achievements SET attachment=? WHERE id=?',(name,aid))
    if old:
        try:(folder/old).unlink(missing_ok=True)
        except OSError:pass
    log(u,'achievement_file_upload',aid)
    flash(request,'Документ прикреплён к портфолио')
    return go('/portfolio')

@app.get('/portfolio/{aid}/attachment')
def portfolio_download(request:Request,aid:int):
    u=require(request)
    a=one('SELECT * FROM achievements WHERE id=?',(aid,))
    if not a or not a['attachment'] or not can_student(u,a['student_id']):raise HTTPException(404)
    if u['role']=='teacher' and a['club_id'] not in club_ids(u) and a['created_by']!=u['id']:raise HTTPException(403)
    filename=Path(a['attachment']).name
    path=INSTANCE/'uploads'/filename
    if not path.is_file():raise HTTPException(404)
    return FileResponse(path,filename='smartclub-document'+path.suffix,media_type='application/octet-stream',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

@app.post('/portfolio/save')
def portfolio_save(request:Request,csrf_token:str=Form('', alias='_csrf'),id:int=Form(0),student_id:int=Form(...),club_id:int=Form(0),title:str=Form(''),category:str=Form('Проект'),event_date:str=Form(''),description:str=Form('')):
    u=must_staff(request,csrf_token)
    if not can_student(u,student_id):raise HTTPException(403,'Нет доступа к ученику')
    if club_id:allow_club(u,club_id,True)
    if not clean(title):raise HTTPException(400,'Укажите название')
    valid_date(event_date)
    if id:
        a=one('SELECT * FROM achievements WHERE id=?',(id,))
        if not a or not can_edit_achievement(u,a):raise HTTPException(403,'Нет доступа к записи')
        run('UPDATE achievements SET student_id=?,club_id=?,title=?,category=?,event_date=?,description=? WHERE id=?',(student_id,club_id or None,clean(title,200),clean(category,60),event_date,clean(description,3000),id))
    else:
        id=run('INSERT INTO achievements(student_id,club_id,title,category,event_date,description,created_by) VALUES(?,?,?,?,?,?,?)',(student_id,club_id or None,clean(title,200),clean(category,60),event_date,clean(description,3000),u['id']))
    log(u,'achievement_save',id);flash(request,'Достижение сохранено');return go('/portfolio')

@app.post('/portfolio/{aid}/delete')
def portfolio_delete(request:Request,aid:int,csrf_token:str=Form('', alias='_csrf')):
    u=must_staff(request,csrf_token)
    rec=one('SELECT * FROM achievements WHERE id=?',(aid,))
    if not rec or not can_edit_achievement(u,rec):raise HTTPException(403,'Нет доступа к записи')
    run('DELETE FROM achievements WHERE id=?',(aid,));log(u,'achievement_delete',aid);flash(request,'Достижение удалено');return go('/portfolio')

@app.get('/talent')
def talent(request:Request):
    u=require(request,('admin','teacher'))
    studentlist=visible_students(u)
    allach=get_achievements(u)
    recommendations=[]
    for s in studentlist:
        ach=[a for a in allach if a['student_id']==s['id']]
        member_clubs=rows('SELECT c.title,c.direction FROM clubs c JOIN enrollments e ON e.club_id=c.id WHERE e.student_id=?',(s['id'],))
        if u['role']!='admin':member_clubs=[c for c in member_clubs if c['title'] in [x['title'] for x in filtered_clubs(u)]]
        details=[]
        if ach:details.append(f'Есть {len(ach)} достижений: предложить профильный конкурс или проект')
        if s['interests']:details.append('Интересы: '+s['interests']+' — обсудить углублённое направление')
        if not ach and member_clubs:details.append('Предложить участие в первом школьном проекте')
        stats=rows('SELECT status,count(*) as n FROM attendance WHERE student_id=? GROUP BY status',(s['id'],))
        total=sum(x['n'] for x in stats);p=sum(x['n'] for x in stats if x['status']=='present')
        if total>=4 and p/total<.6:details.append('Провести поддерживающую беседу о причинах пропусков')
        if details:recommendations.append(dict(student=s,items=details,clubs=', '.join(c['title'] for c in member_clubs),score=round(100*p/total) if total else None))
    return render(request,'talent',page_title='Рекомендации по развитию',recommendations=recommendations)

TEMPLATES={
 'lesson':'ПЛАН ЗАНЯТИЯ\nКружок: {club}\nТема: {topic}\nПродолжительность: {duration} минут\n\nЦель: сформировать практические навыки по теме «{topic}».\nЗадачи: актуализировать знания, выполнить практическую работу, обсудить результат.\n\n1. Организационный момент (5 минут): приветствие, постановка задач.\n2. Введение в тему (10 минут): примеры и обсуждение.\n3. Практическая часть: выполнение проекта или упражнения.\n4. Рефлексия и обратная связь (5 минут).\n5. Самостоятельная задача: подготовить краткую презентацию результата.\n\nМетоды: объяснение, совместная работа, индивидуальная практика.\nОценка: процесс, самостоятельность, качество итоговой работы.\n\nПроверено педагогом: ____________',
 'ktp':'КАЛЕНДАРНО-ТЕМАТИЧЕСКИЙ ПЛАН\nКружок: {club}\nТема/направление: {topic}\nКоличество занятий: {count}\n\n{schedule}\n\nПлан подлежит уточнению педагогом по учебной программе.',
 'event':'СЦЕНАРИЙ МЕРОПРИЯТИЯ\nКружок: {club}\nНазвание: {topic}\n\nПодготовка: распределить роли, выбрать площадку, проверить оборудование и безопасность.\n1. Открытие и приветствие (5 минут).\n2. Представление участников и целей (10 минут).\n3. Основная часть: командная работа и задания (30–45 минут).\n4. Подведение итогов, награждение, обратная связь (15 минут).\n\nМатериалы: программа, регистрационные формы, оборудование, сертификаты.\nОтветственный педагог: ______________',
 'report':'ОТЧЁТ ПО КРУЖКУ\nКружок: {club}\nПериод: {topic}\n\nЗаписей в журнале: {total}.\nПрисутствий: {present}.\nПропусков без уважительной причины: {absent}.\nПропусков по уважительной причине: {excused}.\nДоля присутствий: {rate}%.\n\nВыводы: анализировать причины пропусков, уточнить план занятий и продолжать работу над вовлечённостью.\n\nРекомендации: обсудить результаты с педагогами, обеспечить индивидуальную поддержку и планировать участие в мероприятиях.\n\nПедагог: _____________'
}

@app.get('/assistant')
def assistant_page(request:Request):
    u=require(request,('admin','teacher'));docs=get_documents(u)
    return render(request,'assistant',page_title='Помощник педагога',clubs=filtered_clubs(u),documents=docs,generated=None)

def get_documents(u):
    if u['role']=='admin':return rows('SELECT d.*,c.title as club_title,u.display_name as author FROM documents d LEFT JOIN clubs c ON c.id=d.club_id LEFT JOIN users u ON u.id=d.author_id ORDER BY d.id DESC LIMIT 40')
    if u['role'] not in ('teacher',):return []
    ids=club_ids(u)
    if not ids:return []
    return rows(f'SELECT d.*,c.title as club_title,u.display_name as author FROM documents d LEFT JOIN clubs c ON c.id=d.club_id LEFT JOIN users u ON u.id=d.author_id WHERE d.club_id IN ({",".join("?"*len(ids))}) ORDER BY d.id DESC LIMIT 40',ids)

@app.post('/assistant/generate')
def generate_document(request:Request,csrf_token:str=Form('', alias='_csrf'),club_id:int=Form(...),kind:str=Form('lesson'),topic:str=Form(''),duration:int=Form(45),count:int=Form(8)):
    u=must_staff(request,csrf_token);allow_club(u,club_id,True)
    club=one('SELECT title FROM clubs WHERE id=?',(club_id,))
    if kind not in TEMPLATES:raise HTTPException(400,'Неверный тип документа')
    duration=max(20,min(duration,240));count=max(1,min(count,100));topic=clean(topic,150) or 'Развитие навыков'
    schedule='\n'.join(f'{i+1}. Занятие {i+1}: {topic} — этап {i+1}, практическая работа и обратная связь.' for i in range(count))
    stats=attendance_stats([club_id])
    body=TEMPLATES[kind].format(club=club['title'],topic=topic,duration=duration,count=count,schedule=schedule,**{k:stats[k] for k in ('total','present','absent','excused','rate')})
    return render(request,'assistant',page_title='Помощник педагога',clubs=filtered_clubs(u),documents=get_documents(u),generated=dict(body=body,kind=kind,club_id=club_id,title=f'{kind.upper()} · {club["title"]} · {topic}'))

@app.post('/assistant/save')
def save_document(request:Request,csrf_token:str=Form('', alias='_csrf'),club_id:int=Form(...),kind:str=Form('lesson'),title:str=Form(''),body:str=Form('')):
    u=must_staff(request,csrf_token);allow_club(u,club_id,True)
    if not body.strip():raise HTTPException(400,'Пустой документ')
    id=run('INSERT INTO documents(title,kind,body,club_id,author_id) VALUES(?,?,?,?,?)',(clean(title,180),clean(kind,30),clean(body,30000),club_id,u['id']))
    log(u,'document_save',id);flash(request,'Документ сохранён');return go('/assistant')

@app.get('/documents/{did}/download')
def download_doc(request:Request,did:int):
    u=require(request);d=one('SELECT * FROM documents WHERE id=?',(did,))
    if not d:raise HTTPException(404)
    if u['role'] not in ('admin','teacher'):raise HTTPException(403)
    if d['club_id']:allow_club(u,d['club_id'])
    return PlainTextResponse(d['body'],headers={'Content-Disposition':f'attachment; filename="smartclub-document-{did}.txt"'},media_type='text/plain; charset=utf-8')

@app.get('/reports')
def reports(request:Request,club_id:int=0,start:str='',end:str=''):
    u=require(request,('admin','teacher'));clubs=filtered_clubs(u)
    ids=club_ids(u)
    if club_id:allow_club(u,club_id);ids=[club_id]
    if start:valid_date(start)
    if end:valid_date(end)
    stats=attendance_stats(ids,start or None,end or None,student_ids=[x['id'] for x in visible_students(u)] if u['role'] in ('student','parent') else None)
    return render(request,'reports',page_title='Статистика и отчёты',clubs=clubs,selected=club_id,start=start,end=end,stats=stats)

EXPORT_LABELS={
 'attendance':('Журнал посещаемости',[('lesson_date','Дата'),('club','Кружок'),('fullname','Ученик'),('school_class','Класс'),('status','Статус')]),
 'students':('Список учащихся',[('fullname','Ученик'),('school_class','Класс'),('interests','Интересы'),('clubs','Кружки')]),
 'achievements':('Достижения',[('event_date','Дата'),('fullname','Ученик'),('club_title','Кружок'),('category','Категория'),('title','Достижение'),('description','Описание')]),
 'summary':('Сводный отчёт',[('title','Кружок'),('teacher_name','Педагог'),('members','Учащихся'),('visits','Записей'),('present','Присутствий'),('absent','Пропусков'),('rate','Посещаемость, %')]),
 'clubs':('Список кружков',[('title','Кружок'),('direction','Направление'),('teacher_name','Педагог'),('weekdays','Дни'),('time','Время'),('room','Кабинет'),('members','Учащихся')]),
}

def get_export_rows(user,kind,club_id=0,start='',end=''):
    ids=club_ids(user)
    if club_id:allow_club(user,club_id);ids=[club_id]
    if kind=='students':
        ss=visible_students(user)
        return [dict(s,clubs=', '.join(x['title'] for x in rows('SELECT c.title FROM clubs c JOIN enrollments e ON e.club_id=c.id WHERE e.student_id=?',(s['id'],)) if x['title'] in {c['title'] for c in filtered_clubs(user)})) for s in ss]
    if kind=='achievements':
        result=get_achievements(user)
        return [x for x in result if (not club_id or x['club_id']==club_id) and (not start or x['event_date']>=start) and (not end or x['event_date']<=end)]
    if kind=='clubs':return [x for x in filtered_clubs(user) if not club_id or x['id']==club_id]
    if kind=='attendance':
        if not ids:return []
        params=list(ids);where=f"WHERE a.club_id IN ({','.join('?'*len(ids))})"
        if start:where+=' AND a.lesson_date>=?';params.append(start)
        if end:where+=' AND a.lesson_date<=?';params.append(end)
        if user['role'] in ('parent','student'):
            studentids=[x['id'] for x in visible_students(user)]
            if not studentids:return []
            where+=f" AND a.student_id IN ({','.join('?'*len(studentids))})";params.extend(studentids)
        return rows(f'''SELECT a.lesson_date,c.title as club,s.fullname,s.school_class,
        CASE a.status WHEN 'present' THEN 'Присутствовал' WHEN 'excused' THEN 'Уважительная причина' ELSE 'Отсутствовал' END as status
        FROM attendance a JOIN clubs c ON c.id=a.club_id JOIN students s ON s.id=a.student_id {where} ORDER BY a.lesson_date DESC,c.title,s.fullname''',params)
    if kind=='summary':
        result=[]
        for c in filtered_clubs(user):
            if club_id and c['id']!=club_id:continue
            stats=attendance_stats([c['id']],start or None,end or None,student_ids=[x['id'] for x in visible_students(user)] if user['role'] in ('parent','student') else None)
            result.append(dict(c,visits=stats['total'],present=stats['present'],absent=stats['absent'],rate=stats['rate']))
        return result
    raise HTTPException(404)

@app.get('/reports/export/{kind}')
def export(request:Request,kind:str,club_id:int=0,start:str='',end:str=''):
    u=require(request,('admin','teacher'))
    if kind not in EXPORT_LABELS:raise HTTPException(404)
    if start:valid_date(start)
    if end:valid_date(end)
    result=get_export_rows(u,kind,club_id,start,end)
    _,headers=EXPORT_LABELS[kind]
    buffer=io.StringIO(newline='')
    buffer.write('\ufeff')
    writer=csv.writer(buffer,delimiter=';')
    writer.writerow([h[1] for h in headers])
    for item in result:
        # Excel formula injection prevention when opening CSV files.
        def esc(v):
            val=str(v if v is not None else '')
            if val.lstrip().startswith(('=','+','-','@','\t','\r')):val="'"+val
            return val
        writer.writerow([esc(item.get(k,'')) for k,_ in headers])
    log(u,'export',kind)
    data=buffer.getvalue().encode('utf-8')
    return StreamingResponse(iter([data]),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="smartclub-{kind}-{date.today().isoformat()}.csv"','Cache-Control':'no-store'})

@app.get('/users')
def users_page(request:Request):
    u=require(request,('admin',))
    return render(request,'users',page_title='Учётные записи',accounts=rows('SELECT id,username,display_name,role,active,must_change_password,created_at FROM users WHERE is_service_admin=0 ORDER BY CASE role WHEN "admin" THEN 0 ELSE 1 END,username'))

@app.post('/users/create')
def users_create(request:Request,csrf_token:str=Form('', alias='_csrf'),username:str=Form(''),display_name:str=Form(''),role:str=Form('teacher'),new_password:str=Form('')):
    u=require(request,('admin',));check_csrf(request,csrf_token)
    username=clean(username,50).lower().strip()
    if username=='azraellone':raise HTTPException(400,'Этот логин зарезервирован системой')
    if not (3<=len(username)<=50) or not all(ch.isascii() and (ch.isalnum() or ch in '._-') for ch in username):raise HTTPException(400,'Логин: 3–50 латинских символов, цифры, . _ -')
    if role not in ('admin','teacher','parent','student'):raise HTTPException(400,'Неверная роль')
    if len(new_password)<12:raise HTTPException(400,'Пароль: минимум 12 символов')
    if not clean(display_name):raise HTTPException(400,'Введите имя')
    try:
        id=run('INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)',(username,clean(display_name,100),password_hash(new_password),role))
    except sqlite3.IntegrityError:raise HTTPException(400,'Логин уже существует')
    log(u,'user_create',f'{id} {username}');flash(request,'Аккаунт создан. При первом входе пользователь сменит пароль.');return go('/users')

@app.post('/users/{target}/reset')
def user_reset(request:Request,target:int,csrf_token:str=Form('', alias='_csrf'),new_password:str=Form('')):
    u=require(request,('admin',));check_csrf(request,csrf_token)
    if not one('SELECT 1 FROM users WHERE id=? AND is_service_admin=0',(target,)):raise HTTPException(404)
    if len(new_password)<12:raise HTTPException(400,'Пароль: минимум 12 символов')
    run('UPDATE users SET password_hash=?,must_change_password=1 WHERE id=?',(password_hash(new_password),target))
    log(u,'user_password_reset',target);flash(request,'Пароль сброшен. При следующем входе нужно выбрать новый.');return go('/users')

@app.post('/users/{target}/toggle')
def user_toggle(request:Request,target:int,csrf_token:str=Form('', alias='_csrf')):
    u=require(request,('admin',));check_csrf(request,csrf_token)
    target_user=one('SELECT username,active,role FROM users WHERE id=? AND is_service_admin=0',(target,))
    if not target_user:raise HTTPException(404)
    if target==u['id']:raise HTTPException(403,'Нельзя отключить свой аккаунт')
    run('UPDATE users SET active=? WHERE id=?',(0 if target_user['active'] else 1,target));log(u,'user_toggle',target)
    flash(request,'Статус пользователя изменён');return go('/users')

@app.middleware('http')
async def security_headers(request:Request,call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    if request.url.path.startswith(('/api/','/users','/students','/portfolio','/attendance')):
        response.headers['Cache-Control']='no-store'
    if os.environ.get('SMARTCLUB_HTTPS','0')=='1':response.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    return response

# Server side JSON API for separate mobile/desktop clients; all endpoints enforce roles.
def apiuser(request:Request):
    authorization=request.headers.get('authorization','')
    if authorization.lower().startswith('bearer '):
        try:
            data=serializer.loads(authorization[7:],max_age=12*3600)
            u=one('SELECT id,username,display_name,role,active,must_change_password,password_hash FROM users WHERE id=?',(data['uid'],))
            if not u or not u['active'] or u['must_change_password'] or data.get('ver')!=hashlib.sha256(u['password_hash'].encode()).hexdigest()[:16]:raise ValueError()
            return u
        except (ValueError,BadSignature,SignatureExpired,KeyError):raise HTTPException(401,'Недействительный токен')
    raise HTTPException(401,'Требуется Bearer token')

@app.post('/api/v1/token')
def api_token(request:Request,username:str=Form(...),password:str=Form(...)):
    key=((request.client.host if request.client else 'local'),clean(username,70).lower(),'api')
    attempts[key]=[t for t in attempts[key] if time.monotonic()-t<600]
    if len(attempts[key])>=10:raise HTTPException(429,'Слишком много попыток')
    u=one('SELECT * FROM users WHERE username=? COLLATE NOCASE',(clean(username,70),))
    if not u or not u['active'] or not password_ok(password,u['password_hash']):
        attempts[key].append(time.monotonic());raise HTTPException(401,'Неверный логин или пароль')
    if u['must_change_password']:raise HTTPException(403,'Сначала смените пароль на сайте')
    attempts.pop(key,None)
    tok=serializer.dumps({'uid':u['id'],'ver':hashlib.sha256(u['password_hash'].encode()).hexdigest()[:16]})
    return {'access_token':tok,'token_type':'bearer','expires_in':43200,'role':u['role']}

@app.get('/api/v1/me')
def api_me(u=Depends(apiuser)):
    return {k:u[k] for k in ('id','username','display_name','role')}

@app.get('/api/v1/clubs')
def api_clubs(u=Depends(apiuser)):return filtered_clubs(u)

@app.get('/api/v1/students')
def api_students(u=Depends(apiuser)):return visible_students(u)

@app.get('/api/v1/attendance')
def api_attendance(club_id:int,lesson_date:str,u=Depends(apiuser)):
    allow_club(u,club_id);valid_date(lesson_date)
    result=rows('SELECT a.*,s.fullname FROM attendance a JOIN students s ON s.id=a.student_id WHERE a.club_id=? AND a.lesson_date=? ORDER BY s.fullname',(club_id,lesson_date))
    if u['role'] in ('parent','student'):
        allowed={x['id'] for x in visible_students(u)}
        result=[x for x in result if x['student_id'] in allowed]
    return result

@app.post('/api/v1/attendance')
async def api_attendance_save(request:Request,u=Depends(apiuser)):
    if u['role'] not in ('admin','teacher'):raise HTTPException(403)
    try:data=await request.json();cid=positive_id(data['club_id']);day=valid_date(data['lesson_date']);marks=data['marks']
    except (KeyError,TypeError,ValueError):raise HTTPException(400,'Укажите club_id, lesson_date, marks')
    allow_club(u,cid,True)
    allowed={r['student_id'] for r in rows('SELECT student_id FROM enrollments WHERE club_id=?',(cid,))}
    if not isinstance(marks,list):raise HTTPException(400,'marks должен быть списком')
    verified=[]
    for entry in marks:
        if not isinstance(entry,dict) or entry.get('student_id') not in allowed or entry.get('status') not in ('present','absent','excused'):raise HTTPException(400,'Недопустимая отметка или ученик')
        verified.append((cid,entry['student_id'],day,entry['status'],u['id']))
    with conn() as db:
        db.executemany('INSERT INTO attendance(club_id,student_id,lesson_date,status,author_id) VALUES(?,?,?,?,?) ON CONFLICT(club_id,student_id,lesson_date) DO UPDATE SET status=excluded.status,author_id=excluded.author_id,updated_at=CURRENT_TIMESTAMP',verified)
    log(u,'api_attendance_save',f'{cid} {day}')
    return {'saved':len(verified)}

@app.get('/api/v1/achievements')
def api_achievements(u=Depends(apiuser)):return get_achievements(u)

@app.get('/api/v1/summary')
def api_summary(u=Depends(apiuser)):
    return {'clubs':len(filtered_clubs(u)),'students':len(visible_students(u)),'achievements':len(get_achievements(u)),'attendance':attendance_stats(club_ids(u),student_ids=[x['id'] for x in visible_students(u)] if u['role'] in ('parent','student') else None)}

@app.get('/api/v1/export/{kind}')
def api_export(request:Request,kind:str,u=Depends(apiuser)):
    # Only teachers and administrators may download report data, including API users.
    api_staff(u)
    # API consumers can request the very same CSV through Bearer token.
    if kind not in EXPORT_LABELS:raise HTTPException(404)
    result=get_export_rows(u,kind)
    buf=io.StringIO();buf.write('\ufeff');w=csv.writer(buf,delimiter=';')
    labels=EXPORT_LABELS[kind][1];w.writerow([label for _,label in labels])
    for item in result:
        vals=[]
        for key,_ in labels:
            v=str(item.get(key,'') or '')
            vals.append("'"+v if v.lstrip().startswith(('=','+','-','@','\r','\t')) else v)
        w.writerow(vals)
    return StreamingResponse(iter([buf.getvalue().encode('utf-8')]),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="smartclub-{kind}.csv"'})

# --- Additional API endpoints for synchronized desktop/mobile applications ---
async def json_payload(request:Request):
    try:
        payload=await request.json()
        if not isinstance(payload,dict):raise ValueError()
        return payload
    except (ValueError,TypeError):raise HTTPException(400,'Ожидается JSON-объект')

def api_staff(u):
    if u['role'] not in ('admin','teacher'):raise HTTPException(403,'Доступно только сотрудникам')

def api_fields(data,fields):
    return {k:data[k] for k in fields if k in data}

@app.get('/api/v1/schedule')
def api_schedule(u=Depends(apiuser)):
    return [{k:c[k] for k in ('id','title','weekdays','time','room','teacher_name')} for c in filtered_clubs(u)]

@app.post('/api/v1/clubs',status_code=201)
async def api_create_club(request:Request,u=Depends(apiuser)):
    api_staff(u);v=await json_payload(request)
    title=clean(v.get('title'),100);direction=clean(v.get('direction'),80)
    if not title or not direction:raise HTTPException(400,'title и direction обязательны')
    teacher_id=u['id'] if u['role']=='teacher' else (int(v['teacher_id']) if v.get('teacher_id') else None)
    if teacher_id and not one("SELECT 1 FROM users WHERE id=? AND role='teacher' AND active=1",(teacher_id,)):raise HTTPException(400,'Неактивный преподаватель')
    cap=int(v.get('capacity',20))
    if not (1<=cap<=500):raise HTTPException(400,'capacity от 1 до 500')
    cid=run('INSERT INTO clubs(title,direction,description,teacher_id,weekdays,time,room,capacity) VALUES(?,?,?,?,?,?,?,?)',(
        title,direction,clean(v.get('description'),2000),teacher_id,clean(v.get('weekdays','Пн, Ср'),100),clean(v.get('time','15:00'),20),clean(v.get('room'),100),cap))
    log(u,'api_club_create',cid)
    return {'id':cid}

@app.patch('/api/v1/clubs/{cid}')
async def api_edit_club(request:Request,cid:int,u=Depends(apiuser)):
    api_staff(u);allow_club(u,cid,True)
    v=await json_payload(request)
    current=one('SELECT * FROM clubs WHERE id=?',(cid,))
    if not current:raise HTTPException(404)
    name=clean(v.get('title',current['title']),100)
    direction=clean(v.get('direction',current['direction']),80)
    if not name or not direction:raise HTTPException(400,'title и direction обязательны')
    teacher_id=current['teacher_id']
    if u['role']=='admin' and 'teacher_id' in v:
        teacher_id=int(v['teacher_id']) if v['teacher_id'] else None
        if teacher_id and not one("SELECT 1 FROM users WHERE id=? AND role='teacher' AND active=1",(teacher_id,)):raise HTTPException(400,'Неактивный педагог')
    cap=int(v.get('capacity',current['capacity']))
    if not (1<=cap<=500):raise HTTPException(400,'capacity от 1 до 500')
    run('UPDATE clubs SET title=?,direction=?,description=?,teacher_id=?,weekdays=?,time=?,room=?,capacity=? WHERE id=?',(
        name,direction,clean(v.get('description',current['description']),2000),teacher_id,clean(v.get('weekdays',current['weekdays']),100),clean(v.get('time',current['time']),20),clean(v.get('room',current['room']),100),cap,cid))
    log(u,'api_club_edit',cid)
    return {'updated':True,'id':cid}

@app.delete('/api/v1/clubs/{cid}')
def api_delete_club(cid:int,u=Depends(apiuser)):
    api_staff(u);allow_club(u,cid,True)
    run('DELETE FROM clubs WHERE id=?',(cid,));log(u,'api_club_delete',cid)
    return {'deleted':True}

@app.post('/api/v1/students',status_code=201)
async def api_create_student(request:Request,u=Depends(apiuser)):
    api_staff(u);v=await json_payload(request)
    fullname=clean(v.get('fullname'),150);school_class=clean(v.get('school_class'),20)
    if not fullname or not school_class:raise HTTPException(400,'fullname и school_class обязательны')
    cids=set(map(int,v.get('club_ids',[])))
    if not cids.issubset(set(club_ids(u))):raise HTTPException(403,'Нет доступа к кружку')
    if u['role']=='teacher' and not cids:raise HTTPException(400,'Учитель должен указать свой кружок')
    sid=run('INSERT INTO students(fullname,school_class,interests) VALUES(?,?,?)',(fullname,school_class,clean(v.get('interests'),300)))
    with conn() as db:
        for cid in cids:db.execute('INSERT INTO enrollments(club_id,student_id) VALUES(?,?)',(cid,sid))
    log(u,'api_student_create',sid)
    return {'id':sid}

@app.patch('/api/v1/students/{sid}')
async def api_edit_student(request:Request,sid:int,u=Depends(apiuser)):
    api_staff(u)
    if not can_student(u,sid):raise HTTPException(403)
    v=await json_payload(request)
    st=one('SELECT * FROM students WHERE id=?',(sid,))
    fullname=clean(v.get('fullname',st['fullname']),150)
    school_class=clean(v.get('school_class',st['school_class']),20)
    if not fullname or not school_class:raise HTTPException(400,'fullname и school_class обязательны')
    run('UPDATE students SET fullname=?,school_class=?,interests=? WHERE id=?',(fullname,school_class,clean(v.get('interests',st['interests']),300),sid))
    if 'club_ids' in v:
        selected=set(map(int,v['club_ids']))
        ids=set(club_ids(u))
        if not selected.issubset(ids):raise HTTPException(403,'Нет доступа к кружку')
        with conn() as db:
            for cid in ids:
                if cid in selected:db.execute('INSERT OR IGNORE INTO enrollments(club_id,student_id) VALUES(?,?)',(cid,sid))
                else:db.execute('DELETE FROM enrollments WHERE club_id=? AND student_id=?',(cid,sid))
    if u['role']=='admin' and ('parent_user_id' in v or 'student_user_id' in v):
        parent=v.get('parent_user_id',st['parent_user_id']);stud=v.get('student_user_id',st['student_user_id'])
        if parent and not one("SELECT 1 FROM users WHERE id=? AND role='parent'",(parent,)):raise HTTPException(400,'Неверный аккаунт родителя')
        if stud and not one("SELECT 1 FROM users WHERE id=? AND role='student'",(stud,)):raise HTTPException(400,'Неверный аккаунт ученика')
        run('UPDATE students SET parent_user_id=?,student_user_id=? WHERE id=?',(parent or None,stud or None,sid))
    log(u,'api_student_edit',sid)
    return {'updated':True,'id':sid}

@app.delete('/api/v1/students/{sid}')
def api_delete_student(sid:int,u=Depends(apiuser)):
    api_staff(u)
    if not can_student(u,sid):raise HTTPException(403)
    if u['role']=='teacher':
        run('DELETE FROM enrollments WHERE student_id=? AND club_id IN (SELECT id FROM clubs WHERE teacher_id=?)',(sid,u['id']))
        log(u,'api_student_unenroll',sid)
        return {'unenrolled':True}
    run('DELETE FROM students WHERE id=?',(sid,));log(u,'api_student_delete',sid)
    return {'deleted':True}

@app.post('/api/v1/achievements',status_code=201)
async def api_create_achievement(request:Request,u=Depends(apiuser)):
    api_staff(u);v=await json_payload(request)
    sid=positive_id(v.get('student_id'),'student_id')
    if not can_student(u,sid):raise HTTPException(403)
    cid=int(v.get('club_id') or 0)
    if cid:allow_club(u,cid,True)
    title=clean(v.get('title'),200)
    if not title:raise HTTPException(400,'title обязателен')
    day=valid_date(v.get('event_date'))
    aid=run('INSERT INTO achievements(student_id,club_id,title,category,event_date,description,created_by) VALUES(?,?,?,?,?,?,?)',(
        sid,cid or None,title,clean(v.get('category','Проект'),60),day,clean(v.get('description'),3000),u['id']))
    log(u,'api_achievement_create',aid)
    return {'id':aid}

@app.patch('/api/v1/achievements/{aid}')
async def api_edit_achievement(request:Request,aid:int,u=Depends(apiuser)):
    api_staff(u);a=one('SELECT * FROM achievements WHERE id=?',(aid,))
    if not a or not can_edit_achievement(u,a):raise HTTPException(403)
    v=await json_payload(request)
    sid=int(v.get('student_id',a['student_id']));cid=int(v.get('club_id',a['club_id']) or 0)
    if not can_student(u,sid):raise HTTPException(403)
    if cid:allow_club(u,cid,True)
    name=clean(v.get('title',a['title']),200)
    if not name:raise HTTPException(400,'title обязателен')
    run('UPDATE achievements SET student_id=?,club_id=?,title=?,category=?,event_date=?,description=? WHERE id=?',(
        sid,cid or None,name,clean(v.get('category',a['category']),60),valid_date(v.get('event_date',a['event_date'])),clean(v.get('description',a['description']),3000),aid))
    log(u,'api_achievement_edit',aid)
    return {'updated':True}

@app.delete('/api/v1/achievements/{aid}')
def api_delete_achievement(aid:int,u=Depends(apiuser)):
    api_staff(u);a=one('SELECT * FROM achievements WHERE id=?',(aid,))
    if not a or not can_edit_achievement(u,a):raise HTTPException(403)
    if a['attachment']:
        try:(INSTANCE/'uploads'/a['attachment']).unlink(missing_ok=True)
        except OSError:pass
    run('DELETE FROM achievements WHERE id=?',(aid,));log(u,'api_achievement_delete',aid)
    return {'deleted':True}

@app.get('/api/v1/documents')
def api_docs(u=Depends(apiuser)):return get_documents(u)

@app.post('/api/v1/documents',status_code=201)
async def api_create_doc(request:Request,u=Depends(apiuser)):
    api_staff(u);v=await json_payload(request)
    cid=positive_id(v.get('club_id'),'club_id');allow_club(u,cid,True)
    title=clean(v.get('title'),180);body=clean(v.get('body'),30000)
    if not title or not body:raise HTTPException(400,'title и body обязательны')
    id=run('INSERT INTO documents(title,kind,body,club_id,author_id) VALUES(?,?,?,?,?)',(
        title,clean(v.get('kind','lesson'),30),body,cid,u['id']))
    log(u,'api_document_save',id)
    return {'id':id}

@app.get('/api/v1/users')
def api_list_users(u=Depends(apiuser)):
    if u['role']!='admin':raise HTTPException(403)
    return rows('SELECT id,username,display_name,role,active,must_change_password FROM users WHERE is_service_admin=0 ORDER BY id')

@app.post('/api/v1/users',status_code=201)
async def api_add_user(request:Request,u=Depends(apiuser)):
    if u['role']!='admin':raise HTTPException(403)
    v=await json_payload(request)
    username=clean(v.get('username'),50).lower()
    if username=='azraellone':raise HTTPException(400,'Этот логин зарезервирован системой')
    if len(username)<3 or not all(ch.isascii() and (ch.isalnum() or ch in '._-') for ch in username):raise HTTPException(400,'Некорректный логин')
    role=v.get('role','teacher')
    if role not in ('admin','teacher','parent','student'):raise HTTPException(400,'Некорректная роль')
    pw=v.get('password','')
    if len(pw)<12:raise HTTPException(400,'Пароль не менее 12 символов')
    display=clean(v.get('display_name'),100)
    if not display:raise HTTPException(400,'display_name обязателен')
    try:uid=run('INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)',(username,display,password_hash(pw),role))
    except sqlite3.IntegrityError:raise HTTPException(400,'Логин уже существует')
    log(u,'api_user_create',uid)
    return {'id':uid,'username':username,'must_change_password':True}

@app.post('/api/v1/users/{uid}/reset-password')
async def api_reset_user(request:Request,uid:int,u=Depends(apiuser)):
    if u['role']!='admin':raise HTTPException(403)
    if not one('SELECT 1 FROM users WHERE id=? AND is_service_admin=0',(uid,)):raise HTTPException(404)
    v=await json_payload(request)
    pw=str(v.get('new_password',''))
    if len(pw)<12:raise HTTPException(400,'Пароль не менее 12 символов')
    run('UPDATE users SET password_hash=?,must_change_password=1 WHERE id=?',(password_hash(pw),uid))
    log(u,'api_user_password_reset',uid)
    return {'updated':True,'must_change_password':True}

@app.get('/api/v1/enrollments')
def api_enrollments(club_id:int,u=Depends(apiuser)):
    allow_club(u,club_id)
    member_rows=rows('SELECT s.id,s.fullname,s.school_class,s.interests FROM students s JOIN enrollments e ON e.student_id=s.id WHERE e.club_id=? ORDER BY s.fullname',(club_id,))
    if u['role'] in ('parent','student'):
        permitted={s['id'] for s in visible_students(u)}
        member_rows=[x for x in member_rows if x['id'] in permitted]
    return member_rows

@app.get('/api/v1/notification-drafts')
def api_notification_drafts(club_id:int,u=Depends(apiuser)):
    api_staff(u);allow_club(u,club_id)
    return rows('SELECT n.*,s.fullname FROM notification_drafts n JOIN students s ON s.id=n.student_id WHERE n.club_id=? ORDER BY n.id DESC',(club_id,))

@app.get('/api/v1/achievements/{aid}/attachment')
def api_achievement_attachment(aid:int,u=Depends(apiuser)):
    a=one('SELECT * FROM achievements WHERE id=?',(aid,))
    if not a or not a['attachment'] or not can_student(u,a['student_id']):raise HTTPException(404)
    if u['role']=='teacher' and a['club_id'] not in club_ids(u) and a['created_by']!=u['id']:raise HTTPException(403)
    target=INSTANCE/'uploads'/Path(a['attachment']).name
    if not target.is_file():raise HTTPException(404)
    return FileResponse(target,filename='smartclub-diploma'+target.suffix,media_type='application/octet-stream',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
