"""ÜiirmeHub: self-service profile and user-uploaded document templates.

Installed at the very end of app.py via install(globals()), after DB migration.
Files for avatars use the existing encrypted-backup-safe uploads/ name format.
Document bytes are stored in SQLite so the existing encrypted snapshot covers them.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from fastapi import Request, Form, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, Response, RedirectResponse
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_AVATAR_UPLOAD = 3 * 1024 * 1024
MAX_DOC_BYTES = 2 * 1024 * 1024
MAX_ZIP_UPLOAD = 10 * 1024 * 1024
MAX_BATCH_ITEMS = 100
MAX_LIBRARY_BYTES = 8 * 1024 * 1024  # headroom for encrypted GitHub archive limit (15 MB)
MAX_LIBRARY_ITEMS = 200
DOC_TYPES = {
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain; charset=utf-8',
    '.odt': 'application/vnd.oasis.opendocument.text',
}
ALLOWED_LANGS = {'ru', 'kk', 'en'}
ALLOWED_THEMES = {'system', 'dark', 'light'}


def _error(msg, status=400):
    raise HTTPException(status, msg)


def _base_name(filename):
    """Never use client filename as a filesystem path or untrusted response header."""
    raw = str(filename or '').replace('\\', '/').rsplit('/', 1)[-1].strip()
    raw = ''.join(c for c in raw if 32 <= ord(c) <= 126 or ord(c) >= 160)
    return raw[:160]


def _valid_document(filename, content):
    suffix = Path(filename).suffix.lower()
    if suffix not in DOC_TYPES:
        _error('Разрешены только DOCX, XLSX, PDF, TXT и ODT')
    if not content or len(content) > MAX_DOC_BYTES:
        _error('Файл документа должен быть от 1 байта до 2 МБ')
    if suffix == '.pdf' and not content.startswith(b'%PDF-'):
        _error('Неверный формат PDF')
    if suffix in ('.docx', '.xlsx', '.odt'):
        if not content.startswith(b'PK'):
            _error('Неверный формат офисного документа')
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                names = z.namelist()
                if suffix == '.docx' and '[Content_Types].xml' not in names:
                    _error('Повреждённый файл DOCX')
                if suffix == '.xlsx' and '[Content_Types].xml' not in names:
                    _error('Повреждённый файл XLSX')
                if suffix == '.odt' and 'mimetype' not in names:
                    _error('Повреждённый файл ODT')
        except (zipfile.BadZipFile, EOFError):
            _error('Повреждённый офисный документ')
    if suffix == '.txt':
        try:
            content.decode('utf-8-sig')
        except UnicodeDecodeError:
            _error('Для TXT используйте кодировку UTF-8')
    return DOC_TYPES[suffix]


def _name_for_zip(name):
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name:
        return None
    return p


def _prepare_zip(data):
    """Parse ZIP in memory; accept Word templates from user's prior library ZIP.

    If the archive includes a catalog.csv, match Russian titles/categories instead
    of showing generic file names like edu_01.docx. Text twins are skipped when
    DOCX version exists. Unknown file types are always ignored.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, EOFError):
        _error('Повреждённый ZIP-архив')
    with archive as z:
        items = z.infolist()
        if len(items) > 400:
            _error('Слишком много элементов в ZIP (не более 400)')
        mapping = {}
        catalogs = [m for m in items if m.filename.endswith('/catalog.csv') or m.filename == 'catalog.csv']
        for catalog in catalogs[:1]:
            if catalog.file_size > 160_000:
                _error('Слишком большой каталог шаблонов')
            try:
                reader = csv.DictReader(io.StringIO(z.read(catalog).decode('utf-8-sig')))
                for line in reader:
                    path = line.get('Word файл', '').strip()
                    if path:
                        mapping[path.replace('\\', '/')] = (line.get('Документ',''), line.get('Категория',''))
            except (UnicodeError, csv.Error):
                mapping = {}
        all_docx = {str(PurePosixPath(i.filename).with_suffix('')) for i in items if i.filename.lower().endswith('.docx')}
        results = []
        seen = set()
        total = 0
        for m in items:
            if m.is_dir():
                continue
            p = _name_for_zip(m.filename)
            if p is None or p.suffix.lower() not in DOC_TYPES:
                continue
            if (m.external_attr >> 16) & 0o170000 == 0o120000:
                _error('Символические ссылки в ZIP не допускаются')
            if (p.suffix.lower() == '.txt' and
                    any(str(PurePosixPath(m.filename).with_suffix('')).replace('/02_ТЕКСТОВЫЕ_ШАБЛОНЫ/', '/01_WORD_ШАБЛОНЫ/') == x for x in all_docx)):
                continue
            filename = _base_name(p.name)
            if not filename or m.file_size <= 0 or m.file_size > MAX_DOC_BYTES:
                _error('В ZIP есть файл превышающий ограничение 2 МБ')
            if filename.lower() in seen:
                continue
            seen.add(filename.lower())
            total += m.file_size
            if len(results) >= MAX_BATCH_ITEMS or total > MAX_LIBRARY_BYTES:
                _error('В ZIP более 100 шаблонов или больше 8 МБ данных')
            b = z.read(m)
            _valid_document(filename, b)
            display, category = next(
                (v for k, v in mapping.items() if m.filename.endswith(k)),
                (p.stem.replace('_', ' ').strip(), 'Импорт из ZIP'))
            results.append((str(display or p.stem)[:130], str(category or 'Импорт из ZIP')[:60], filename, b))
        if not results:
            _error('В ZIP не найдено поддерживаемых файлов DOCX, XLSX, PDF, TXT или ODT')
        return results


def install(ns):
    app = ns['app']
    conn = ns['conn']
    rows = ns['rows']
    one = ns['one']
    get_user = ns['get_user']
    require = ns['require']
    csrf = ns['csrf']
    check_csrf = ns['check_csrf']
    password_hash = ns['password_hash']
    password_ok = ns['password_ok']
    templates = ns['templates']
    INSTANCE = ns['INSTANCE']
    log = ns['log']
    flash = ns['flash']
    go = ns['go']

    # Additive migrations only; no modification of any existing records.
    with conn() as db:
        cols = {c['name'] for c in db.execute('PRAGMA table_info(users)')}
        for col, sql in {
            'profile_avatar': "TEXT NOT NULL DEFAULT ''",
            'profile_about': "TEXT NOT NULL DEFAULT ''",
            'profile_email': "TEXT NOT NULL DEFAULT ''",
            'profile_lang': "TEXT NOT NULL DEFAULT 'ru'",
            'profile_theme': "TEXT NOT NULL DEFAULT 'system'",
        }.items():
            if col not in cols:
                db.execute('ALTER TABLE users ADD COLUMN ' + col + ' ' + sql)
        db.execute('''CREATE TABLE IF NOT EXISTS document_templates (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Общие',
            description TEXT NOT NULL DEFAULT '',
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            file_content BLOB NOT NULL,
            file_hash TEXT NOT NULL,
            owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            owner_role TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_document_templates_dedup ON document_templates(owner_id,file_hash) WHERE owner_id IS NOT NULL')
        db.execute('CREATE INDEX IF NOT EXISTS idx_document_templates_owner ON document_templates(owner_id)')

    def local_user(request):
        user = require(request)
        profile = one('''SELECT profile_avatar,profile_about,profile_email,profile_lang,profile_theme
                          FROM users WHERE id=?''', (user['id'],))
        if not profile:
            _error('Аккаунт не найден', 401)
        return user, profile

    def profile_page(request, error=None):
        user, profile = local_user(request)
        result = templates.TemplateResponse(request, 'my_profile.html', {
            'request': request, 'user': user, 'profile': profile,
            'csrf': csrf(request), 'notice': request.session.pop('notice', None),
            'current': 'profile', 'page_title': 'Мой профиль', 'error': error,
        }, status_code=400 if error else 200)
        result.headers['Cache-Control'] = 'no-store'
        return result

    @app.get('/profile')
    def profile_get(request: Request):
        return profile_page(request)

    @app.post('/profile/settings')
    def profile_settings(request: Request, csrf_token: str=Form('', alias='_csrf'),
                         about: str=Form(''), email: str=Form(''),
                         lang: str=Form('ru'), theme: str=Form('system')):
        user, _ = local_user(request)
        check_csrf(request, csrf_token)
        about = about.strip()
        email = email.strip().lower()
        if len(about) > 450:
            return profile_page(request, 'Описание не должно превышать 450 символов')
        if email and (len(email) > 180 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email)):
            return profile_page(request, 'Введите корректный адрес электронной почты')
        if lang not in ALLOWED_LANGS or theme not in ALLOWED_THEMES:
            return profile_page(request, 'Некорректные настройки интерфейса')
        with conn() as db:
            db.execute('''UPDATE users SET profile_about=?,profile_email=?,profile_lang=?,profile_theme=?
                          WHERE id=?''', (about, email, lang, theme, user['id']))
        log(user, 'profile_settings_update')
        flash(request, 'Настройки профиля сохранены')
        return go('/profile')

    @app.post('/profile/password')
    def profile_password(request: Request, csrf_token: str=Form('', alias='_csrf'),
                         current_password: str=Form(''), new_password: str=Form(''),
                         repeat_password: str=Form('')):
        user, _ = local_user(request)
        check_csrf(request, csrf_token)
        hashed = one('SELECT password_hash FROM users WHERE id=?', (user['id'],))
        if not hashed or not password_ok(current_password, hashed['password_hash']):
            return profile_page(request, 'Текущий пароль неверный')
        if len(new_password) < 12 or len(new_password) > 200:
            return profile_page(request, 'Новый пароль: от 12 до 200 символов')
        if new_password != repeat_password:
            return profile_page(request, 'Новые пароли не совпадают')
        if new_password == current_password:
            return profile_page(request, 'Новый пароль должен отличаться от старого')
        with conn() as db:
            db.execute('''UPDATE users SET password_hash=?,temporary_password_expires=NULL,
                          must_change_password=0 WHERE id=?''', (password_hash(new_password), user['id']))
        log(user, 'profile_password_change')
        # Rotate authenticated session, so old API tokens invalidated by password hash.
        request.session.clear()
        flash(request, 'Пароль изменён. Войдите с новым паролем.')
        return go('/login')

    def _safe_existing_avatar(filename):
        if not re.fullmatch(r'[a-f0-9]{32}\.jpg', filename or ''):
            return None
        path = INSTANCE / 'uploads' / filename
        return path if path.is_file() and not path.is_symlink() else None

    @app.get('/profile/photo')
    def profile_photo(request: Request):
        user, profile = local_user(request)
        path = _safe_existing_avatar(profile['profile_avatar'])
        if not path:
            raise HTTPException(404, 'Фото профиля не загружено')
        return FileResponse(path, media_type='image/jpeg', headers={
            'Cache-Control': 'private, max-age=30', 'X-Content-Type-Options': 'nosniff'})

    @app.post('/profile/photo')
    async def profile_photo_upload(request: Request, csrf_token: str=Form('', alias='_csrf'),
                                   photo: UploadFile=File(...)):
        user, profile = local_user(request)
        check_csrf(request, csrf_token)
        payload = await photo.read(MAX_AVATAR_UPLOAD + 1)
        if not payload or len(payload) > MAX_AVATAR_UPLOAD:
            return profile_page(request, 'Фото должно быть не больше 3 МБ')
        try:
            Image.MAX_IMAGE_PIXELS = 16_000_000
            with Image.open(io.BytesIO(payload)) as raw:
                if raw.format not in ('JPEG', 'PNG', 'WEBP'):
                    raise ValueError('unsupported image')
                raw.verify()
            with Image.open(io.BytesIO(payload)) as raw:
                raw = ImageOps.exif_transpose(raw)
                raw.thumbnail((512, 512))
                photo_out = io.BytesIO()
                raw.convert('RGB').save(photo_out, format='JPEG', quality=87, optimize=True)
            converted = photo_out.getvalue()
        except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError):
            return profile_page(request, 'Загрузите корректное изображение JPG, PNG или WEBP')
        directory = INSTANCE / 'uploads'
        directory.mkdir(parents=True, exist_ok=True)
        filename = secrets.token_hex(16) + '.jpg'
        tempname = directory / ('.upload-' + secrets.token_hex(16))
        target = directory / filename
        try:
            tempname.write_bytes(converted)
            os.replace(tempname, target)
            with conn() as db:
                db.execute('UPDATE users SET profile_avatar=? WHERE id=?', (filename, user['id']))
        except Exception:
            tempname.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            raise
        old = _safe_existing_avatar(profile['profile_avatar'])
        if old and old.name != filename:
            old.unlink(missing_ok=True)
        log(user, 'profile_avatar_update')
        flash(request, 'Фотография профиля обновлена')
        return go('/profile')

    @app.post('/profile/photo/remove')
    def profile_photo_remove(request: Request, csrf_token: str=Form('', alias='_csrf')):
        user, profile = local_user(request)
        check_csrf(request, csrf_token)
        with conn() as db:
            db.execute("UPDATE users SET profile_avatar='' WHERE id=?", (user['id'],))
        path = _safe_existing_avatar(profile['profile_avatar'])
        if path:
            path.unlink(missing_ok=True)
        log(user, 'profile_avatar_remove')
        flash(request, 'Фотография удалена')
        return go('/profile')

    def docs_user(request):
        u = require(request, ('admin', 'teacher'))
        return u

    def can_see(row, user):
        return user['role'] == 'admin' or row['owner_role'] == 'admin' or row['owner_id'] == user['id']

    @app.get('/document-templates')
    def templates_page(request: Request, q: str='', category: str=''):
        user = docs_user(request)
        # Never return BLOBs in a list (only metadata).
        if user['role'] == 'admin':
            docs = rows('''SELECT id,title,category,description,filename,length(file_content) AS size,
                          owner_id,owner_role,created_at FROM document_templates
                          ORDER BY id DESC LIMIT 250''')
        else:
            docs = rows('''SELECT id,title,category,description,filename,length(file_content) AS size,
                          owner_id,owner_role,created_at FROM document_templates
                          WHERE owner_role='admin' OR owner_id=?
                          ORDER BY id DESC LIMIT 250''', (user['id'],))
        search = q.strip().lower()[:100]
        chosen = category.strip().lower()[:60]
        cats = sorted({d['category'] for d in docs})
        if search:
            docs = [d for d in docs if search in (d['title']+' '+d['category']+' '+d['description']+' '+d['filename']).lower()]
        if chosen:
            docs = [d for d in docs if d['category'].lower() == chosen]
        total = one('SELECT COUNT(*) AS n, COALESCE(SUM(length(file_content)),0) AS bytes FROM document_templates')
        resp = templates.TemplateResponse(request, 'my_document_templates.html', {
            'request': request, 'user': user, 'documents': docs, 'categories': cats,
            'search': q, 'selected_category': category,
            'count_total': total['n'], 'total_mb': round(total['bytes']/1048576, 2),
            'csrf': csrf(request), 'notice': request.session.pop('notice', None),
            'current': 'document-templates', 'page_title': 'Шаблоны документов',
        })
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    def _save_items(user, items, description=''):
        """Atomic upload, with quota and hash-based duplicate prevention."""
        if not items:
            _error('Нечего загружать')
        inserted = 0
        duplicates = 0
        with conn() as db:
            quota = db.execute('''SELECT COUNT(*) AS n,
                         COALESCE(SUM(length(file_content)),0) AS bytes
                         FROM document_templates''').fetchone()
            existing = quota['bytes']
            count = quota['n']
            for title, category, filename, content in items:
                hashval = hashlib.sha256(content).hexdigest()
                already = db.execute('SELECT 1 FROM document_templates WHERE owner_id=? AND file_hash=?',
                                     (user['id'], hashval)).fetchone()
                if already:
                    duplicates += 1
                    continue
                existing += len(content)
                count += 1
                if existing > MAX_LIBRARY_BYTES or count > MAX_LIBRARY_ITEMS:
                    _error('Лимит библиотеки: до 8 МБ файлов и до 200 шаблонов')
                kind = _valid_document(filename, content)
                db.execute('''INSERT INTO document_templates
                    (title,category,description,filename,content_type,file_content,file_hash,owner_id,owner_role)
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                    (title[:130], category[:60], description[:500], filename, kind, content,
                     hashval, user['id'], user['role']))
                inserted += 1
        return inserted, duplicates

    @app.post('/document-templates/upload')
    async def template_upload(request: Request, csrf_token: str=Form('', alias='_csrf'),
                              title: str=Form(''), category: str=Form('Общие'),
                              description: str=Form(''), file: UploadFile=File(...)):
        user = docs_user(request)
        check_csrf(request, csrf_token)
        original = _base_name(file.filename)
        suffix = Path(original).suffix.lower()
        if suffix == '.zip':
            binary = await file.read(MAX_ZIP_UPLOAD + 1)
            if len(binary) > MAX_ZIP_UPLOAD:
                _error('ZIP не должен превышать 10 МБ')
            items = _prepare_zip(binary)
        else:
            binary = await file.read(MAX_DOC_BYTES + 1)
            _valid_document(original, binary)
            items = [((title.strip() or Path(original).stem)[:130],
                      (category.strip() or 'Общие')[:60], original, binary)]
        n, skipped = _save_items(user, items, description.strip())
        log(user, 'document_templates_upload', f'{n} added {skipped} duplicates')
        flash(request, f'Загружено шаблонов: {n}. Пропущено повторов: {skipped}.')
        return go('/document-templates')

    @app.get('/document-templates/{doc_id}/download')
    def template_download(request: Request, doc_id: int):
        user = docs_user(request)
        row = one('SELECT * FROM document_templates WHERE id=?', (doc_id,))
        if not row or not can_see(row, user):
            _error('Документ не найден', 404)
        filename = _base_name(row['filename'])
        # filename* is RFC 5987 compliant and avoids untrusted quote characters.
        headers = {
            'Content-Disposition': "attachment; filename*=UTF-8''" + quote(filename, safe=''),
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        }
        return Response(content=bytes(row['file_content']), media_type=row['content_type'], headers=headers)

    @app.post('/document-templates/{doc_id}/delete')
    def template_delete(request: Request, doc_id: int, csrf_token: str=Form('', alias='_csrf')):
        user = docs_user(request)
        check_csrf(request, csrf_token)
        row = one('SELECT id,owner_id,owner_role FROM document_templates WHERE id=?', (doc_id,))
        if not row or not can_see(row, user):
            _error('Шаблон не найден', 404)
        # Admin can moderate all templates; teacher can delete only own.
        if user['role'] != 'admin' and row['owner_id'] != user['id']:
            _error('Нельзя удалить чужой шаблон', 403)
        with conn() as db:
            db.execute('DELETE FROM document_templates WHERE id=?', (doc_id,))
        log(user, 'document_template_delete', doc_id)
        flash(request, 'Шаблон удалён')
        return go('/document-templates')

    # The original app selects only a small set of user fields. Extend the
    # user object for the avatar shown on every page; name/login stay immutable.
    original_get_user = ns['get_user']
    def get_user_with_avatar(request):
        user = original_get_user(request)
        if user:
            photo = one('SELECT profile_avatar FROM users WHERE id=?', (user['id'],))
            user['profile_avatar'] = photo['profile_avatar'] if photo else ''
        return user
    ns['get_user'] = get_user_with_avatar

    return True
