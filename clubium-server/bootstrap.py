"""Initial setup: only one administrator account, AzraelLone.

Repeated setup NEVER deletes existing accounts or school data. To remove
existing accounts, use the explicit `python keep_only_azrael.py --apply`.
"""
import os
import secrets
import re
from app import INSTANCE, conn, password_hash, _github_backup

OWNER_USERNAME = 'AzraelLone'
OWNER_PASSWORD_FILE = INSTANCE / 'СЛУЖЕБНЫЙ_АДМИН_ПЕРВЫЙ_ПАРОЛЬ.txt'

def setup():
    supplied = os.environ.get('SMARTCLUB_OWNER_INITIAL_PASSWORD', '').strip()
    # Optional one-off password reset via Render secret env vars. Never put the
    # credential into source control; resets are idempotent per request ID.
    reset_password = os.environ.get('CLUBIUM_OWNER_RESET_PASSWORD', '').strip()
    reset_id = os.environ.get('CLUBIUM_OWNER_RESET_ID', '').strip()
    if reset_password and (len(reset_password) < 12 or not re.fullmatch(r'[A-Za-z0-9_-]{16,80}', reset_id)):
        raise ValueError('Для сброса задайте CLUBIUM_OWNER_RESET_PASSWORD (>=12) и CLUBIUM_OWNER_RESET_ID (16-80 символов: латиница, цифры, - или _)')
    if supplied and len(supplied) < 12:
        raise ValueError('SMARTCLUB_OWNER_INITIAL_PASSWORD: пароль должен быть не короче 12 символов')
    created = False
    with conn() as db:
        owner = db.execute('SELECT id,is_service_admin,role,active FROM users WHERE username=? COLLATE NOCASE',
                           (OWNER_USERNAME,)).fetchone()
        if owner:
            if not owner['is_service_admin'] or owner['role'] != 'admin':
                raise RuntimeError('Логин AzraelLone занят неслужебным аккаунтом: нужен ручной разбор')
            if not owner['active']:
                raise RuntimeError('AzraelLone отключён; восстановите доступ вручную после проверки')
        else:
            another_owner = db.execute('SELECT username FROM users WHERE is_service_admin=1').fetchone()
            if another_owner:
                raise RuntimeError('Уже существует другой служебный аккаунт. Автоматическое изменение запрещено.')
            pw = supplied or reset_password or (secrets.token_urlsafe(27) + 'A9!')
            db.execute('INSERT INTO users(username,display_name,password_hash,role,must_change_password,is_service_admin) '
                       'VALUES(?,?,?,?,1,1)',
                       (OWNER_USERNAME, 'Главный администратор', password_hash(pw), 'admin'))
            created = True
    if created:
        if supplied or reset_password:
            print('Создан только AzraelLone; пароль получен из секретной переменной окружения.')
        else:
            OWNER_PASSWORD_FILE.write_text('Логин: AzraelLone\nВременный пароль: ' + pw +
                '\nСмените его при первом входе и удалите этот файл.\n',encoding='utf-8')
            try: OWNER_PASSWORD_FILE.chmod(0o600)
            except OSError: pass
            print('Первый временный пароль находится в приватном файле:', OWNER_PASSWORD_FILE)
    else:
        print('Существующий аккаунт AzraelLone сохранён, пароль не изменён.')
    if reset_password:
        with conn() as db:
            db.execute('CREATE TABLE IF NOT EXISTS owner_password_resets ('
                       'request_id TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
            was_applied = db.execute('SELECT 1 FROM owner_password_resets WHERE request_id=?', (reset_id,)).fetchone()
            if not was_applied:
                user = db.execute('SELECT id FROM users WHERE username=? AND is_service_admin=1 AND active=1 COLLATE NOCASE',
                                  (OWNER_USERNAME,)).fetchone()
                if not user:
                    raise RuntimeError('Служебный администратор AzraelLone не найден для сброса')
                db.execute('UPDATE users SET password_hash=?, must_change_password=1 WHERE id=?',
                           (password_hash(reset_password), user['id']))
                db.execute('INSERT INTO owner_password_resets(request_id) VALUES(?)', (reset_id,))
                db.execute('INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)',
                           (user['id'], 'owner_password_reset_env', 'Одноразовый сброс через секреты сервера'))
                print('Одноразовый сброс пароля AzraelLone выполнен. УДАЛИТЕ CLUBIUM_OWNER_RESET_PASSWORD и CLUBIUM_OWNER_RESET_ID из Render.')
            else:
                print('Этот запрос на сброс AzraelLone уже выполнен; пароль при перезапуске не изменён.')
    print('Автоматического создания igor, elmira, учителей, родителей и учеников больше нет.')
    print('Если на сервере уже есть другие аккаунты, для их удаления используйте отдельную команду:')
    print('    python keep_only_azrael.py --apply')

if __name__ == '__main__':
    setup()
    if _github_backup.enabled:
        _github_backup.flush(force=True)  # ensure first account and last changes are backed up before serving
