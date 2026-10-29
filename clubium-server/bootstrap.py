"""Initial setup: only one administrator account, AzraelLone.

Repeated setup NEVER deletes existing accounts or school data. To remove
existing accounts, use the explicit `python keep_only_azrael.py --apply`.
"""
import os
import secrets
from app import INSTANCE, conn, password_hash

OWNER_USERNAME = 'AzraelLone'
OWNER_PASSWORD_FILE = INSTANCE / 'СЛУЖЕБНЫЙ_АДМИН_ПЕРВЫЙ_ПАРОЛЬ.txt'

def setup():
    supplied = os.environ.get('SMARTCLUB_OWNER_INITIAL_PASSWORD', '').strip()
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
            pw = supplied or (secrets.token_urlsafe(27) + 'A9!')
            db.execute('INSERT INTO users(username,display_name,password_hash,role,must_change_password,is_service_admin) '
                       'VALUES(?,?,?,?,1,1)',
                       (OWNER_USERNAME, 'Главный администратор', password_hash(pw), 'admin'))
            created = True
    if created:
        if supplied:
            print('Создан только AzraelLone; пароль получен из секретной переменной окружения.')
        else:
            OWNER_PASSWORD_FILE.write_text('Логин: AzraelLone\nВременный пароль: ' + pw +
                '\nСмените его при первом входе и удалите этот файл.\n',encoding='utf-8')
            try: OWNER_PASSWORD_FILE.chmod(0o600)
            except OSError: pass
            print('Первый временный пароль находится в приватном файле:', OWNER_PASSWORD_FILE)
    else:
        print('Существующий аккаунт AzraelLone сохранён, пароль не изменён.')
    print('Автоматического создания igor, elmira, учителей, родителей и учеников больше нет.')
    print('Если на сервере уже есть другие аккаунты, для их удаления используйте отдельную команду:')
    print('    python keep_only_azrael.py --apply')

if __name__ == '__main__':
    setup()
