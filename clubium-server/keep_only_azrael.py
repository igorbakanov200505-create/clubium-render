"""One-time explicit account cleanup; preserves school records and audit trail.

Usage: python keep_only_azrael.py --apply
Makes a consistent private SQLite backup, then removes every other user
account. Foreign keys with ON DELETE SET NULL preserve linked school data.
"""
from __future__ import annotations
import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app import DB, INSTANCE, conn
from bootstrap import OWNER_USERNAME, setup

OLD_SEED_PASSWORD_FILE = INSTANCE / 'ПЕРВЫЕ_ПАРОЛИ_СОХРАНИТЬ_И_УДАЛИТЬ.txt'

def cleanup(*, apply=False):
    # Ensure the only account to be retained exists *before* any deletion.
    setup()
    with conn() as db:
        owner = db.execute('SELECT id, username, role, is_service_admin, active FROM users '
                           'WHERE username=? COLLATE NOCASE',(OWNER_USERNAME,)).fetchone()
        if not owner or owner['role']!='admin' or not owner['active'] or not owner['is_service_admin']:
            raise RuntimeError('Рабочий служебный аккаунт AzraelLone не найден; отмена.')
        targets = db.execute('SELECT username FROM users WHERE id<>? ORDER BY username', (owner['id'],)).fetchall()
        names = [u['username'] for u in targets]
    if not apply:
        print('Будет удалено аккаунтов:',len(names))
        print('Логины:', ', '.join(names) if names else 'нет')
        print('Для выполнения: python keep_only_azrael.py --apply')
        return {'deleted':0,'preview':names}
    backup_dir = INSTANCE / 'backups'
    backup_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    try: backup_dir.chmod(0o700)
    except OSError: pass
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    backup = backup_dir / f'smartclub-before-account-cleanup-{stamp}.sqlite3'
    with sqlite3.connect(str(DB)) as original, sqlite3.connect(str(backup)) as target:
        original.backup(target)
    try: backup.chmod(0o600)
    except OSError: pass
    with conn() as db:
        owner = db.execute('SELECT id FROM users WHERE username=? COLLATE NOCASE AND is_service_admin=1 AND active=1',
                           (OWNER_USERNAME,)).fetchone()
        if not owner:
            raise RuntimeError('Аккаунт AzraelLone исчез до удаления; отмена.')
        db.execute('DELETE FROM users WHERE id<>?',(owner['id'],))
        db.execute('INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)',
                   (owner['id'],'accounts_cleanup',f'Удалено аккаунтов: {len(names)}; резервная копия: {backup.name}'))
        count = db.execute('SELECT COUNT(*) AS n FROM users').fetchone()['n']
        assert count == 1, 'Операция завершилась неожиданным количеством аккаунтов'
    if OLD_SEED_PASSWORD_FILE.exists():
        try:
            OLD_SEED_PASSWORD_FILE.unlink()
            print('Устаревший файл с начальными паролями удалён.')
        except OSError:
            print('ВНИМАНИЕ: удалите старый файл начальных паролей вручную:',OLD_SEED_PASSWORD_FILE)
    print('Готово. Остался только пользователь AzraelLone.')
    print('Удалено:', len(names))
    print('Приватная резервная копия прежней базы:', backup)
    return {'deleted':len(names),'backup':str(backup)}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Удалить все аккаунты, кроме AzraelLone, с резервной копией.')
    parser.add_argument('--apply', action='store_true',help='Выполнить необратимое удаление аккаунтов из рабочей базы')
    args=parser.parse_args()
    cleanup(apply=args.apply)
