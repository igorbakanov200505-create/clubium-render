"""Emergency local password reset, run by the authorized server operator."""
import getpass,secrets
from app import one,run,password_hash,log
username=input('Логин для сброса: ').strip()
user=one('SELECT id,is_service_admin FROM users WHERE username=? COLLATE NOCASE',(username,))
if not user:raise SystemExit('Пользователь не найден')
password=secrets.token_urlsafe(15)+'A9!'
run('UPDATE users SET password_hash=?,must_change_password=1 WHERE id=?',(password_hash(password),user['id']))
log(user,'server_password_reset','Сброс из консоли сервера')
print('Одноразовый временный пароль:',password)
print('Пользователь обязан сменить пароль после входа. Не сохраняйте этот пароль в общедоступных местах.')
