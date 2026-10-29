"""Technical-owner DM access: invisible to search, visible only after owner writes first.

Patches global helper functions that existing FastAPI chat endpoints resolve at request time;
does not replace or duplicate /chat/api routes. Group rooms remain forbidden for owner.
"""
from __future__ import annotations
from fastapi import HTTPException


def install(ns):
    one, rows = ns['one'], ns['rows']
    original_room = ns['chat_room']
    original_roles = ns['chat_roles']
    original_visible = ns['chat_visible_message']

    def require_chat_user(request):
        return ns['require'](request)

    def initiated(owner_id, other_id):
        return bool(one('''SELECT 1 FROM chat_messages WHERE room='dm' AND
            sender_id=? AND recipient_id=? LIMIT 1''',(owner_id,other_id)))

    def chat_room(user,room_key):
        if not isinstance(room_key,str):
            raise HTTPException(400,'Неизвестный чат')
        if room_key in ('general','admins'):
            if user.get('is_service_admin'):
                raise HTTPException(403,'Технический администратор использует только личные переписки')
            return original_room(user,room_key)
        if room_key.startswith('dm:') and room_key[3:].isdigit():
            target_id=int(room_key[3:])
            if target_id==user['id']:
                raise HTTPException(400,'Нельзя отправлять самому себе')
            peer=one('SELECT id,is_service_admin FROM users WHERE id=? AND active=1',(target_id,))
            if not peer:
                raise HTTPException(404,'Пользователь недоступен')
            if user.get('is_service_admin'):
                if peer['is_service_admin']:
                    raise HTTPException(403,'Нельзя писать техническому аккаунту')
                # The owner must explicitly select/add contact before writing.
                known=one('''SELECT 1 FROM chat_contacts WHERE owner_id=? AND peer_id=?
                  UNION SELECT 1 FROM chat_messages WHERE room='dm' AND
                   ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) LIMIT 1''',
                  (user['id'],target_id,user['id'],target_id,target_id,user['id']))
                if not known:raise HTTPException(403,'Сначала найдите человека по логину')
                return 'dm',target_id
            if peer['is_service_admin']:
                # A user cannot contact/guess the owner account unless owner already sent a message.
                if not initiated(target_id,user['id']):
                    raise HTTPException(404,'Пользователь недоступен')
                return 'dm',target_id
        return original_room(user,room_key)

    def chat_roles(user):
        if not user.get('is_service_admin'):
            data=original_roles(user)
            service=rows('''SELECT u.id,u.username,u.display_name,u.role FROM users u
                     WHERE u.active=1 AND u.is_service_admin=1 AND EXISTS(
                        SELECT 1 FROM chat_messages m WHERE m.room='dm'
                        AND m.sender_id=u.id AND m.recipient_id=?) LIMIT 1''',(user['id'],))
            for p in service:
                p['key']='dm:'+str(p['id'])
                p['unread']=ns['chat_unread'](user,p['key'])
                data['contacts'].append(p)
            data['user_is_service_admin']=False
            return data
        peers=rows('''SELECT u.id,u.username,u.display_name,u.role FROM users u
                WHERE u.active=1 AND u.is_service_admin=0 AND u.id<>? AND (
                  EXISTS(SELECT 1 FROM chat_contacts cc WHERE cc.owner_id=? AND cc.peer_id=u.id)
                  OR EXISTS(SELECT 1 FROM chat_messages m WHERE m.room='dm' AND
                      ((m.sender_id=? AND m.recipient_id=u.id) OR
                       (m.recipient_id=? AND m.sender_id=u.id)))
                ) ORDER BY u.display_name COLLATE NOCASE LIMIT 150''',
                (user['id'],user['id'],user['id'],user['id']))
        for p in peers:
            p['key']='dm:'+str(p['id'])
            p['unread']=ns['chat_unread'](user,p['key'])
        return dict(rooms=[],contacts=peers,user_id=user['id'],
                    user_role=user['role'],user_is_service_admin=True)

    def chat_visible_message(user,message):
        if not message:return False
        if message.get('room')=='dm':
            sender=one('SELECT is_service_admin FROM users WHERE id=?',(message['sender_id'],))
            recipient=one('SELECT is_service_admin FROM users WHERE id=?',(message['recipient_id'],))
            if sender and recipient and (sender['is_service_admin'] or recipient['is_service_admin']):
                if user['id'] not in (message['sender_id'],message['recipient_id']):return False
                owner_id=message['sender_id'] if sender['is_service_admin'] else message['recipient_id']
                other_id=message['recipient_id'] if sender['is_service_admin'] else message['sender_id']
                return initiated(owner_id,other_id)
        return original_visible(user,message)

    # These names are global lookups inside previously registered route handlers.
    ns['require_chat_user']=require_chat_user
    ns['chat_room']=chat_room
    ns['chat_roles']=chat_roles
    ns['chat_visible_message']=chat_visible_message
    return True
