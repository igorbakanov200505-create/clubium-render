"""Example of connecting an external app to the Smart-Club Admin site.

Set environment variables before running:
  SMARTCLUB_URL=http://127.0.0.1:8000
  SMARTCLUB_USER=AzraelLone
  SMARTCLUB_PASSWORD=your_personal_password

Use HTTPS for access across a network. Never embed an administrator password
inside a mobile application's source code.
"""
import json
import os
import urllib.parse
import urllib.request

BASE=os.environ.get('SMARTCLUB_URL','http://127.0.0.1:8000').rstrip('/')
USER=os.environ['SMARTCLUB_USER']
PASSWORD=os.environ['SMARTCLUB_PASSWORD']


def http(method,path,payload=None,token=None,form=False):
    headers={}
    if token:headers['Authorization']='Bearer '+token
    if form:
        data=urllib.parse.urlencode(payload).encode()
        headers['Content-Type']='application/x-www-form-urlencoded'
    elif payload is not None:
        data=json.dumps(payload,ensure_ascii=False).encode('utf-8')
        headers['Content-Type']='application/json'
    else:data=None
    req=urllib.request.Request(BASE+path,method=method,headers=headers,data=data)
    with urllib.request.urlopen(req,timeout=15) as resp:
        return json.loads(resp.read().decode('utf-8'))


auth=http('POST','/api/v1/token',{'username':USER,'password':PASSWORD},form=True)
token=auth['access_token']
print('Current account:',http('GET','/api/v1/me',token=token))
print('Clubs:',http('GET','/api/v1/clubs',token=token))
print('Summary:',http('GET','/api/v1/summary',token=token))
print('Students:',len(http('GET','/api/v1/students',token=token)))

# POST attendance example (uncomment with a real club ID and enrolled student ID).
# print(http('POST','/api/v1/attendance',{
#     'club_id':1,
#     'lesson_date':'2026-10-28',
#     'marks':[{'student_id':1,'status':'present'}]
# },token=token))
