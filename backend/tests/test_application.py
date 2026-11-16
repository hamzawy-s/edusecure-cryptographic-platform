import json, os, time
from pathlib import Path
from backend.tests.conftest import csrf, register
from backend.app.main import WEBHOOK_SECRET
from backend.app.models import Material, Payment
from backend.app.cryptography.primitives import canonical_json, sign_webhook
from sqlalchemy import select
from backend.app.database import get_db

def test_registration_login_and_signed_session(client):
    token=register(client);assert token and client.get('/api/me').status_code==200
    assert client.get('/api/my/audit').json()[0]['action']=='account.registered'
    client.post('/api/logout',headers={'X-CSRF-Token':token});assert client.get('/api/me').status_code==401
    r=client.post('/api/login',json={'email':'learner@example.edu','password':'Correct-Horse-42!'});assert r.status_code==200 and client.get('/api/me').json()['user']['role']=='student'
    assert any(e['action']=='authentication.login' for e in client.get('/api/my/audit').json())
def test_unknown_user_rejected(client):
    r=client.post('/api/login',json={'email':'missing@example.edu','password':'Correct-Horse-42!'});assert r.status_code==401
def test_security_center_reads_real_certificate_and_root_fingerprint(client):
    status=client.get('/api/security').json()
    assert status['tls_minimum']=='TLS 1.2' and len(status['root_ca_sha256'])==64
    assert status['server_certificate']['subject']=='localhost' and status['server_certificate']['sha256']
def test_instructor_registration_requires_invite_code(client):
    r=client.post('/api/register',json={'email':'open-instructor@example.edu','name':'Uninvited','password':'Correct-Horse-42!','role':'instructor'})
    assert r.status_code==403
def test_profile_password_rotation_rehashes_secret(client):
    token=register(client)
    updated=client.put('/api/profile',json={'name':'Updated Name','current_password':'Correct-Horse-42!','new_password':'New-Correct-Horse-55!'},headers={'X-CSRF-Token':token})
    assert updated.status_code==200 and updated.json()['user']['name']=='Updated Name'
    assert client.post('/api/login',json={'email':'learner@example.edu','password':'New-Correct-Horse-55!'}).status_code==200
def test_account_lockout_after_five_failed_attempts(client):
    register(client)
    for _ in range(5): client.post('/api/login',json={'email':'learner@example.edu','password':'incorrect-password'})
    r=client.post('/api/login',json={'email':'learner@example.edu','password':'Correct-Horse-42!'});assert r.status_code==423
def test_student_cannot_create_instructor_course(client):
    token=register(client)
    r=client.post('/api/courses',json={'title':'Forbidden course','price':0},headers={'X-CSRF-Token':token});assert r.status_code==403
def test_public_course_details_are_available(client):
    _,course=_course(client)
    detail=client.get(f"/api/courses/{course.json()['id']}")
    assert detail.status_code==200 and detail.json()['title']=='Secure Learning' and detail.json()['currency']=='USD'
def _course(client, role='instructor', email='teacher@example.edu'):
    token=register(client,email,role,'Test Teacher' if role=='instructor' else 'Test Student')
    r=client.post('/api/courses',json={'title':'Secure Learning','description':'Test content','price':42.5,'currency':'USD'},headers={'X-CSRF-Token':token})
    return token,r
def test_verified_payment_enrolls_once(client):
    teacher=ClientProxy(client); ttoken,course=_course(teacher); assert course.status_code==200
    student=ClientProxy(client); stoken=register(student,'s@example.edu')
    order=student.post(f"/api/checkout/{course.json()['id']}",headers={'X-CSRF-Token':stoken}).json()
    paid=student.post(f"/api/demo-gateway/{order['order_id']}",headers={'X-CSRF-Token':stoken}); assert paid.status_code==200 and paid.json()['enrolled']
    replay=student.post(f"/api/demo-gateway/{order['order_id']}",headers={'X-CSRF-Token':stoken}); assert replay.status_code==409
    assert len(student.get('/api/my/courses').json())==1
def test_forged_webhook_signature_rejected(client):
    instructor=ClientProxy(client); _,course=_course(instructor)
    student=ClientProxy(client);st=register(student,'pay@example.edu');order=student.post(f"/api/checkout/{course.json()['id']}",headers={'X-CSRF-Token':st}).json()
    body=canonical_json({'event_id':'forged-1','order_id':order['order_id'],'amount':42.5,'currency':'USD'});ts=int(time.time())
    r=student.post('/api/webhooks/payment',content=body,headers={'X-Webhook-Timestamp':str(ts),'X-Webhook-Signature':'00'*32});assert r.status_code==400 and r.json()['detail'].startswith('Invalid signature')
def test_expired_webhook_rejected(client):
    instructor=ClientProxy(client); _,course=_course(instructor)
    student=ClientProxy(client);st=register(student,'oldpay@example.edu');order=student.post(f"/api/checkout/{course.json()['id']}",headers={'X-CSRF-Token':st}).json()
    body=canonical_json({'event_id':'expired-1','order_id':order['order_id'],'amount':42.5,'currency':'USD'});ts=int(time.time())-301;sig=sign_webhook(WEBHOOK_SECRET.encode(),ts,body)
    r=student.post('/api/webhooks/payment',content=body,headers={'X-Webhook-Timestamp':str(ts),'X-Webhook-Signature':sig});assert r.status_code==400
def test_webhook_amount_mismatch_rejected(client):
    instructor=ClientProxy(client);_,course=_course(instructor)
    student=ClientProxy(client);st=register(student,'amt@example.edu');order=student.post(f"/api/checkout/{course.json()['id']}",headers={'X-CSRF-Token':st}).json()
    body=canonical_json({'event_id':'amount-1','order_id':order['order_id'],'amount':1.0,'currency':'USD'});ts=int(time.time());sig=sign_webhook(WEBHOOK_SECRET.encode(),ts,body)
    r=student.post('/api/webhooks/payment',content=body,headers={'X-Webhook-Timestamp':str(ts),'X-Webhook-Signature':sig});assert r.status_code==400 and 'mismatch' in r.json()['detail']
def test_course_file_encrypted_download_and_tampering_rejection(client):
    teacher=ClientProxy(client);token,course=_course(teacher)
    uploaded=teacher.post(f"/api/courses/{course.json()['id']}/materials",files={'file':('notes.txt',b'private course notes','text/plain')},headers={'X-CSRF-Token':token});assert uploaded.status_code==200 and uploaded.json()['encrypted']
    material_id=uploaded.json()['id'];db=next(client.app.dependency_overrides[get_db]());m=db.get(Material,material_id);cipher=Path(m.path).read_bytes();assert b'private course notes' not in cipher
    denied=ClientProxy(client);register(denied,'not-enrolled@example.edu');assert denied.get(f'/api/materials/{material_id}/download').status_code==403
    student=ClientProxy(client);st=register(student,'enrolled@example.edu');order=student.post(f"/api/checkout/{course.json()['id']}",headers={'X-CSRF-Token':st}).json();student.post(f"/api/demo-gateway/{order['order_id']}",headers={'X-CSRF-Token':st})
    ok=student.get(f'/api/materials/{material_id}/download');assert ok.status_code==200 and ok.content==b'private course notes'
    altered=bytearray(cipher);altered[0]^=1;Path(m.path).write_bytes(altered)
    bad=student.get(f'/api/materials/{material_id}/download');assert bad.status_code==400 and b'private course notes' not in bad.content
    Path(m.path).write_bytes(cipher);db.close()
def test_grade_is_encrypted_and_only_available_to_owner(client):
    teacher=ClientProxy(client);token,course=_course(teacher)
    student=ClientProxy(client);st=register(student,'grade@example.edu');order=student.post(f"/api/checkout/{course.json()['id']}",headers={'X-CSRF-Token':st}).json();student.post(f"/api/demo-gateway/{order['order_id']}",headers={'X-CSRF-Token':st})
    student_id=student.get('/api/me').json()['user']['id'];saved=teacher.post('/api/grades',json={'student_id':student_id,'course_id':course.json()['id'],'grade':'A'},headers={'X-CSRF-Token':token});assert saved.status_code==200
    assert student.get('/api/my/grades').json()[0]['grade']=='A'
    stranger=ClientProxy(client);register(stranger,'other@example.edu');assert stranger.get('/api/my/grades').json()==[]
def test_certificate_signature_and_chain_verify(client):
    teacher=ClientProxy(client);token,course=_course(teacher)
    student=ClientProxy(client);st=register(student,'cert@example.edu');order=student.post(f"/api/checkout/{course.json()['id']}",headers={'X-CSRF-Token':st}).json();student.post(f"/api/demo-gateway/{order['order_id']}",headers={'X-CSRF-Token':st})
    sid=student.get('/api/me').json()['user']['id'];issued=teacher.post(f"/api/certificates/{course.json()['id']}?student_id={sid}",headers={'X-CSRF-Token':token});assert issued.status_code==200
    verified=student.get('/api/verify/'+issued.json()['document']['credential_id']);assert verified.status_code==200 and verified.json()['certificate_status']=='VALID'
    from backend.app.main import AUTH
    assert AUTH['root_fingerprint'] and AUTH['root_cert'].exists()

class ClientProxy:
    """Each logical user gets an independent cookie jar over the same test DB."""
    def __init__(self, base):
        self.client=base.__class__(base.app,base_url=str(base.base_url))
    def __getattr__(self,name): return getattr(self.client,name)
