from __future__ import annotations
import hashlib, hmac, json, os, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request, Response, UploadFile, File, Form, Header
from fastapi.responses import FileResponse, HTMLResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from cryptography import x509
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from .config import SESSION_SECRET, WEBHOOK_SECRET, KEY_DIR, CERT_DIR, STORAGE_DIR, SECURE_COOKIES, INSTRUCTOR_INVITE_CODE
from .database import Base, engine, get_db
from .models import User, Course, Enrollment, Payment, Material, Grade, Credential, AuditEvent
from .cryptography.primitives import *
from .cryptography.authority import load_authority, verify_certificate_chain
from .cryptography.channel import establish_channel

Base.metadata.create_all(bind=engine)
AUTH = load_authority(CERT_DIR, KEY_DIR)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="EduSecure", version="1.0.0", description="Layered cryptographic security educational platform")
app.add_middleware(CORSMiddleware, allow_origins=["https://localhost:5173", "http://localhost:5173"], allow_credentials=True, allow_methods=["GET","POST","PUT","DELETE"], allow_headers=["Content-Type","X-CSRF-Token","X-Webhook-Timestamp","X-Webhook-Signature"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response=await call_next(request)
    response.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"]="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self' https://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers["X-Content-Type-Options"]="nosniff"; response.headers["Referrer-Policy"]="no-referrer"; response.headers["X-Frame-Options"]="DENY"
    return response

def _token(user: User, csrf: str) -> str:
    payload=b64e(canonical_json({"uid":user.id,"role":user.role,"exp":int(time.time())+8*3600,"csrf":csrf}))
    return payload+"."+hmac.new(SESSION_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
def _session(raw: str | None):
    if not raw: raise HTTPException(401,"Authentication required")
    try:
        payload, sig=raw.rsplit(".",1)
        expected=hmac.new(SESSION_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,expected): raise ValueError()
        data=json.loads(b64d(payload))
        if data["exp"]<time.time(): raise ValueError()
        return data
    except Exception: raise HTTPException(401,"Session is invalid or expired")
def current_user(request: Request, db: Session=Depends(get_db)) -> User:
    data=_session(request.cookies.get("edusecure_session")); user=db.get(User,data["uid"])
    if not user: raise HTTPException(401,"Account no longer exists")
    request.state.session=data
    return user
def require_role(*roles):
    def dependency(user: User=Depends(current_user)):
        if user.role not in roles: raise HTTPException(403,"This action is not permitted for your role")
        return user
    return dependency
def csrf(request: Request, token: str | None=Header(default=None, alias="X-CSRF-Token")):
    data=getattr(request.state,"session",None) or _session(request.cookies.get("edusecure_session"))
    if not token or not hmac.compare_digest(token,data["csrf"]): raise HTTPException(403,"CSRF validation failed")
    return True
def set_session(response: Response, user: User):
    token=secrets.token_urlsafe(24); response.set_cookie("edusecure_session",_token(user,token),httponly=True,secure=SECURE_COOKIES,samesite="lax",max_age=28800,path="/")
    response.set_cookie("edusecure_csrf",token,httponly=False,secure=SECURE_COOKIES,samesite="lax",max_age=28800,path="/")
def user_view(user): return {"id":user.id,"email":user.email,"name":user.name,"role":user.role}
def audit(db:Session,actor_id:int|None,action:str,outcome:str,object_ref:str=""):
    db.add(AuditEvent(actor_id=actor_id,action=action,outcome=outcome,object_ref=object_ref[:120]))

class RegisterIn(BaseModel):
    email: EmailStr; name: str=Field(min_length=2,max_length=120); password: str=Field(min_length=10,max_length=128); role: str="student"; instructor_code: str=""
class LoginIn(BaseModel): email: EmailStr; password: str
class CourseIn(BaseModel): title: str=Field(min_length=3,max_length=160); description: str=""; price: float=Field(ge=0); currency: str="USD"
class GradeIn(BaseModel): student_id: int; course_id: int; grade: str=Field(min_length=1,max_length=100)
class DemoIn(BaseModel): text: str=Field(max_length=3000, default="EduSecure cryptographic demonstration")

@app.get("/api/health")
def health(): return {"status":"ok","service":"EduSecure","demo_environment":True}

@app.post("/api/register")
def register(data: RegisterIn, response: Response, db: Session=Depends(get_db)):
    email=data.email.lower()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,"Email already registered")
    role="student"
    if data.role=="instructor":
        if not INSTRUCTOR_INVITE_CODE or not hmac.compare_digest(data.instructor_code,INSTRUCTOR_INVITE_CODE): raise HTTPException(403,"Instructor accounts require a configured invitation code")
        role="instructor"
    salt,digest=password_hash(data.password)
    user=User(email=email,name=data.name,role=role,salt=salt,password_digest=digest); db.add(user); db.flush(); audit(db,user.id,"account.registered","success"); db.commit(); db.refresh(user); set_session(response,user)
    return {"user":user_view(user),"message":"Account created"}

@app.post("/api/login")
def login(data: LoginIn, response: Response, db: Session=Depends(get_db)):
    user=db.scalar(select(User).where(User.email==data.email.lower()))
    if not user:
        password_hash(data.password,b"EduSecureDummySalt")
        raise HTTPException(401,"Invalid email or password")
    now=datetime.now(timezone.utc)
    locked=user.locked_until
    if locked and locked.tzinfo is None: locked=locked.replace(tzinfo=timezone.utc)
    if locked and locked>now: raise HTTPException(423,"Account locked temporarily")
    if not password_verify(data.password,user.salt,user.password_digest):
        user.failed_logins+=1
        if user.failed_logins>=5: user.locked_until=now+timedelta(minutes=5); user.failed_logins=0
        audit(db,user.id,"authentication.login","denied")
        db.commit(); raise HTTPException(401,"Invalid email or password")
    user.failed_logins=0; user.locked_until=None; audit(db,user.id,"authentication.login","success"); db.commit(); set_session(response,user)
    return {"user":user_view(user)}

@app.get("/api/me")
def me(user: User=Depends(current_user), request: Request=None):
    return {"user":user_view(user),"csrf_token":request.state.session["csrf"]}
@app.post("/api/logout")
def logout(response: Response, _: bool=Depends(csrf)):
    response.delete_cookie("edusecure_session",path="/"); response.delete_cookie("edusecure_csrf",path="/"); return {"ok":True}

@app.get("/api/courses")
def courses(db: Session=Depends(get_db)):
    return [{"id":x.id,"title":x.title,"description":x.description,"price":x.price,"currency":x.currency,"instructor":db.get(User,x.instructor_id).name} for x in db.scalars(select(Course)).all()]
@app.get("/api/courses/{course_id}")
def course_detail(course_id:int,db:Session=Depends(get_db)):
    course=db.get(Course,course_id)
    if not course: raise HTTPException(404,"Course not found")
    instructor=db.get(User,course.instructor_id)
    return {"id":course.id,"title":course.title,"description":course.description,"price":course.price,"currency":course.currency,"instructor":instructor.name}
@app.post("/api/courses")
def create_course(data: CourseIn, user: User=Depends(require_role("instructor")), _: bool=Depends(csrf), db: Session=Depends(get_db)):
    course=Course(instructor_id=user.id,title=data.title,description=data.description,price=data.price,currency=data.currency.upper()); db.add(course); db.flush(); audit(db,user.id,"course.created","success",str(course.id)); db.commit(); db.refresh(course)
    return {"id":course.id,"title":course.title,"price":course.price,"currency":course.currency}
@app.get("/api/my/courses")
def my_courses(user: User=Depends(current_user), db: Session=Depends(get_db)):
    if user.role=="instructor": rows=db.scalars(select(Course).where(Course.instructor_id==user.id)).all()
    else: rows=db.scalars(select(Course).join(Enrollment,Enrollment.course_id==Course.id).where(Enrollment.student_id==user.id)).all()
    return [{"id":c.id,"title":c.title,"description":c.description,"price":c.price,"currency":c.currency} for c in rows]

@app.get("/api/my/audit")
def my_audit(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(AuditEvent).where(AuditEvent.actor_id==user.id).order_by(AuditEvent.created_at.desc()).limit(25)).all()
    return [{"action":x.action,"outcome":x.outcome,"object_ref":x.object_ref,"created_at":x.created_at.isoformat()} for x in rows]

@app.get("/api/instructor/overview")
def instructor_overview(user:User=Depends(require_role("instructor")),db:Session=Depends(get_db)):
    owned=db.scalars(select(Course).where(Course.instructor_id==user.id)).all(); ids=[c.id for c in owned]
    enrollments=db.scalar(select(func.count(Enrollment.id)).where(Enrollment.course_id.in_(ids))) if ids else 0
    sales=db.scalar(select(func.coalesce(func.sum(Payment.amount),0)).join(Course,Payment.course_id==Course.id).where(Course.instructor_id==user.id,Payment.status=="paid")) or 0
    breakdown=db.execute(select(Course.title,func.coalesce(func.sum(Payment.amount),0)).outerjoin(Payment,(Payment.course_id==Course.id)&(Payment.status=="paid")).where(Course.instructor_id==user.id).group_by(Course.id)).all()
    return {"courses":len(owned),"enrollments":enrollments,"sales":float(sales),"currency":"USD","sales_by_course":[{"course":name,"sales":float(amount)} for name,amount in breakdown]}

class ProfileIn(BaseModel):
    name: str=Field(min_length=2,max_length=120)
    current_password: str=Field(min_length=10,max_length=128)
    new_password: str | None=Field(default=None,min_length=10,max_length=128)

@app.put("/api/profile")
def update_profile(data:ProfileIn,user:User=Depends(current_user),_:bool=Depends(csrf),db:Session=Depends(get_db)):
    if not password_verify(data.current_password,user.salt,user.password_digest): raise HTTPException(400,"Current password is incorrect")
    user.name=data.name
    if data.new_password:
        user.salt,user.password_digest=password_hash(data.new_password)
    audit(db,user.id,"profile.updated","success","password-rotated" if data.new_password else "name-updated")
    db.commit();return {"user":user_view(user),"password_changed":bool(data.new_password)}

@app.post("/api/checkout/{course_id}")
def checkout(course_id: int,user: User=Depends(require_role("student")), _: bool=Depends(csrf), db: Session=Depends(get_db)):
    c=db.get(Course,course_id)
    if not c: raise HTTPException(404,"Course not found")
    if db.scalar(select(Enrollment).where(Enrollment.student_id==user.id,Enrollment.course_id==c.id)): raise HTTPException(409,"Already enrolled")
    p=Payment(id=str(uuid.uuid4()),student_id=user.id,course_id=c.id,amount=c.price,currency=c.currency); db.add(p); db.commit()
    return {"order_id":p.id,"status":"pending","amount":p.amount,"currency":p.currency,"checkout_url":"/api/demo-gateway/"+p.id,"demo_environment":True,"message":"No card data is requested or stored."}

def _process_webhook(raw: bytes, timestamp: int, signature: str, db: Session):
    if not verify_webhook(WEBHOOK_SECRET.encode(),timestamp,raw,signature): raise HTTPException(400,"Invalid signature or expired timestamp")
    try: event=json.loads(raw)
    except Exception: raise HTTPException(400,"Malformed event")
    payment=db.get(Payment,event.get("order_id"))
    if not payment: raise HTTPException(404,"Payment order not found")
    if payment.status!="pending" or (event.get("event_id") and db.scalar(select(Payment).where(Payment.event_id==event["event_id"]))): raise HTTPException(409,"Duplicate or replayed event")
    if float(event.get("amount",-1))!=payment.amount or event.get("currency")!=payment.currency: raise HTTPException(400,"Payment amount or currency mismatch")
    payment.status="paid"; payment.event_id=event.get("event_id",str(uuid.uuid4()))
    exists=db.scalar(select(Enrollment).where(Enrollment.student_id==payment.student_id,Enrollment.course_id==payment.course_id))
    if not exists: db.add(Enrollment(student_id=payment.student_id,course_id=payment.course_id))
    audit(db,payment.student_id,"payment.webhook","verified",payment.id)
    db.commit(); return {"status":"paid","enrolled":True,"receipt_verified":True,"demo_environment":True}

@app.post("/api/webhooks/payment")
async def payment_webhook(request: Request, db: Session=Depends(get_db), x_webhook_timestamp: int=Header(alias="X-Webhook-Timestamp"), x_webhook_signature: str=Header(alias="X-Webhook-Signature")):
    return _process_webhook(await request.body(),x_webhook_timestamp,x_webhook_signature,db)
@app.post("/api/demo-gateway/{order_id}")
def demo_gateway(order_id: str, user: User=Depends(require_role("student")), _: bool=Depends(csrf), db: Session=Depends(get_db)):
    p=db.get(Payment,order_id)
    if not p or p.student_id!=user.id: raise HTTPException(404,"Order not found")
    event={"event_id":str(uuid.uuid4()),"order_id":p.id,"amount":p.amount,"currency":p.currency,"status":"succeeded"}
    body=canonical_json(event); ts=int(time.time()); sig=sign_webhook(WEBHOOK_SECRET.encode(),ts,body)
    return _process_webhook(body,ts,sig,db)
@app.get("/api/my/payments")
def my_payments(user: User=Depends(current_user), db: Session=Depends(get_db)):
    rows=db.scalars(select(Payment).where(Payment.student_id==user.id).order_by(Payment.created_at.desc())).all()
    return [{"id":p.id,"course":db.get(Course,p.course_id).title,"amount":p.amount,"currency":p.currency,"status":p.status,"created_at":p.created_at.isoformat()} for p in rows]

@app.get("/api/instructor/roster")
def instructor_roster(user:User=Depends(require_role("instructor")),db:Session=Depends(get_db)):
    rows=db.execute(select(Enrollment,Course,User).join(Course,Enrollment.course_id==Course.id).join(User,Enrollment.student_id==User.id).where(Course.instructor_id==user.id)).all()
    return [{"student_id":u.id,"student_name":u.name,"email":u.email,"course_id":c.id,"course":c.title} for _,c,u in rows]

@app.get("/api/instructor/materials")
def instructor_materials(user:User=Depends(require_role("instructor")),db:Session=Depends(get_db)):
    rows=db.scalars(select(Material).where(Material.instructor_id==user.id)).all()
    return [{"id":m.id,"course_id":m.course_id,"course":db.get(Course,m.course_id).title,"filename":m.filename,"size":m.size} for m in rows]

@app.post("/api/courses/{course_id}/materials")
async def upload_material(course_id:int,file:UploadFile=File(...),user:User=Depends(require_role("instructor")),_:bool=Depends(csrf),db:Session=Depends(get_db)):
    course=db.get(Course,course_id)
    if not course or course.instructor_id!=user.id: raise HTTPException(404,"Course not found")
    data=await file.read(20*1024*1024+1)
    if len(data)>20*1024*1024: raise HTTPException(413,"Maximum file size is 20 MiB")
    dek=os.urandom(32); nonce,ciphertext=aes_encrypt(dek,data,f"course:{course_id}".encode()); wrapped=rsa_wrap(AUTH["wrap_key"].public_key(),dek); digest=sha256(data)
    identifier=str(uuid.uuid4()); path=STORAGE_DIR/(identifier+".bin"); path.write_bytes(ciphertext)
    m=Material(course_id=course_id,instructor_id=user.id,filename=Path(file.filename or "material").name,path=str(path),nonce=nonce,wrapped_key=wrapped,digest=digest,size=len(data)); db.add(m); db.flush(); audit(db,user.id,"material.uploaded","encrypted",str(m.id)); db.commit(); db.refresh(m)
    return {"id":m.id,"filename":m.filename,"size":m.size,"sha256":m.digest,"encrypted":True}
@app.get("/api/materials/{material_id}/download")
def download_material(material_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    m=db.get(Material,material_id)
    if not m: raise HTTPException(404,"Material not found")
    enrolled=db.scalar(select(Enrollment).where(Enrollment.student_id==user.id,Enrollment.course_id==m.course_id))
    owns=user.role=="instructor" and user.id==m.instructor_id
    if not enrolled and not owns: raise HTTPException(403,"Enrollment required")
    try:
        ciphertext=Path(m.path).read_bytes(); dek=rsa_unwrap(AUTH["wrap_key"],m.wrapped_key); plaintext=aes_decrypt(dek,m.nonce,ciphertext,f"course:{m.course_id}".encode())
        if not hmac.compare_digest(sha256(plaintext),m.digest): raise ValueError("digest mismatch")
    except Exception: raise HTTPException(400,"Encrypted material integrity verification failed")
    temporary=STORAGE_DIR.parent/"temporary"; temporary.mkdir(parents=True,exist_ok=True)
    audit(db,user.id,"material.download","verified",str(m.id));db.commit()
    out=temporary/(str(uuid.uuid4())+".verified"); out.write_bytes(plaintext)
    return FileResponse(out,filename=m.filename,media_type="application/octet-stream",background=BackgroundTask(out.unlink,missing_ok=True))

@app.post("/api/grades")
def put_grade(data:GradeIn,user:User=Depends(require_role("instructor")),_:bool=Depends(csrf),db:Session=Depends(get_db)):
    c=db.get(Course,data.course_id)
    if not c or c.instructor_id!=user.id: raise HTTPException(404,"Course not found")
    if not db.get(User,data.student_id): raise HTTPException(404,"Student not found")
    dek=os.urandom(32); nonce,cipher=aes_encrypt(dek,data.grade.encode(),f"grade:{data.student_id}:{data.course_id}".encode()); wrapped=rsa_wrap(AUTH["wrap_key"].public_key(),dek)
    row=db.scalar(select(Grade).where(Grade.student_id==data.student_id,Grade.course_id==data.course_id))
    if row: row.nonce=nonce; row.wrapped_key=wrapped; row.ciphertext=cipher; row.updated_at=datetime.now(timezone.utc)
    else: db.add(Grade(student_id=data.student_id,course_id=data.course_id,nonce=nonce,wrapped_key=wrapped,ciphertext=cipher))
    audit(db,user.id,"grade.saved","encrypted",f"{data.student_id}:{data.course_id}");db.commit(); return {"saved":True,"encrypted":True}
@app.get("/api/my/grades")
def my_grades(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(Grade).where(Grade.student_id==user.id)).all(); result=[]
    for g in rows:
        try:
            dek=rsa_unwrap(AUTH["wrap_key"],g.wrapped_key); grade=aes_decrypt(dek,g.nonce,g.ciphertext,f"grade:{g.student_id}:{g.course_id}".encode()).decode()
        except Exception: raise HTTPException(400,"Grade integrity verification failed")
        result.append({"course":db.get(Course,g.course_id).title,"grade":grade})
    return result

@app.get("/api/my/materials")
def my_materials(user:User=Depends(current_user),db:Session=Depends(get_db)):
    if user.role=="instructor": rows=db.scalars(select(Material).where(Material.instructor_id==user.id)).all()
    else: rows=db.scalars(select(Material).join(Enrollment,Enrollment.course_id==Material.course_id).where(Enrollment.student_id==user.id)).all()
    return [{"id":m.id,"course":db.get(Course,m.course_id).title,"filename":m.filename,"size":m.size} for m in rows]

@app.post("/api/certificates/{course_id}")
def issue_certificate(course_id:int,student_id:int,user:User=Depends(require_role("instructor")),_:bool=Depends(csrf),db:Session=Depends(get_db)):
    c=db.get(Course,course_id); student=db.get(User,student_id)
    if not c or c.instructor_id!=user.id or not student: raise HTTPException(404,"Course or student not found")
    if not db.scalar(select(Enrollment).where(Enrollment.student_id==student_id,Enrollment.course_id==course_id)): raise HTTPException(409,"Student is not enrolled")
    cid=str(uuid.uuid4()); doc={"credential_id":cid,"student_name":student.name,"student_email":student.email,"course":c.title,"issuer":"EduSecure Credential Issuer","issued_at":datetime.now(timezone.utc).isoformat()}
    envelope=signed_document(doc,AUTH["issuer_key"]); db.add(Credential(id=cid,student_id=student_id,course_id=course_id,envelope=json.dumps(envelope,separators=(",",":"))));audit(db,user.id,"credential.issued","signed",cid); db.commit()
    return envelope
@app.get("/api/my/certificates")
def my_certificates(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(Credential).where(Credential.student_id==user.id)).all()
    return [{"id":c.id,"course":db.get(Course,c.course_id).title,"verify_url":"/api/verify/"+c.id,"issued_at":json.loads(c.envelope)["document"]["issued_at"]} for c in rows]
@app.get("/api/verify/{credential_id}")
def verify_credential(credential_id:str,db:Session=Depends(get_db)):
    row=db.get(Credential,credential_id)
    if not row: raise HTTPException(404,"Credential not found")
    envelope=json.loads(row.envelope)
    valid=verify_document(envelope,AUTH["issuer_key"].public_key()) and verify_certificate_chain(AUTH["issuer_cert"].read_bytes(),AUTH["root_cert"].read_bytes(),AUTH["root_cert"].read_bytes())
    return {"certificate_status":"VALID" if valid else "INVALID","document_integrity":"VERIFIED" if valid else "FAILED","digital_signature":"VALID" if valid else "INVALID","certificate_chain":"TRUSTED" if valid else "UNTRUSTED","document":envelope["document"]}

@app.get("/api/security")
def security_status(request:Request):
    server_cert=x509.load_pem_x509_certificate(AUTH["server_cert"].read_bytes())
    common_name=server_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    return {"layers":[
        {"id":1,"name":"Transport Security","algorithm":"TLS 1.2+ / ECDSA","status":"Configured","verification":"Active when served with HTTPS"},
        {"id":2,"name":"Secure Channel","algorithm":"X25519 + HKDF-SHA256 + AES-256-GCM","status":"Implemented","verification":"Independent demonstration API"},
        {"id":3,"name":"Authentication","algorithm":"PBKDF2-HMAC-SHA256 (600,000)","status":"Implemented","verification":"HMAC session and CSRF"},
        {"id":4,"name":"Payment Security","algorithm":"HMAC-SHA256","status":"Implemented","verification":"Timestamp, amount, currency, replay checks"},
        {"id":5,"name":"Digital Credentials","algorithm":"SHA-256 + ECDSA P-256 + X.509","status":"Implemented","verification":"Signature and issuer chain"},
        {"id":6,"name":"Data at Rest","algorithm":"AES-256-GCM + RSA-3072-OAEP + SHA-256","status":"Implemented","verification":"Per-file and per-grade DEK"}],
        "root_ca_sha256":AUTH["root_fingerprint"],"root_ca_subject":"EduSecure Local Root CA","tls_minimum":"TLS 1.2","tls12_cipher_required":"ECDHE-ECDSA-AES256-GCM-SHA384","server_certificate":{"subject":common_name,"not_before":server_cert.not_valid_before_utc.isoformat(),"not_after":server_cert.not_valid_after_utc.isoformat(),"sha256":server_cert.fingerprint(hashes.SHA256()).hex()},"transport_active":request.url.scheme=="https","password_iterations":PBKDF2_ITERATIONS,"demo_environment":True,"transport_note":"Run with scripts/run_https.ps1 for live TLS verification."}

@app.post("/api/demo/crypto")
def crypto_demo(data:DemoIn,user:User=Depends(current_user),_:bool=Depends(csrf)):
    raw=data.text.encode(); dek=os.urandom(32); nonce,cipher=aes_encrypt(dek,raw); digest=sha256(raw)
    wrapped=rsa_wrap(AUTH["wrap_key"].public_key(),dek); unwrapped=rsa_unwrap(AUTH["wrap_key"],wrapped); recovered=aes_decrypt(unwrapped,nonce,cipher)
    ekey=ecdsa_generate(); sig=ecdsa_sign(ekey,raw); verified=ecdsa_verify(ekey.public_key(),raw,sig)
    client=x25519_pair(); server=x25519_pair(); shared_a=client.exchange(server.public_key()); shared_b=server.exchange(client.public_key()); k1,k2=derive_channel_keys(shared_a,os.urandom(16))
    ts=int(time.time()); wh=sign_webhook(WEBHOOK_SECRET.encode(),ts,raw); sample_salt,sample_digest=password_hash("Disposable EduSecure demonstration phrase")
    return {"aes_gcm":{"encrypted":True,"round_trip":recovered==raw,"ciphertext_bytes":len(cipher)},"rsa_oaep":{"key_bits":3072,"wrapped_and_unwrapped":hmac.compare_digest(dek,unwrapped)},"sha256":{"digest":digest,"verified":hmac.compare_digest(digest,sha256(recovered))},"ecdsa_p256":{"signature_verified":verified},"x25519_hkdf":{"shared_secrets_equal":hmac.compare_digest(shared_a,shared_b),"directional_keys_distinct":not hmac.compare_digest(k1,k2)},"hmac_sha256":{"signature_verified":verify_webhook(WEBHOOK_SECRET.encode(),ts,raw,wh)},"pbkdf2":{"iterations":PBKDF2_ITERATIONS,"salt_bytes":len(sample_salt),"derived_bytes":len(sample_digest),"sample_verifier_matches":password_verify("Disposable EduSecure demonstration phrase",sample_salt,sample_digest),"sample_password_stored":False}}

@app.post("/api/demo/channel")
def channel_demo(data:DemoIn,user:User=Depends(current_user),_:bool=Depends(csrf)):
    session=establish_channel(AUTH["issuer_key"],AUTH["issuer_cert"].read_bytes(),AUTH["root_cert"].read_bytes())
    record=session["client"].encrypt(data.text.encode()); recovered=session["server"].decrypt(record)
    return {"certificate_chain_verified":True,"ecdsa_key_exchange_signature_verified":True,"x25519_shared_secret_agreement":session["shared_match"],"hkdf_directional_keys_distinct":session["directions_separate"],"record_sequence":record.sequence,"encrypted_record_round_trip":recovered==data.text.encode(),"application_transport_note":"TLS remains the only transport security layer."}

@app.get("/api/certificates/root")
def download_root(): return FileResponse(AUTH["root_cert"],filename="edusecure-root-ca.pem",media_type="application/x-pem-file")

@app.get("/",response_class=HTMLResponse)
def root():
    index=Path(__file__).resolve().parents[2]/"frontend"/"dist"/"index.html"
    if index.exists(): return HTMLResponse(index.read_text(encoding="utf-8"))
    return HTMLResponse("""<!doctype html><html><head><title>EduSecure</title></head><body><h1>EduSecure API is running</h1><p>Start the Vite frontend with <code>npm run dev</code> in frontend/.</p><a href='/docs'>API documentation</a></body></html>""")

_assets=Path(__file__).resolve().parents[2]/"frontend"/"dist"/"assets"
if _assets.exists(): app.mount("/assets",StaticFiles(directory=_assets),name="assets")
