import os
os.environ["EDUSECURE_SECURE_COOKIES"]="false"
os.environ["EDUSECURE_SESSION_SECRET"]="test-session-secret-32-bytes-minimum-value"
os.environ["EDUSECURE_WEBHOOK_SECRET"]="test-webhook-secret-32-bytes-minimum-value"
os.environ["EDUSECURE_INSTRUCTOR_INVITE"]="test-instructor-invite"
import pytest
from backend.app.config import KEY_DIR,CERT_DIR
from backend.app.cryptography.authority import bootstrap_authority
bootstrap_authority(CERT_DIR,KEY_DIR)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from backend.app.database import Base, get_db
from backend.app.main import app

@pytest.fixture()
def client():
    engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool)
    TestingSession=sessionmaker(bind=engine,autoflush=False,expire_on_commit=False)
    Base.metadata.create_all(engine)
    def override():
        db=TestingSession()
        try: yield db
        finally: db.close()
    app.dependency_overrides[get_db]=override
    with TestClient(app) as c: yield c
    app.dependency_overrides.clear(); Base.metadata.drop_all(engine); engine.dispose()

def csrf(client):
    response=client.get('/api/me')
    return response.json()['csrf_token']

def register(client,email='learner@example.edu',role='student',name='Test Learner'):
    response=client.post('/api/register',json={'email':email,'name':name,'password':'Correct-Horse-42!','role':role,'instructor_code':'test-instructor-invite' if role=='instructor' else ''})
    assert response.status_code==200, response.text
    return csrf(client)
