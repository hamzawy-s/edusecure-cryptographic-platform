"""Create one instructor, one student, and one sample course with random one-time passwords."""
import secrets
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sqlalchemy import select
from backend.app.database import SessionLocal, Base, engine
from backend.app.models import User, Course
from backend.app.cryptography.primitives import password_hash

Base.metadata.create_all(bind=engine)
db=SessionLocal(); created=[]
for email,name,role in [('instructor@edusecure.example.com','Demo Instructor','instructor'),('student@edusecure.example.com','Demo Student','student')]:
    user=db.scalar(select(User).where(User.email==email))
    if user is None:
        password=secrets.token_urlsafe(18);salt,digest=password_hash(password);user=User(email=email,name=name,role=role,salt=salt,password_digest=digest);db.add(user);created.append((email,password))
db.commit();teacher=db.scalar(select(User).where(User.email=='instructor@edusecure.example.com'))
if db.scalar(select(Course).where(Course.instructor_id==teacher.id)) is None:
    db.add(Course(instructor_id=teacher.id,title='Foundations of Cybersecurity',description='A sample course for local demonstrations.',price=25.0,currency='USD'));db.commit()
db.close()
if created:
    print('One-time demo credentials (save these now; passwords are not recoverable):')
    for email,password in created: print(f'{email}  {password}')
else: print('Demo accounts already exist. Use your saved credentials or remove the demo rows and run again.')
