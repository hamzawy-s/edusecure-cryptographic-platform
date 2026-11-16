from pathlib import Path
import os, secrets
BASE_DIR = Path(__file__).resolve().parents[2]
def get_path(env: str, default: str) -> Path:
    value = Path(os.getenv(env, default)); return value if value.is_absolute() else BASE_DIR / value
DATABASE_URL = os.getenv("EDUSECURE_DATABASE_URL", f"sqlite:///{BASE_DIR / 'edusecure.db'}")
SESSION_SECRET = os.getenv("EDUSECURE_SESSION_SECRET", "")
WEBHOOK_SECRET = os.getenv("EDUSECURE_WEBHOOK_SECRET", "")
if not SESSION_SECRET: SESSION_SECRET = secrets.token_urlsafe(48)
if not WEBHOOK_SECRET: WEBHOOK_SECRET = secrets.token_urlsafe(48)
KEY_DIR = get_path("EDUSECURE_KEY_DIR", "keys")
CERT_DIR = get_path("EDUSECURE_CERT_DIR", "certificates")
STORAGE_DIR = get_path("EDUSECURE_STORAGE_DIR", "storage/encrypted")
SECURE_COOKIES = os.getenv("EDUSECURE_SECURE_COOKIES", "true").lower() == "true"
INSTRUCTOR_INVITE_CODE = os.getenv("EDUSECURE_INSTRUCTOR_INVITE", "")
