"""Run as a separate local bootstrap step; the web process does not load the Root CA key."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.app.config import KEY_DIR,CERT_DIR
from backend.app.cryptography.authority import bootstrap_authority
materials=bootstrap_authority(CERT_DIR,KEY_DIR)
print(f"EduSecure local Root CA, issuer, HTTPS identity, and RSA-3072 wrapping key ready. Root fingerprint: {materials['root_fingerprint']}")
