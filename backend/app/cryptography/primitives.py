"""Small, independently testable wrappers around vetted cryptographic primitives."""
from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, time
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PBKDF2_ITERATIONS = 600_000

def b64e(value: bytes) -> str: return base64.urlsafe_b64encode(value).decode().rstrip("=")
def b64d(value: str) -> bytes: return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def password_hash(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, 32)

def password_verify(password: str, salt: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, 32), expected)

def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)

def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

def rsa_generate(): return rsa.generate_private_key(public_exponent=65537, key_size=3072)
def rsa_wrap(public_key, key: bytes) -> bytes:
    return public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
def rsa_unwrap(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def canonical_json(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
def ecdsa_generate(): return ec.generate_private_key(ec.SECP256R1())
def ecdsa_sign(private_key, data: bytes) -> bytes: return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
def ecdsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    try: public_key.verify(signature, data, ec.ECDSA(hashes.SHA256())); return True
    except InvalidSignature: return False

def x25519_pair(): return x25519.X25519PrivateKey.generate()
def xpub_bytes(private_key) -> bytes: return private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def derive_channel_keys(shared: bytes, salt: bytes) -> tuple[bytes, bytes]:
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"EduSecure channel v1 client-server").derive(shared)
    return material[:32], material[32:]

def sign_webhook(secret: bytes, timestamp: int, body: bytes) -> str:
    return hmac.new(secret, str(timestamp).encode() + b"." + body, hashlib.sha256).hexdigest()
def verify_webhook(secret: bytes, timestamp: int, body: bytes, signature: str, now: int | None = None, tolerance: int = 300) -> bool:
    if abs((int(time.time()) if now is None else now) - timestamp) > tolerance: return False
    return hmac.compare_digest(sign_webhook(secret, timestamp, body), signature.lower())

def signed_document(document: dict, private_key) -> dict:
    payload = canonical_json(document)
    return {"document": document, "sha256": sha256(payload), "signature": b64e(ecdsa_sign(private_key, payload))}
def verify_document(envelope: dict, public_key) -> bool:
    payload = canonical_json(envelope["document"])
    return hmac.compare_digest(sha256(payload), envelope["sha256"]) and ecdsa_verify(public_key, payload, b64d(envelope["signature"]))

@dataclass
class ChannelRecord:
    sequence: int
    nonce: bytes
    ciphertext: bytes

class SecureChannel:
    """Educational record layer; TLS remains the only application transport."""
    def __init__(self, send_key: bytes, receive_key: bytes):
        self.send_key, self.receive_key = send_key, receive_key
        self.send_sequence = self.receive_sequence = 0
    def encrypt(self, plaintext: bytes) -> ChannelRecord:
        seq = self.send_sequence; self.send_sequence += 1
        nonce = os.urandom(12); aad = seq.to_bytes(8, "big")
        return ChannelRecord(seq, nonce, AESGCM(self.send_key).encrypt(nonce, plaintext, aad))
    def decrypt(self, record: ChannelRecord) -> bytes:
        if record.sequence != self.receive_sequence: raise ValueError("replayed or out-of-order record")
        result = AESGCM(self.receive_key).decrypt(record.nonce, record.ciphertext, record.sequence.to_bytes(8, "big"))
        self.receive_sequence += 1
        return result
