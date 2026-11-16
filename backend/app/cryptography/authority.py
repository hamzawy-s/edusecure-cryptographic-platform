"""Local demo CA bootstrap. Private keys stay on disk and are never returned by API."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from .primitives import ecdsa_generate

def _write_private(path: Path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

def bootstrap_authority(cert_dir: Path, key_dir: Path):
    cert_dir.mkdir(parents=True, exist_ok=True); key_dir.mkdir(parents=True, exist_ok=True)
    root_p, root_c = key_dir / "root-ca-key.pem", cert_dir / "root-ca.pem"
    issuer_p, issuer_c = key_dir / "issuer-key.pem", cert_dir / "issuer.pem"
    server_p, server_c = key_dir / "server-key.pem", cert_dir / "server.pem"
    wrap_p = key_dir / "file-wrap-rsa3072.pem"
    now = datetime.now(timezone.utc)
    if not root_p.exists() or not root_c.exists():
        key = ecdsa_generate(); name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EduSecure Local Root CA")])
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True).sign(key, hashes.SHA256())
        _write_private(root_p, key); root_c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    root_key = serialization.load_pem_private_key(root_p.read_bytes(), password=None)
    root_cert = x509.load_pem_x509_certificate(root_c.read_bytes())
    if not issuer_p.exists() or not issuer_c.exists():
        key = ecdsa_generate(); name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EduSecure Credential Issuer")])
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(root_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1825)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True).sign(root_key, hashes.SHA256())
        _write_private(issuer_p, key); issuer_c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if not server_p.exists() or not server_c.exists():
        key = ecdsa_generate(); name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(root_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=825)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("127.0.0.1")]), critical=False).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(root_key, hashes.SHA256())
        _write_private(server_p, key); server_c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if not wrap_p.exists():
        from cryptography.hazmat.primitives.asymmetric import rsa
        _write_private(wrap_p, rsa.generate_private_key(public_exponent=65537, key_size=3072))
    return {
        "root_cert": root_c, "issuer_cert": issuer_c, "server_cert": server_c,
        "issuer_key": serialization.load_pem_private_key(issuer_p.read_bytes(), password=None),
        "wrap_key": serialization.load_pem_private_key(wrap_p.read_bytes(), password=None),
        "root_fingerprint": root_cert.fingerprint(hashes.SHA256()).hex(),
        "root_certificate": root_cert,
    }

def verify_certificate_chain(cert_pem: bytes, issuer_pem: bytes, root_pem: bytes) -> bool:
    try:
        cert=x509.load_pem_x509_certificate(cert_pem); issuer=x509.load_pem_x509_certificate(issuer_pem); root=x509.load_pem_x509_certificate(root_pem)
        cert.verify_directly_issued_by(issuer); issuer.verify_directly_issued_by(root)
        now=datetime.now(timezone.utc)
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc and issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc and root.subject == root.issuer
    except Exception: return False

def load_authority(cert_dir: Path, key_dir: Path):
    """Load service keys without loading the Root CA private key into the web process."""
    root_c=cert_dir/"root-ca.pem"; issuer_c=cert_dir/"issuer.pem"; server_c=cert_dir/"server.pem"
    issuer_p=key_dir/"issuer-key.pem"; wrap_p=key_dir/"file-wrap-rsa3072.pem"
    if not all(p.exists() for p in (root_c,issuer_c,server_c,issuer_p,wrap_p)):
        raise FileNotFoundError("EduSecure keys/certificates are missing; run python scripts/init_keys.py first")
    root_cert=x509.load_pem_x509_certificate(root_c.read_bytes()); issuer_cert=x509.load_pem_x509_certificate(issuer_c.read_bytes())
    issuer_cert.verify_directly_issued_by(root_cert)
    issuer_key=serialization.load_pem_private_key(issuer_p.read_bytes(),password=None)
    if issuer_key.public_key().public_numbers()!=issuer_cert.public_key().public_numbers(): raise ValueError("Issuer signing key does not match its certificate")
    return {"root_cert":root_c,"issuer_cert":issuer_c,"server_cert":server_c,"issuer_key":issuer_key,
        "wrap_key":serialization.load_pem_private_key(wrap_p.read_bytes(),password=None),
        "root_fingerprint":root_cert.fingerprint(hashes.SHA256()).hex(),"root_certificate":root_cert}
