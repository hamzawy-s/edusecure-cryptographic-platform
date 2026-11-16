import hashlib, hmac, os
import pytest
from cryptography.exceptions import InvalidTag
from backend.app.cryptography.primitives import *
from backend.app.cryptography.channel import establish_channel
from backend.app.main import AUTH

def test_aes_gcm_round_trip():
    key=os.urandom(32); nonce,cipher=aes_encrypt(key,b"educational record",b"metadata"); assert aes_decrypt(key,nonce,cipher,b"metadata")==b"educational record"
def test_aes_gcm_tampering_rejected():
    key=os.urandom(32); nonce,cipher=aes_encrypt(key,b"grade: A"); changed=bytearray(cipher); changed[0]^=1
    with pytest.raises(InvalidTag): aes_decrypt(key,nonce,bytes(changed))
def test_aes_gcm_wrong_aad_rejected():
    key=os.urandom(32); nonce,cipher=aes_encrypt(key,b"file",b"course:1")
    with pytest.raises(InvalidTag): aes_decrypt(key,nonce,cipher,b"course:2")
def test_rsa_3072_oaep_wrap_unwrap():
    key=rsa_generate(); dek=os.urandom(32); wrapped=rsa_wrap(key.public_key(),dek); assert key.key_size==3072 and rsa_unwrap(key,wrapped)==dek
def test_rsa_oaep_wrong_private_key_rejected():
    a,b=rsa_generate(),rsa_generate()
    with pytest.raises(Exception): rsa_unwrap(b,rsa_wrap(a.public_key(),os.urandom(32)))
def test_sha256_known_answer(): assert sha256(b"abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
def test_pbkdf2_known_answer(): assert hashlib.pbkdf2_hmac('sha256',b'password',b'salt',1,32).hex()=="120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
def test_password_salt_is_random_and_verifies():
    s1,d1=password_hash("demo-pass"); s2,d2=password_hash("demo-pass"); assert len(s1)==16 and s1!=s2 and d1!=d2 and password_verify("demo-pass",s1,d1) and not password_verify("bad",s1,d1)
def test_password_iteration_configuration(): assert PBKDF2_ITERATIONS==600_000
def test_hmac_sha256_known_answer(): assert hmac.new(b"key",b"The quick brown fox jumps over the lazy dog",hashlib.sha256).hexdigest()=="f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
def test_x25519_shared_secret_agrees():
    a,b=x25519_pair(),x25519_pair(); assert a.exchange(b.public_key())==b.exchange(a.public_key())
def test_hkdf_directional_keys_agree_and_separate():
    a,b=x25519_pair(),x25519_pair(); shared=a.exchange(b.public_key()); c2s,s2c=derive_channel_keys(shared,b"unique salt"); assert c2s!=s2c and derive_channel_keys(b.exchange(a.public_key()),b"unique salt")== (c2s,s2c)
def test_ecdsa_p256_valid_signature():
    k=ecdsa_generate(); sig=ecdsa_sign(k,b"certificate"); assert k.curve.name=="secp256r1" and ecdsa_verify(k.public_key(),b"certificate",sig)
def test_ecdsa_rejects_wrong_document():
    k=ecdsa_generate(); sig=ecdsa_sign(k,b"original"); assert not ecdsa_verify(k.public_key(),b"changed",sig)
def test_channel_record_success_and_replay_rejection():
    key=os.urandom(32); sender=SecureChannel(key,b"unused receive key not 32 b"); receiver=SecureChannel(b"unused send key not 32 byt",key); record=sender.encrypt(b"hello"); assert receiver.decrypt(record)==b"hello"
    with pytest.raises(ValueError): receiver.decrypt(record)
def test_channel_record_tamper_rejected_without_advancing_sequence():
    key=os.urandom(32); sender=SecureChannel(key,b"unused receive key not 32 b"); receiver=SecureChannel(b"unused send key not 32 byt",key); r=sender.encrypt(b"hello"); bad=ChannelRecord(r.sequence,r.nonce,r.ciphertext[:-1]+bytes([r.ciphertext[-1]^1]))
    with pytest.raises(InvalidTag): receiver.decrypt(bad)
    assert receiver.decrypt(r)==b"hello"
def test_webhook_hmac_accepts_fresh_signed_body():
    body=b'{"amount":12}';ts=1000;sig=sign_webhook(b"s",ts,body);assert verify_webhook(b"s",ts,body,sig,now=1000)
def test_webhook_rejects_wrong_secret():
    body=b'{}';sig=sign_webhook(b"right",1000,body);assert not verify_webhook(b"wrong",1000,body,sig,now=1000)
def test_webhook_rejects_expired_timestamp():
    body=b'{}';sig=sign_webhook(b"s",1000,body);assert not verify_webhook(b"s",1000,body,sig,now=1301)
def test_signed_document_detects_tampering():
    k=ecdsa_generate(); envelope=signed_document({"student":"A","course":"C"},k);assert verify_document(envelope,k.public_key());envelope['document']['student']='B';assert not verify_document(envelope,k.public_key())
def test_authenticated_channel_signature_chain_and_encrypted_record():
    channel=establish_channel(AUTH['issuer_key'],AUTH['issuer_cert'].read_bytes(),AUTH['root_cert'].read_bytes());record=channel['client'].encrypt(b'channel proof')
    assert channel['shared_match'] and channel['directions_separate'] and channel['server'].decrypt(record)==b'channel proof'
def test_authenticated_channel_rejects_tampered_issuer_chain():
    with pytest.raises(ValueError,match='untrusted'):
        establish_channel(AUTH['issuer_key'],b'not-a-certificate',AUTH['root_cert'].read_bytes())
