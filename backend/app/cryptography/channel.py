"""Authenticated ephemeral X25519 channel exercise; never used for app transport."""
import os
from cryptography.hazmat.primitives.asymmetric import ec
from .primitives import x25519_pair,xpub_bytes,derive_channel_keys,SecureChannel,ecdsa_sign,ecdsa_verify
from .authority import verify_certificate_chain

def establish_channel(issuer_private_key,issuer_cert_pem:bytes,root_cert_pem:bytes,client_private=None,server_private=None):
    client_private=client_private or x25519_pair(); server_private=server_private or x25519_pair()
    client_public=xpub_bytes(client_private); server_public=xpub_bytes(server_private); session_id=os.urandom(32)
    transcript=b"EduSecure-X25519-v1"+session_id+client_public+server_public
    signature=ecdsa_sign(issuer_private_key,transcript)
    if not verify_certificate_chain(issuer_cert_pem,root_cert_pem,root_cert_pem): raise ValueError("issuer certificate chain is untrusted")
    issuer_public=issuer_private_key.public_key()
    if not ecdsa_verify(issuer_public,transcript,signature): raise ValueError("server key exchange signature is invalid")
    client_shared=client_private.exchange(server_private.public_key()); server_shared=server_private.exchange(client_private.public_key())
    if client_shared!=server_shared: raise ValueError("key agreement failed")
    c2s,s2c=derive_channel_keys(client_shared,session_id)
    client=SecureChannel(send_key=c2s,receive_key=s2c);server=SecureChannel(send_key=s2c,receive_key=c2s)
    return {"client":client,"server":server,"session_id":session_id,"client_public":client_public,"server_public":server_public,"signature":signature,"shared_match":True,"directions_separate":c2s!=s2c}
