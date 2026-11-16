from __future__ import annotations
import argparse, socket, ssl
from pathlib import Path

def request(context,port):
    with socket.create_connection(('127.0.0.1',port),timeout=5) as raw:
        with context.wrap_socket(raw,server_hostname='localhost') as conn:
            conn.sendall(b'GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            data=b''
            while True:
                block=conn.recv(8192)
                if not block: break
                data+=block
            return conn.version(),conn.cipher(),data
def main():
    parser=argparse.ArgumentParser(description='Verify actual trusted and untrusted EduSecure TLS handshakes');parser.add_argument('--port',type=int,default=8000);args=parser.parse_args()
    trusted=ssl.create_default_context(cafile=str(Path('certificates/root-ca.pem')));trusted.minimum_version=ssl.TLSVersion.TLSv1_2;trusted.maximum_version=ssl.TLSVersion.TLSv1_2;trusted.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
    version,cipher,response=request(trusted,args.port)
    assert version=='TLSv1.2',version;assert cipher[0]=='ECDHE-ECDSA-AES256-GCM-SHA384',cipher[0]
    headers=response.split(b'\r\n\r\n',1)[0].lower();assert b'strict-transport-security:' in headers and b'content-security-policy:' in headers
    print(f'Trusted CA: ACCEPTED | TLS {version} | {cipher[0]}');print('HSTS: PRESENT | CSP: PRESENT')
    tls13=ssl.create_default_context(cafile=str(Path('certificates/root-ca.pem')));tls13.minimum_version=ssl.TLSVersion.TLSv1_3;tls13.maximum_version=ssl.TLSVersion.TLSv1_3
    version13,cipher13,_=request(tls13,args.port);assert version13=='TLSv1.3',version13
    print(f'TLS 1.3: ACCEPTED | {cipher13[0]}')
    untrusted=ssl.create_default_context();untrusted.minimum_version=ssl.TLSVersion.TLSv1_2;untrusted.maximum_version=ssl.TLSVersion.TLSv1_2;untrusted.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
    try: request(untrusted,args.port)
    except ssl.SSLCertVerificationError as exc: print(f'Untrusted CA: REJECTED | {exc.verify_message}')
    else: raise AssertionError('Untrusted certificate was accepted')
if __name__=='__main__': main()
