import os, socket, subprocess, sys, time, re, urllib.request

def test_real_https_tls12_trust_and_security_headers():
    env=os.environ.copy();process=subprocess.Popen([sys.executable,'scripts/serve_https.py','--host','127.0.0.1','--port','8443'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
    try:
        ready=False
        for _ in range(80):
            if process.poll() is not None: break
            try:
                with socket.create_connection(('127.0.0.1',8443),timeout=.2): ready=True;break
            except OSError: time.sleep(.1)
        assert ready, 'local HTTPS server did not start'
        result=subprocess.run([sys.executable,'scripts/verify_tls.py','--port','8443'],capture_output=True,text=True,timeout=20)
        assert result.returncode==0, result.stdout+'\n'+result.stderr
        assert 'Trusted CA: ACCEPTED | TLS TLSv1.2 | ECDHE-ECDSA-AES256-GCM-SHA384' in result.stdout
        assert 'Untrusted CA: REJECTED' in result.stdout
        import ssl
        trust=ssl.create_default_context(cafile='certificates/root-ca.pem')
        with urllib.request.urlopen('https://localhost:8443/',context=trust,timeout=5) as response:
            html=response.read().decode();assert response.status==200 and 'EduSecure' in html
        script=re.search(r'src="(/assets/[^\"]+\.js)"',html);assert script
        with urllib.request.urlopen('https://localhost:8443'+script.group(1),context=trust,timeout=5) as response:
            assert response.status==200 and len(response.read())>10000
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill()
