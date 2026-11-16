"""Run reproducible local attacks against EduSecure's test application."""
import subprocess, sys
commands=[
    [sys.executable,'-m','pytest','backend/tests/test_application.py::test_forged_webhook_signature_rejected','backend/tests/test_application.py::test_expired_webhook_rejected','backend/tests/test_application.py::test_webhook_amount_mismatch_rejected','backend/tests/test_application.py::test_verified_payment_enrolls_once','-q'],
    [sys.executable,'-m','pytest','backend/tests/test_application.py::test_course_file_encrypted_download_and_tampering_rejection','-q'],
]
for cmd in commands:
    completed=subprocess.run(cmd,check=False)
    if completed.returncode: raise SystemExit(completed.returncode)
print('Attack checks completed. Run scripts/verify_tls.py while the HTTPS server is running for Attack 1.')
