# Instructor demonstration (about 10 minutes)

1. **0:00–1:00 — Product overview.** Open EduSecure over HTTPS. Explain the three protected data groups and label the payment gateway as simulated.
2. **1:00–2:30 — TLS trust.** Run `python scripts/verify_tls.py`. Point out the trusted Root CA success, exact TLS 1.2 cipher, TLS 1.3 support, untrusted CA rejection, HSTS, and CSP.
3. **2:30–4:00 — Accounts and authorization.** Show the student and instructor roles. Attempt an instructor-only action as student and show server-side 403. Explain PBKDF2, lockout, signed session, and CSRF.
4. **4:00–5:30 — Course and payment.** Instructor creates a priced course. Student initiates checkout. Show pending order changing to paid only after simulator HMAC, timestamp, amount, and currency checks. Never enter card information.
5. **5:30–6:30 — Forgery/replay.** Run `python scripts/attack_demo.py`; identify wrong signature, expired timestamp, amount mismatch, and duplicate event rejection.
6. **6:30–7:30 — Files and grades.** Upload a course file; demonstrate ciphertext at rest, RSA-wrapped per-file DEK, access control, and verified download. Post a grade and show the student's grade view.
7. **7:30–8:30 — Tampering.** The attack script modifies stored ciphertext and confirms AES-GCM failure with no plaintext response.
8. **8:30–9:30 — Credential and crypto lab.** Issue a credential from a roster, verify signature/chain, run the interactive cryptographic lab.
9. **9:30–10:00 — Limitations.** State local key custody, simulated payments, no MFA/revocation, and no post-quantum claim. Point to the threat model and key plan.

The instructor demo accounts are created by `python scripts/seed_demo.py`; generated passwords are printed once. Keep credentials out of the project ZIP and delete the demo database after the presentation if it contains test data.
