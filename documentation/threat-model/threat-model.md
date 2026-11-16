# Threat model and security rationale

## Scope and trust boundaries

Assets include student identity and account state, password derivation records, grades, course files, payments/orders, credentials/receipts, session tokens, wrapping/signing keys, and the Root CA. The browser and network are untrusted. The local API process, SQLite database, and filesystem form the demonstration server trust boundary. The gateway is a simulator that shares an HMAC secret with the service.

| Asset | Main threat | Control in this build | Residual risk |
|---|---|---|---|
| Password credentials | Offline guessing, online brute force | PBKDF2-SHA256, random salt, 600,000 iterations, lockout, generic errors, dummy derivation for unknown email | Weak user-chosen passwords; lockout can be abused for denial of service; no MFA |
| Sessions and actions | Theft, CSRF, role bypass | HMAC-signed expiring cookie, HttpOnly/Secure/SameSite, CSRF token, backend role checks | Single-process secret lifecycle; no centralized rotation/revocation |
| Grades and course documents | Database/file theft, unauthorized read, tampering | Per-object AES-256-GCM, RSA-3072-OAEP DEK wrapping, SHA-256 check, enrollment/owner authorization | Host compromise exposes service unwrapping key; identities are not separately field-encrypted |
| Payment orders and enrollment | Forged callback, stale callback, replay, price/currency substitution | Timestamp and raw-body HMAC, constant-time check, 5-minute window, order amount/currency check, unique event and pending-only transition | Simulator secret is local; actual gateway integration is absent |
| Credentials and receipts | Document alteration, forged issuer, untrusted CA | Canonical JSON, SHA-256, ECDSA P-256, issuer certificate and Root chain verification | No CRL/OCSP/revocation or issuance ceremony; credential state is local |
| Keys / Root CA | File theft, accidental commit, misuse | Key separation, `.gitignore`, explicit bootstrap command, app process does not load Root private key | Local filesystem protection only; no HSM, offline media or tested recovery process |

## Required attack classes

1. **Brute force:** attackers guess account passwords or exploit weak choices. Per-account lockout and PBKDF2 raise cost. A production deployment needs an IP/device-aware rate limiter, MFA, breached-password checks, recovery safeguards, and monitoring. Lockout alone enables targeted account denial of service.
2. **Mathematical cryptanalysis:** attackers exploit weak algorithms/parameters or future cryptanalytic advances. The app uses library AES-GCM, RSA-3072-OAEP, SHA-256, PBKDF2-HMAC-SHA256, X25519, ECDSA P-256, and HKDF. No custom primitive is implemented. RSA/ECC/X25519 are vulnerable to a sufficiently capable quantum computer; the project is not post-quantum secure.
3. **Implementation attacks:** attackers target nonce reuse, side channels, invalid parsing, authentication bypass, and race/replay conditions. The project delegates primitives to `cryptography`, uses random per-object AES keys/nonces, strict schema validation, constant-time MAC comparisons, authenticated AAD, file digest checks, webhook replay checks, and integration tests. Runtime resource exhaustion, host compromise, database locking, dependency compromise, and multi-process race behavior remain outside this local scope.
4. **Social engineering:** users may be phished, tricked into reusing passwords, or induced to install a malicious Root CA. The interface identifies the demo environment and never asks for card data. Training, MFA, trusted distribution of CA fingerprints, and out-of-band incident response remain necessary.

## Explicit limitations

Weak passwords remain guessable. Physical access to the key directory can expose signing and unwrapping keys. The Root CA private key is separated from the web process after bootstrap but remains on local disk, not offline hardware. The issuer key remains available to the web process for academic issuance. There is no MFA, certificate revocation, real payment provider, production-grade audit retention, or post-quantum algorithm. Production should move master keys to an HSM/KMS, keep a documented offline Root CA ceremony, add revocation, MFA, centralized rate limiting, provider-hosted checkout, monitoring, backups, and tested key rotation. Migration should evaluate hybrid ML-KEM (FIPS 203) and ML-DSA (FIPS 204); these are not currently implemented.
