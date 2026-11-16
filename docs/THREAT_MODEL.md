# EduSecure threat model

## Scope

This model describes the local academic demonstration. It is not a production risk assessment, penetration test, or deployment security guarantee. The browser and inbound requests are treated as untrusted; local generated keys, the host, and configured secrets are assumed to be controlled by the operator.

## Assets

| Asset | Security goal |
|---|---|
| User identity and session | Prevent password disclosure, session forgery, and unauthorized role use |
| Grades and course materials | Protect confidentiality and detect unauthorized modification |
| Enrollment/payment state | Accept only valid demo events for the expected order and avoid replay |
| Digital credentials | Detect changes and prove signature under the configured local issuer |
| Private keys and webhook/session secrets | Keep secrets local and out of source control |
| Audit history | Preserve useful records of relevant application activity |

## Threats and mitigations

| Threat | Implemented mitigation | Remaining limitation |
|---|---|---|
| Password guessing or account enumeration | PBKDF2-HMAC-SHA256, random salts, dummy derivation for unknown users, temporary failed-login lockout | No MFA; lockout policy is a demonstration and may need availability tuning |
| Forged or stolen session | HMAC-signed session cookie, expiry, CSRF token, HTTPS, backend role checks | No centralized session revocation or production identity provider |
| Cross-site request forgery | CSRF token required for state-changing browser requests | Deployment still requires correct origin, cookie, and proxy configuration |
| Unauthorized student/instructor actions | Server-side role, ownership, and enrollment checks | Must be reviewed whenever new routes are added |
| File or grade tampering | AES-GCM authentication; SHA-256 checks in relevant flows | Local keys and database host are not hardened against host compromise |
| File key disclosure | Per-object data key wrapped with RSA-3072-OAEP | Private wrapping key is stored locally, without HSM/KMS controls or rotation workflow |
| Forged/replayed webhook | HMAC-SHA256, timestamp tolerance, order checks, event state/replay validation | Shared-secret demo integration only; no actual provider or durable distributed replay store |
| Forged credential | ECDSA P-256 signature and local X.509 chain relationship checks | No certificate revocation or external trust registry |
| Network interception | Local HTTPS with TLS 1.2 minimum and configured ECDSA certificate | Local root is not publicly trusted; secure deployment and certificate lifecycle are not supplied |
| Source publication leaks | `.gitignore` excludes environment files, databases, keys, certificates, storage, caches, and scratch output | Maintainers must still inspect staged files and Git history before publication |

## Out of scope

Production cloud infrastructure, multi-tenant isolation, real payment processing, browser/device compromise, denial-of-service resilience, MFA, certificate revocation, HSM/KMS operations, post-quantum deployment, and organizational incident response are out of scope.

## Operator guidance

Use only synthetic demo data. Keep `.env`, `keys/`, `certificates/`, `storage/`, and local database files private. Generate distinct secrets and keys for each local environment. Do not expose the demo server to the public internet. Review staged paths and commit history before pushing.
