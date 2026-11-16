# EduSecure architecture

```mermaid
flowchart LR
  B[Student / Instructor Browser] -->|HTTPS TLS 1.2+| API[FastAPI API]
  API --> Auth[Authentication / RBAC / CSRF]
  API --> Course[Courses / Enrollment / Payment]
  API --> Crypto[Cryptographic Services]
  Auth --> DB[(SQLite)]
  Course --> DB
  Crypto --> DB
  Crypto --> FS[Encrypted file storage]
  Crypto --> Issuer[Issuer ECDSA key]
  Crypto --> Wrap[RSA-3072 unwrapping key]
  TLS[Local TLS ECDSA key + certificate] -.HTTPS listener.-> API
  Root[Offline local Root CA key] -.signed certificates.-> TLS
  Root -.signed issuer certificate.-> Issuer
```

The frontend is a React/TypeScript single-page application. It uses same-origin `/api` requests in production and a Vite development proxy while working locally. API routes call cryptographic wrappers in `backend/app/cryptography`; route handlers enforce authorization and call data services. SQLAlchemy persists application records. Filesystem storage contains AES-GCM ciphertext, nonces are stored in the database, DEKs are RSA-OAEP-wrapped, and digests support post-decryption verification.

The X25519/HKDF record channel is a separate demonstration. It authenticates ephemeral key material with the issuer's ECDSA signature and verifies the issuer chain. It is not wired as an alternate web transport.
