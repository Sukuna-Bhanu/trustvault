# TrustVault 🔐

A high-assurance document management and cryptographic audit system built with TypeScript, Node.js, Express, and PostgreSQL (Neon.tech).

## Core Security Standards

1. **Server-Side Authorization & 404 Concealment**:
   - Access control checks are evaluated directly against the database on every single request (no stale JWT permission claims).
   - Instant permission revocation immediately terminates access.
   - Probing unauthorized documents returns `404 Not Found` rather than `403 Forbidden` to prevent object enumeration and metadata leakage.

2. **Cryptographic Audit Ledger**:
   - Every file upload, download, permission grant, and denied access event is recorded in a SHA-256 hash-chained append-only log.
   - Built-in verification endpoint recalculates the cryptographic chain to detect any database-level tampering or record alteration.

3. **Magic-Byte MIME Validation**:
   - Files are validated using native header signature inspection (magic bytes for PDF, PNG, and JPEG) rather than relying solely on spoofable file extensions or client-supplied MIME headers.

---

## Getting Started

### Prerequisites
- Node.js (v20+)
- Neon PostgreSQL connection string

### Setup
1. Clone the repository and install dependencies:
   ```bash
   git clone [https://github.com/Sukuna-Bhanu/trustvault.git](https://github.com/Sukuna-Bhanu/trustvault.git)
   cd trustvault
   npm install