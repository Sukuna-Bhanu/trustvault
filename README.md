# TrustVault 🔐

A high-assurance document management and cryptographic audit system built with **TypeScript**, **Node.js**, **Express**, and **PostgreSQL (Neon.tech)**.

TrustVault enforces zero-trust architecture, real-time database-driven authorization, anti-enumeration (404 concealment), buffer-level magic-byte validation, and an append-only SHA-256 hash-chained immutable audit ledger.

---

## 🛡️ Core Security Architecture & Standards

### 1. Server-Side Authorization & Anti-Enumeration (404 Concealment)
- **Zero Token Stasis**: Permissions are never baked into long-lived JWT claims. Identity is verified via JWT, while all document access rules are evaluated against the PostgreSQL database in real time.
- **Immediate Revocation Cutoff**: When an owner revokes a permission, the target user's next request is immediately blocked on the server with zero propagation delay.
- **Uniform 404 Concealment**: To defeat ID probing and object enumeration attacks, unauthorized requests return `404 Not Found` (identical to non-existent documents) rather than `403 Forbidden`. Unauthorized probing attempts are automatically logged in the audit ledger under `ACCESS_DENIED`.

### 2. Cryptographic Audit Ledger
- **SHA-256 Hash Chaining**: Every read, write, upload, download, grant, revocation, and denied attempt is recorded sequentially in an append-only audit ledger.
- **Cryptographic Chaining Formula**:
  $$\text{hash}_n = \text{SHA-256}(\text{previous\_hash}_{n-1} \parallel \text{actor\_id} \parallel \text{action} \parallel \text{target\_document\_id} \parallel \text{status} \parallel \text{timestamp})$$
- **Genesis Block**: Initiates with a fixed 64-character zero-hash (`0000000000000000000000000000000000000000000000000000000000000000`).
- **Cryptographic Verification (`/api/audit/verify`)**: Sequentially recalculates all hashes from genesis to head block. Returns `INTACT` if all hashes match, or `TAMPERED` with the exact block ID if any row or hash was altered.
- **Database-Level Immutability**: Protected by PostgreSQL rules (`no_update_audit` and `no_delete_audit`) that block `UPDATE` and `DELETE` operations.

### 3. Magic-Byte Header Validation
- **Deep Buffer Inspection**: Rejects spoofed extensions by analyzing raw binary header magic numbers:
  - **PDF**: `%PDF` (`0x25 0x50 0x44 0x46`)
  - **PNG**: `\x89PNG` (`0x89 0x50 0x4E 0x47`)
  - **JPEG**: `\xFF\xD8\xFF` (`0xFF 0xD8 0xFF`)
- **Malicious Payload Rejection**: Executable binaries (e.g. `MZ` PE headers) disguised with a `.pdf` extension are rejected with HTTP 400.

---

## 🖥️ Web UI Dashboard (`/public`)

TrustVault includes a responsive, dark slate single-page interface served directly from `/public`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🛡️ TrustVault  •  Zero-Trust Cryptographic Document Vault   [Online • SHA] │
├──────────────────────────────────────┬──────────────────────────────────────┤
│  Panel 1: Identity & Session Matrix  │  Panel 2: Document Vault             │
│  • Fast Switcher (Admin/Owner/Viewer)│  • Drag & Drop File Upload           │
│  • Active JWT Token & User UUID      │  • Magic-Byte Buffer Feedback        │
│  • Manual Credential Authentication  │  • Test Genuine vs Spoofed Demos     │
│                                      │  • Authorized Documents Table        │
├──────────────────────────────────────┼──────────────────────────────────────┤
│  Panel 3: Permission Manager         │  Panel 4: Cryptographic Audit Ledger │
│  • Real-Time Dynamic Delegation      │  • "Verify Ledger Integrity" Button  │
│  • Document ID & Target User ID      │  • Status Badge (INTACT / TAMPERED)  │
│  • GRANT (READ/EDIT) & REVOKE Access │  • Chronological Hash-Chain Explorer │
│  • Real-Time Active Grants List      │  • Previous & Current Hash Inspector │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

### Pre-Seeded Accounts for Testing:
| Persona | Email | Password | Role / Capabilities |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@trustvault.local` | `AdminPass123!` | System Administrator & Audit Ledger Verification |
| **Owner** | `owner@trustvault.local` | `OwnerPass123!` | Document Upload & Real-Time Dynamic Grant/Revoke |
| **Viewer** | `viewer@trustvault.local` | `ViewerPass123!` | Subject to 404 Concealment & Dynamic Permissions |

---

## 🚀 Quickstart & Setup

### 1. Prerequisites
- Node.js (v20 or v22+)
- PostgreSQL connection string (configured in `.env`)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/Sukuna-Bhanu/trustvault.git
cd trustvault

# Install production and dev dependencies
npm install
```

### 3. Environment Configuration
Create a `.env` file from `.env.example`:
```bash
cp .env.example .env
```
Ensure your `.env` contains:
```env
PORT=3000
DATABASE_URL=postgresql://<user>:<password>@<neon-host>/neondb?sslmode=require
JWT_SECRET=super-secret-trustvault-key-2026
```

### 4. Database Migration & Seeding
Applies `schema.sql`, configures PostgreSQL immutability rules, and seeds the initial user accounts:
```bash
npm run migrate
```

### 5. Run the Automated Security Test Suite
Executes the adversarial test suite covering all 6 security standards:
```bash
npm test
```

### 6. Start the Server & Web Dashboard
```bash
npm start
# Server listens on http://localhost:3000
```
Open [http://localhost:3000](http://localhost:3000) in your browser to interact with the full dashboard.

---

## 🧪 Adversarial Test Suite (`tests/security.test.ts`)

| # | Standard | Test Case Description | Verified Behavior |
| :---: | :---: | :--- | :--- |
| **1** | **Standard 3** | Reject fake PDF files with mismatched magic numbers | `400 Bad Request` with magic-byte mismatch error |
| **2** | **Standard 3** | Accept genuine PDF files by magic byte signature (`%PDF`) | `201 Created` with storage key and metadata |
| **3** | **Standard 1** | Unauthorized viewer probing document returns 404 | Uniform `404 Not Found` (Anti-Enumeration) |
| **4** | **Standard 1** | Owner grants READ access to viewer | Viewer can immediately download document (`200 OK`) |
| **5** | **Standard 1** | Immediate permission revocation cuts access instantly | Immediate cutoff returning `404 Not Found` |
| **6** | **Standard 2** | Audit hash chain integrity verification | Recalculates full chain and reports `INTACT` (`200 OK`) |

---

## 📡 API Reference

| Method | Endpoint | Auth | Description |
| :--- | :--- | :---: | :--- |
| `POST` | `/api/auth/login` | None | Authenticate credentials and receive Bearer JWT |
| `GET` | `/api/auth/seed-accounts`| None | Retrieve pre-seeded test personas |
| `GET` | `/api/auth/users` | Bearer | Retrieve system users list with UUIDs and roles |
| `GET` | `/api/documents` | Bearer | List documents accessible to current user in real time |
| `POST` | `/api/documents/upload` | Bearer | Upload file with raw magic-byte buffer validation |
| `GET` | `/api/documents/:id/download` | Bearer | Download document with 404 anti-enumeration concealment |
| `POST` | `/api/permissions/grant` | Bearer | Grant `READ` or `EDIT` permission to a target user |
| `POST` | `/api/permissions/revoke`| Bearer | Revoke document permission with immediate cutoff |
| `GET` | `/api/permissions/grants/:id` | Bearer | Inspect active named grants for a document |
| `GET` | `/api/audit/verify` | Bearer (Admin) | Recalculate hash chain and return `INTACT` or `TAMPERED` |
| `GET` | `/api/status` | None | Health check & API metadata |