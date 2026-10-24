# Threat Model & Security Posture (TrustVault)

## 1. Document Enumeration & ID Probing
- **Threat**: An attacker iterates over UUIDs or document endpoints attempting to discover valid file records by watching for `403 Forbidden` vs `404 Not Found`.
- **Mitigation**: TrustVault implements **404 Concealment**. Any request made by a user lacking active read permissions returns a uniform `404 Not Found` response. Unauthorized access attempts are recorded to the tamper-evident ledger with action `ACCESS_DENIED`.

## 2. Token Stasis & Delayed Revocation
- **Threat**: Permissions encoded inside long-lived JWTs allow users to retain file access after their permission was revoked in the backend.
- **Mitigation**: JWTs are strictly used for user authentication (identity). All document authorization checks query `documents` and `document_grants` in real time. Revoking an entry in `document_grants` halts access immediately on the next HTTP request.

## 3. Malicious Payload Disguise (Extension Spoofing)
- **Threat**: An attacker uploads an executable binary disguised with a `.pdf` extension.
- **Mitigation**: Multi-part upload inspects the raw file buffer header magic numbers (`%PDF` `0x25 0x50 0x44 0x46`, PNG `0x89 0x50 0x4E 0x47`, JPEG `0xFF 0xD8 0xFF`). Files failing magic-byte signature checks are rejected with HTTP 400.

## 4. Audit Log Tampering
- **Threat**: A privileged actor directly modifies or deletes rows in the database to erase tracks of an exfiltration attempt.
- **Mitigation**: Each log row calculates its hash from `previous_hash || actor_id || action || target_document_id || status || timestamp`. The `/api/audit/verify` endpoint walks the entire chain sequentially; any altered row breaks hash continuity and flags the corrupted record.