import crypto from 'crypto';
import { PoolClient } from 'pg';

export interface AuditLogParams {
    actorId?: string | null;
    action: 'UPLOAD' | 'DOWNLOAD' | 'VIEW_METADATA' | 'GRANT_PERM' | 'REVOKE_PERM' | 'ACCESS_DENIED';
    targetDocumentId?: string | null;
    status: 'SUCCESS' | 'DENIED';
    details?: Record<string, any>;
    ipAddress: string;
}

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export async function logAuditEvent(client: PoolClient, params: AuditLogParams): Promise<void> {
    // Lock the last record to guarantee strict sequential hash chaining
    const lastRecordRes = await client.query(
        'SELECT current_hash FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 1 FOR UPDATE'
    );

    const previousHash = lastRecordRes.rows.length > 0
        ? lastRecordRes.rows[0].current_hash
        : GENESIS_HASH;

    const timestamp = new Date().toISOString();
    const payload = `${previousHash}|${params.actorId || 'ANON'}|${params.action}|${params.targetDocumentId || 'NONE'}|${params.status}|${timestamp}`;
    const currentHash = crypto.createHash('sha256').update(payload).digest('hex');

    await client.query(
        `INSERT INTO audit_logs 
     (actor_id, action, target_document_id, status, details, ip_address, timestamp, previous_hash, current_hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
            params.actorId || null,
            params.action,
            params.targetDocumentId || null,
            params.status,
            JSON.stringify(params.details || {}),
            params.ipAddress,
            timestamp,
            previousHash,
            currentHash,
        ]
    );
}

export async function verifyAuditLedger(client: PoolClient): Promise<{ valid: boolean; brokenAtId?: string }> {
    const rows = (await client.query('SELECT * FROM audit_logs ORDER BY timestamp ASC, id ASC')).rows;
    let expectedPrevHash = GENESIS_HASH;

    for (const row of rows) {
        if (row.previous_hash !== expectedPrevHash) {
            return { valid: false, brokenAtId: row.id };
        }
        const payload = `${row.previous_hash}|${row.actor_id || 'ANON'}|${row.action}|${row.target_document_id || 'NONE'}|${row.status}|${new Date(row.timestamp).toISOString()}`;
        const recalculated = crypto.createHash('sha256').update(payload).digest('hex');

        if (recalculated !== row.current_hash) {
            return { valid: false, brokenAtId: row.id };
        }
        expectedPrevHash = row.current_hash;
    }

    return { valid: true };
}