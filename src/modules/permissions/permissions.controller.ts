import { Router, Request, Response } from 'express';
import { pool } from '../../config/db';
import { authenticateJWT } from '../../middleware/auth';
import { logAuditEvent } from '../audit/audit.service';

const router = Router();

// Grant Named Access
router.post('/grant', authenticateJWT, async (req: Request, res: Response): Promise<void> => {
    const user = req.user!;
    const { documentId, targetUserId, permission } = req.body;
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

    if (!documentId || !targetUserId || !permission) {
        res.status(400).json({ error: 'documentId, targetUserId, and permission are required' });
        return;
    }

    const client = await pool.connect();
    try {
        const docRes = await client.query('SELECT owner_id FROM documents WHERE id = $1', [documentId]);
        if (docRes.rows.length === 0 || (user.role !== 'ADMIN' && docRes.rows[0].owner_id !== user.id)) {
            res.status(404).json({ error: 'Document not found' });
            return;
        }

        await client.query('BEGIN');

        await client.query(
            `INSERT INTO document_grants (document_id, user_id, permission, granted_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (document_id, user_id) DO UPDATE SET permission = EXCLUDED.permission`,
            [documentId, targetUserId, permission, user.id]
        );

        await logAuditEvent(client, {
            actorId: user.id,
            action: 'GRANT_PERM',
            targetDocumentId: documentId,
            status: 'SUCCESS',
            details: { grantedTo: targetUserId, permission },
            ipAddress: ip,
        });

        await client.query('COMMIT');
        res.json({ message: 'Permission granted successfully' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Failed to grant permission' });
    } finally {
        client.release();
    }
});

// Revoke Access (Immediate server cutoff)
router.post('/revoke', authenticateJWT, async (req: Request, res: Response): Promise<void> => {
    const user = req.user!;
    const { documentId, targetUserId } = req.body;
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

    if (!documentId || !targetUserId) {
        res.status(400).json({ error: 'documentId and targetUserId are required' });
        return;
    }

    const client = await pool.connect();
    try {
        const docRes = await client.query('SELECT owner_id FROM documents WHERE id = $1', [documentId]);
        if (docRes.rows.length === 0 || (user.role !== 'ADMIN' && docRes.rows[0].owner_id !== user.id)) {
            res.status(404).json({ error: 'Document not found' });
            return;
        }

        await client.query('BEGIN');

        await client.query(
            'DELETE FROM document_grants WHERE document_id = $1 AND user_id = $2',
            [documentId, targetUserId]
        );

        await logAuditEvent(client, {
            actorId: user.id,
            action: 'REVOKE_PERM',
            targetDocumentId: documentId,
            status: 'SUCCESS',
            details: { revokedFrom: targetUserId },
            ipAddress: ip,
        });

        await client.query('COMMIT');
        res.json({ message: 'Permission revoked successfully' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Failed to revoke permission' });
    } finally {
        client.release();
    }
});

export default router;