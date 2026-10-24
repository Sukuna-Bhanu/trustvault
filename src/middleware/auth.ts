import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { pool } from '../config/db';
import { logAuditEvent } from '../modules/audit/audit.service';

export interface AuthUser {
    id: string;
    email: string;
    role: 'ADMIN' | 'OWNER' | 'VIEWER';
}

declare global {
    namespace Express {
        interface Request {
            user?: AuthUser;
        }
    }
}

export const authenticateJWT = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Missing or malformed authorization token' });
        return;
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret') as AuthUser;
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Real-time server-side database permission enforcement with 404 authorization concealment
export const requireDocumentAccess = (requiredPerm: 'READ' | 'EDIT' = 'READ') => {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const client = await pool.connect();
        const docId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const user = req.user;
        const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

        if (!user) {
            res.status(401).json({ error: 'Authentication required' });
            client.release();
            return;
        }

        try {
            // 1. Fetch document existence and ownership directly from DB
            const docRes = await client.query('SELECT * FROM documents WHERE id = $1', [docId]);
            if (docRes.rows.length === 0) {
                res.status(404).json({ error: 'Document not found' });
                client.release();
                return;
            }

            const doc = docRes.rows[0];

            // 2. Admins and owners always pass
            if (user.role === 'ADMIN' || doc.owner_id === user.id) {
                client.release();
                return next();
            }

            // 3. For viewers, query document_grants table in real time (immediate revocation check)
            const grantRes = await client.query(
                'SELECT permission FROM document_grants WHERE document_id = $1 AND user_id = $2',
                [docId, user.id]
            );

            const userGrant = grantRes.rows[0];
            let hasAccess = false;

            if (userGrant) {
                if (requiredPerm === 'READ') {
                    hasAccess = true;
                } else if (requiredPerm === 'EDIT' && userGrant.permission === 'EDIT') {
                    hasAccess = true;
                }
            }

            if (!hasAccess) {
                // Log unauthorized probing attempt into tamper-evident ledger
                await client.query('BEGIN');
                await logAuditEvent(client, {
                    actorId: user.id,
                    action: 'ACCESS_DENIED',
                    targetDocumentId: docId,
                    status: 'DENIED',
                    details: { attemptedPerm: requiredPerm, reason: 'Insufficient privileges or revoked grant' },
                    ipAddress: ip,
                });
                await client.query('COMMIT');

                // 404 authorization concealment to prevent object enumeration
                res.status(404).json({ error: 'Document not found' });
                client.release();
                return;
            }

            client.release();
            next();
        } catch (error) {
            await client.query('ROLLBACK');
            client.release();
            res.status(500).json({ error: 'Authorization verification failed' });
        }
    };
};