import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { pool } from '../../config/db';
import { authenticateJWT, requireDocumentAccess } from '../../middleware/auth';
import { logAuditEvent } from '../audit/audit.service';

const router = Router();
const upload = multer({ limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB limit

// Inspect raw magic numbers directly from buffer
function detectMimeType(buffer: Buffer): string | null {
    if (buffer.length >= 4) {
        // PDF: %PDF (25 50 44 46)
        if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
            return 'application/pdf';
        }
        // PNG: 89 50 4E 47
        if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
            return 'image/png';
        }
        // JPEG: FF D8 FF
        if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
            return 'image/jpeg';
        }
    }
    return null;
}

// 1. Secure Upload with Magic-Byte Inspection
router.post('/upload', authenticateJWT, upload.single('file'), async (req: Request, res: Response): Promise<void> => {
    const user = req.user!;
    const file = req.file;
    const { category } = req.body;
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

    if (!file) {
        res.status(400).json({ error: 'No file uploaded' });
        return;
    }

    const mimeType = detectMimeType(file.buffer);
    if (!mimeType) {
        res.status(400).json({ error: 'Invalid file payload: signature does not match allowed types (PDF, PNG, JPEG)' });
        return;
    }

    const storageKey = crypto.randomUUID();
    const storageDir = path.join(process.cwd(), 'storage', 'uploads');
    if (!fs.existsSync(storageDir)) {
        fs.mkdirSync(storageDir, { recursive: true });
    }
    const filePath = path.join(storageDir, `${storageKey}.bin`);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        fs.writeFileSync(filePath, file.buffer);

        const docRes = await client.query(
            `INSERT INTO documents (owner_id, original_name, storage_key, mime_type, file_size, category)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
            [user.id, file.originalname, storageKey, mimeType, file.size, category || 'general']
        );

        const createdDoc = docRes.rows[0];

        await logAuditEvent(client, {
            actorId: user.id,
            action: 'UPLOAD',
            targetDocumentId: createdDoc.id,
            status: 'SUCCESS',
            details: { originalName: file.originalname, mime: mimeType, size: file.size },
            ipAddress: ip,
        });

        await client.query('COMMIT');
        res.status(201).json({ message: 'Document uploaded securely', document: createdDoc });
    } catch (err) {
        await client.query('ROLLBACK');
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        res.status(500).json({ error: 'Upload failed' });
    } finally {
        client.release();
    }
});

// 2. Download with Real-Time Authorization & 404 Concealment
router.get('/:id/download', authenticateJWT, requireDocumentAccess('READ'), async (req: Request, res: Response): Promise<void> => {
    const user = req.user!;
    const docId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

    const client = await pool.connect();
    try {
        const docRes = await client.query('SELECT * FROM documents WHERE id = $1', [docId]);
        const doc = docRes.rows[0];
        const filePath = path.join(process.cwd(), 'storage', 'uploads', `${doc.storage_key}.bin`);

        if (!fs.existsSync(filePath)) {
            res.status(404).json({ error: 'Document not found' });
            return;
        }

        await client.query('BEGIN');
        await logAuditEvent(client, {
            actorId: user.id,
            action: 'DOWNLOAD',
            targetDocumentId: doc.id,
            status: 'SUCCESS',
            details: { filename: doc.original_name },
            ipAddress: ip,
        });
        await client.query('COMMIT');

        res.setHeader('Content-Type', doc.mime_type);
        res.setHeader('Content-Disposition', `attachment; filename="${doc.original_name}"`);
        fs.createReadStream(filePath).pipe(res);
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Download failed' });
    } finally {
        client.release();
    }
});

export default router;