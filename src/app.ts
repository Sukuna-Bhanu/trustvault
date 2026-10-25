import path from 'path';
import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './modules/auth/auth.controller';
import documentRoutes from './modules/documents/documents.controller';
import permissionRoutes from './modules/permissions/permissions.controller';
import { pool } from './config/db';
import { verifyAuditLedger } from './modules/audit/audit.service';
import { authenticateJWT } from './middleware/auth';

dotenv.config();

const app = express();
app.use(express.json());

// Serve static assets from public/ directory
const publicDir = path.join(process.cwd(), 'public');
app.use(express.static(publicDir));

// Dedicated Login Route
app.get('/login', (req, res) => {
    res.sendFile(path.join(publicDir, 'login.html'));
});

// API Status & Health
app.get('/api/status', (req, res) => {
    res.json({
        name: 'TrustVault API',
        status: 'ONLINE',
        version: '1.0.0',
        documentation: 'https://github.com/Sukuna-Bhanu/trustvault',
        endpoints: {
            auth: '/api/auth/login',
            documents: '/api/documents',
            permissions: '/api/permissions',
            auditLedgerVerify: '/api/audit/verify',
        },
    });
});

// Mount Routes
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/permissions', permissionRoutes);

// Admin Ledger Cryptographic Verification Endpoint
app.get('/api/audit/verify', authenticateJWT, async (req, res): Promise<void> => {
    if (req.user?.role !== 'ADMIN') {
        res.status(404).json({ error: 'Document not found' });
        return;
    }

    const client = await pool.connect();
    try {
        const verification = await verifyAuditLedger(client);
        res.json({
            status: verification.valid ? 'INTACT' : 'TAMPERED',
            details: verification,
            chain: verification.chain,
        });
    } catch (err) {
        res.status(500).json({ error: 'Verification failed' });
    } finally {
        client.release();
    }
});

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => {
        console.log(`TrustVault server running on port ${PORT}`);
    });
}

export default app;