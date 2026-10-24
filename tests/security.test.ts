import request from 'supertest';
import app from '../src/app';
import { pool } from '../src/config/db';

describe('TrustVault Security Standard Verification Suite', () => {
    let adminToken: string;
    let ownerToken: string;
    let viewerToken: string;
    let viewerId: string;
    let documentId: string;

    beforeAll(async () => {
        // Log in users seeded by migrateAndSeed
        const adminRes = await request(app).post('/api/auth/login').send({
            email: 'admin@trustvault.local',
            password: 'AdminPass123!',
        });
        adminToken = adminRes.body.token;

        const ownerRes = await request(app).post('/api/auth/login').send({
            email: 'owner@trustvault.local',
            password: 'OwnerPass123!',
        });
        ownerToken = ownerRes.body.token;

        const viewerRes = await request(app).post('/api/auth/login').send({
            email: 'viewer@trustvault.local',
            password: 'ViewerPass123!',
        });
        viewerToken = viewerRes.body.token;
        viewerId = viewerRes.body.user.id;
    });

    afterAll(async () => {
        await pool.end();
    });

    // Test 1: Magic Byte Enforcement
    it('Standard 3: Should reject fake PDF files with mismatched magic numbers', async () => {
        const fakePdfBuffer = Buffer.from('MZ_FAKE_EXECUTABLE_HEADER_CONTENT');
        const res = await request(app)
            .post('/api/documents/upload')
            .set('Authorization', `Bearer ${ownerToken}`)
            .attach('file', fakePdfBuffer, 'malicious.pdf');

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/signature does not match allowed types/i);
    });

    // Test 2: Legitimate Upload
    it('Standard 3: Should accept genuine PDF files by magic byte signature (%PDF)', async () => {
        const realPdfBuffer = Buffer.from('%PDF-1.4\n%Fake Genuine Content\n%%EOF');
        const res = await request(app)
            .post('/api/documents/upload')
            .set('Authorization', `Bearer ${ownerToken}`)
            .attach('file', realPdfBuffer, 'confidential_report.pdf');

        expect(res.status).toBe(201);
        expect(res.body.document).toBeDefined();
        documentId = res.body.document.id;
    });

    // Test 3: Anti-Enumeration (404 Concealment)
    it('Standard 1: Unauthorized viewer probing document should receive 404 (not 403)', async () => {
        const res = await request(app)
            .get(`/api/documents/${documentId}/download`)
            .set('Authorization', `Bearer ${viewerToken}`);

        expect(res.status).toBe(404);
        expect(res.body.error).toBe('Document not found');
    });

    // Test 4: Dynamic Grant
    it('Standard 1: Owner grants READ access to viewer -> viewer can download', async () => {
        const grantRes = await request(app)
            .post('/api/permissions/grant')
            .set('Authorization', `Bearer ${ownerToken}`)
            .send({
                documentId,
                targetUserId: viewerId,
                permission: 'READ',
            });

        expect(grantRes.status).toBe(200);

        const downloadRes = await request(app)
            .get(`/api/documents/${documentId}/download`)
            .set('Authorization', `Bearer ${viewerToken}`);

        expect(downloadRes.status).toBe(200);
    });

    // Test 5: Real-Time Instant Revocation
    it('Standard 1: Revoking permission results in immediate 404 cutoff', async () => {
        const revokeRes = await request(app)
            .post('/api/permissions/revoke')
            .set('Authorization', `Bearer ${ownerToken}`)
            .send({
                documentId,
                targetUserId: viewerId,
            });

        expect(revokeRes.status).toBe(200);

        const downloadRes = await request(app)
            .get(`/api/documents/${documentId}/download`)
            .set('Authorization', `Bearer ${viewerToken}`);

        expect(downloadRes.status).toBe(404);
        expect(downloadRes.body.error).toBe('Document not found');
    });

    // Test 6: Audit Hash Chain Integrity
    it('Standard 2: Cryptographic ledger verification reports INTACT', async () => {
        const verifyRes = await request(app)
            .get('/api/audit/verify')
            .set('Authorization', `Bearer ${adminToken}`);

        expect(verifyRes.status).toBe(200);
        expect(verifyRes.body.status).toBe('INTACT');
        expect(verifyRes.body.details.valid).toBe(true);
    });
});