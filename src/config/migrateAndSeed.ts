import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { pool } from './db';

async function run() {
    const client = await pool.connect();
    try {
        console.log('Running schema migrations on Neon...');
        const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf-8');
        await client.query(schemaSql);

        console.log('Seeding initial required roles...');
        const users = [
            { email: 'admin@trustvault.local', pass: 'AdminPass123!', role: 'ADMIN' },
            { email: 'owner@trustvault.local', pass: 'OwnerPass123!', role: 'OWNER' },
            { email: 'viewer@trustvault.local', pass: 'ViewerPass123!', role: 'VIEWER' },
        ];

        for (const u of users) {
            const hash = await bcrypt.hash(u.pass, 10);
            await client.query(
                `INSERT INTO users (email, password_hash, role)
         VALUES ($1, $2, $3)
         ON CONFLICT (email) DO NOTHING`,
                [u.email, hash, u.role]
            );
        }
        console.log('Schema migration and user seeding complete.');
    } catch (err) {
        console.error('Migration failed:', err);
    } finally {
        client.release();
        await pool.end();
    }
}

run();