import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from '../../config/db';

const router = Router();

router.post('/login', async (req: Request, res: Response): Promise<void> => {
    const { email, password } = req.body;
    if (!email || !password) {
        res.status(400).json({ error: 'Email and password are required' });
        return;
    }

    const client = await pool.connect();
    try {
        const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '8h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
            },
        });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    } finally {
        client.release();
    }
});

router.get('/seed-accounts', (req: Request, res: Response): void => {
    res.json({
        accounts: [
            { email: 'admin@trustvault.local', password: 'AdminPass123!', role: 'ADMIN', label: 'Admin' },
            { email: 'owner@trustvault.local', password: 'OwnerPass123!', role: 'OWNER', label: 'Owner' },
            { email: 'viewer@trustvault.local', password: 'ViewerPass123!', role: 'VIEWER', label: 'Viewer' },
        ],
    });
});

router.get('/users', async (req: Request, res: Response): Promise<void> => {
    const client = await pool.connect();
    try {
        const result = await client.query('SELECT id, email, role, created_at FROM users ORDER BY role ASC, email ASC');
        res.json({ users: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve users' });
    } finally {
        client.release();
    }
});

export default router;