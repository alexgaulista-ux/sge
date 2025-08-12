import { Router } from 'https://cdn.jsdelivr.net/npm/itty-router@2.7.5/dist/esm/index.min.js';


async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateUuid() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    return 'id-' + Math.floor(Math.random() * 1e9).toString(36);
}

async function signJwt(payload, secret, expiresInSeconds) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const encodedPayload = btoa(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds }))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    const textEncoder = new TextEncoder();
    const keyData = textEncoder.encode(secret);
    const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    const data = `${encodedHeader}.${encodedPayload}`;
    const signature = await crypto.subtle.sign({ name: 'HMAC' }, key, textEncoder.encode(data));
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

async function verifyJwt(token, secret) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) throw new Error('Invalid token format');
        const [encodedHeader, encodedPayload, encodedSignature] = parts;
        const textEncoder = new TextEncoder();
        const keyData = textEncoder.encode(secret);
        const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const data = `${encodedHeader}.${encodedPayload}`;
        const signatureBuffer = Uint8Array.from(atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        const isValid = await crypto.subtle.verify({ name: 'HMAC' }, key, signatureBuffer, textEncoder.encode(data));
        if (!isValid) throw new Error('Invalid signature');
        const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
        return payload;
    } catch (err) {
        throw new Error('Invalid token');
    }
}

const router = Router();

async function authenticate(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ message: 'Unauthorized: Missing or invalid token' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = await verifyJwt(token, env.JWT_SECRET);
        request.user = decoded;
        return null;
    } catch (err) {
        return new Response(JSON.stringify({ message: 'Unauthorized: invalid token' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
}

function authorize(requiredPermission) {
    return async (request, env) => {
        if (!request.user) return new Response(JSON.stringify({ message: 'Forbidden: User not authenticated' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        const userPermissions = Array.isArray(request.user.permissions) ? request.user.permissions : JSON.parse(request.user.permissions || '[]');
        if (!userPermissions.includes(requiredPermission) && !userPermissions.includes('admin')) {
            return new Response(JSON.stringify({ message: 'Forbidden: Insufficient permissions' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }
        return null;
    };
}

function handleDbError(error, message = 'Database error') {
    return new Response(JSON.stringify({ message: `${message}: ${error.message || error}` }), { status: 500, headers: { 'Content-Type': 'application/json' } });
}

// --- Core routes (login + CRUD) --
router.post('/api/login', async (request, env) => {
    try {
        const { email, password } = await request.json();
        if (!email || !password) return new Response(JSON.stringify({ message: 'Email and password are required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

        const { results } = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).all();
        const user = results[0];
        const hashedPasswordInput = await sha256(password);
        if (!user || hashedPasswordInput !== user.password_hash) {
            return new Response(JSON.stringify({ message: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }
        const token = await signJwt({ id: user.id, email: user.email, permissions: user.permissions }, env.JWT_SECRET, 3600);
        const userResponse = { id: user.id, email: user.email, permissions: Array.isArray(user.permissions) ? user.permissions : JSON.parse(user.permissions || '[]') };
        return new Response(JSON.stringify({ token, user: userResponse }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return handleDbError(error, 'Login failed');
    }
});

// Optional DB init endpoint (protected by env var + admin auth)
router.post('/api/init-db', async (request, env) => {
    try {
        if (String(env.ALLOW_DB_INIT).toLowerCase() !== 'true') {
            return new Response(JSON.stringify({ message: 'Init disabled' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }
        // Authenticate admin
        const authResp = await authenticate(request, env);
        if (authResp) return authResp;
        const perms = Array.isArray(request.user.permissions) ? request.user.permissions : JSON.parse(request.user.permissions || '[]');
        if (!perms.includes('admin')) return new Response(JSON.stringify({ message: 'Forbidden: admin only' }), { status: 403, headers: { 'Content-Type': 'application/json' } });

        // Read schema from request body or fallback to embedded SQL in body (should be sent by client)
        const body = await request.json().catch(() => ({}));
        const sql = body.sql || env.INIT_SQL || '';
        if (!sql) return new Response(JSON.stringify({ message: 'No SQL provided' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

        // Split statements and execute sequentially
        const statements = sql.split(/;\s*(?=\n|$)/g).map(s => s.trim()).filter(Boolean);
        for (const st of statements) {
            await env.DB.prepare(st).run();
        }
        return new Response(JSON.stringify({ message: 'DB initialized' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return handleDbError(error, 'DB init failed');
    }
});

// Other CRUD routes (users + collections) - omitted for brevity but should be same as before.
// For the bundle, we'll include users CRUD minimal endpoints for admin management.

router.post('/api/users', async (request, env) => {
    const authResp = await authenticate(request, env);
    if (authResp) return authResp;
    const authzResp = await authorize('users')(request, env);
    if (authzResp) return authzResp;
    try {
        const { email, password, permissions } = await request.json();
        if (!email || !password) return new Response(JSON.stringify({ message: 'Email and password are required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        const hashedPassword = await sha256(password);
        const userId = generateUuid();
        const permissionsJson = JSON.stringify(permissions || []);
        await env.DB.prepare('INSERT INTO users (id, email, password_hash, permissions) VALUES (?, ?, ?, ?)').bind(userId, email, hashedPassword, permissionsJson).run();
        return new Response(JSON.stringify({ id: userId, email, permissions: permissions || [] }), { status: 201, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        if (error.message && error.message.includes('UNIQUE constraint failed')) {
            return new Response(JSON.stringify({ message: 'User with this email already exists' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
        }
        return handleDbError(error, 'Failed to create user');
    }
});

router.get('/api/users', async (request, env) => {
    const authResp = await authenticate(request, env);
    if (authResp) return authResp;
    const authzResp = await authorize('users')(request, env);
    if (authzResp) return authzResp;
    try {
        const { results } = await env.DB.prepare('SELECT id, email, permissions FROM users').all();
        const users = results.map(user => ({ ...user, permissions: Array.isArray(user.permissions) ? user.permissions : JSON.parse(user.permissions || '[]') }));
        return new Response(JSON.stringify(users), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return handleDbError(error, 'Failed to fetch users');
    }
});

router.get('/api/users/:id', async (request, env) => {
    const authResp = await authenticate(request, env);
    if (authResp) return authResp;
    const { id } = request.params;
    try {
        const requesterPerms = Array.isArray(request.user.permissions) ? request.user.permissions : JSON.parse(request.user.permissions || '[]');
        if (request.user.id !== id && !requesterPerms.includes('users')) return new Response(JSON.stringify({ message: 'Forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        const { results } = await env.DB.prepare('SELECT id, email, permissions FROM users WHERE id = ?').bind(id).all();
        const user = results[0];
        if (!user) return new Response(JSON.stringify({ message: 'User not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        return new Response(JSON.stringify({ ...user, permissions: Array.isArray(user.permissions) ? user.permissions : JSON.parse(user.permissions || '[]') }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return handleDbError(error, 'Failed to fetch user');
    }
});

router.put('/api/users/:id', async (request, env) => {
    const authResp = await authenticate(request, env);
    if (authResp) return authResp;
    const authzResp = await authorize('users')(request, env);
    if (authzResp) return authzResp;
    const { id } = request.params;
    const { email, password, permissions } = await request.json();
    try {
        const isAdmin = Array.isArray(request.user.permissions) ? request.user.permissions.includes('users') : JSON.parse(request.user.permissions || '[]').includes('users');
        let updateFields = [];
        let bindValues = [];
        if (email) { updateFields.push('email = ?'); bindValues.push(email); }
        if (password) { const hashedPassword = await sha256(password); updateFields.push('password_hash = ?'); bindValues.push(hashedPassword); }
        if (permissions && isAdmin) { updateFields.push('permissions = ?'); bindValues.push(JSON.stringify(permissions)); }
        if (updateFields.length === 0) return new Response(JSON.stringify({ message: 'No fields to update' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        bindValues.push(id);
        await env.DB.prepare(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`).bind(...bindValues).run();
        return new Response(JSON.stringify({ message: 'User updated successfully' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        if (error.message && error.message.includes('UNIQUE constraint failed')) {
            return new Response(JSON.stringify({ message: 'User with this email already exists' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
        }
        return handleDbError(error, 'Failed to update user');
    }
});

router.delete('/api/users/:id', async (request, env) => {
    const authResp = await authenticate(request, env);
    if (authResp) return authResp;
    const authzResp = await authorize('users')(request, env);
    if (authzResp) return authzResp;
    const { id } = request.params;
    if (request.user.id === id) return new Response(JSON.stringify({ message: 'Cannot delete yourself' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    try {
        await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
        return new Response(null, { status: 204 });
    } catch (error) {
        return handleDbError(error, 'Failed to delete user');
    }
});

// Simple /api/me endpoint to validate token
router.get('/api/me', async (request, env) => {
    const authResp = await authenticate(request, env);
    if (authResp) return authResp;
    return new Response(JSON.stringify({ user: request.user }), { status: 200, headers: { 'Content-Type': 'application/json' } });
});

router.all('*', () => new Response('Not Found', { status: 404 }));

export default {
    async fetch(request, env, ctx) {
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400'
        };
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders });
        }
        try {
            const response = await router.handle(request, env);
            if (!response) return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
            for (const [k, v] of Object.entries(corsHeaders)) response.headers.set(k, v);
            if (!response.headers.get('Content-Type')) response.headers.set('Content-Type', 'application/json');
            return response;
        } catch (error) {
            return new Response(JSON.stringify({ message: 'Internal Server Error' }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
    }
};
