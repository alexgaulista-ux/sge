import { Router } from 'https://cdn.jsdelivr.net/npm/itty-router@2.7.5/dist/esm/index.min.js';


// --- Funções de Hash e JWT (Implementação simplificada para Workers sem Node.js) ---
// ATENÇÃO: Esta implementação de hash de senha (SHA-256) e JWT é simplificada
// para evitar dependências complexas que exigem Node.js/bundler.
// PARA PRODUÇÃO, VOCÊ DEVE USAR ALGORITMOS DE HASH DE SENHA MAIS FORTES (ex: bcrypt)
// E UMA BIBLIOTECA JWT COMPLETA SE POSSÍVEL.

// Função de hash SHA-256 (para senhas - APENAS PARA DEMONSTRAÇÃO)
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hexHash;
}

// Função para gerar UUID v4
function generateUuid() {
    return crypto.randomUUID();
}

// Funções JWT simplificadas usando Web Crypto API
async function signJwt(payload, secret, expiresInSeconds) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const encodedPayload = btoa(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds }))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    const textEncoder = new TextEncoder();
    const keyData = textEncoder.encode(secret);
    const key = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        textEncoder.encode(`${encodedHeader}.${encodedPayload}`)
    );

    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

async function verifyJwt(token, secret) {
    try {
        const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
        const textEncoder = new TextEncoder();

        const keyData = textEncoder.encode(secret);
        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );

        const signatureBuffer = Uint8Array.from(atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

        const isValid = await crypto.subtle.verify(
            'HMAC',
            key,
            signatureBuffer,
            textEncoder.encode(`${encodedHeader}.${encodedPayload}`)
        );

        if (!isValid) {
            throw new Error('Invalid signature');
        }

        const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
            throw new Error('Token expired');
        }

        return payload;
    } catch (error) {
        console.error("JWT Verification Error:", error);
        throw new Error('Invalid token');
    }
}

// --- Fim das Funções de Hash e JWT ---


// Defina o roteador
const router = Router();

// Middleware de Autenticação JWT
async function authenticate(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response('Unauthorized: Missing or invalid token', { status: 401 });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = await verifyJwt(token, env.JWT_SECRET);
        request.user = decoded; // Anexa o payload do usuário à requisição
        return null; // Continua para a próxima rota
    } catch (error) {
        return new Response(`Unauthorized: ${error.message}`, { status: 401 });
    }
}

// Middleware de Autorização (Permissões)
function authorize(requiredPermission) {
    return async (request, env) => {
        if (!request.user) {
            return new Response('Forbidden: User not authenticated', { status: 403 });
        }
        const userPermissions = JSON.parse(request.user.permissions || '[]');
        if (!userPermissions.includes(requiredPermission) && !userPermissions.includes('admin')) {
            return new Response('Forbidden: Insufficient permissions', { status: 403 });
        }
        return null; // Continua para a próxima rota
    };
}

// Helper para lidar com erros de banco de dados
function handleDbError(error, message = 'Database error') {
    console.error(message, error);
    return new Response(JSON.stringify({ message: `${message}: ${error.message}` }), { status: 500, headers: { 'Content-Type': 'application/json' } });
}

// --- Rotas de Autenticação ---

// Rota de Login
router.post('/api/login', async (request, env) => {
    const { email, password } = await request.json();

    if (!email || !password) {
        return new Response(JSON.stringify({ message: 'Email and password are required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    try {
        const { results } = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).all();
        const user = results[0];

        // Compara a senha fornecida com o hash SHA-256 armazenado
        const hashedPasswordInput = await sha256(password);
        if (!user || hashedPasswordInput !== user.password_hash) {
            return new Response(JSON.stringify({ message: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }

        // Crie um token JWT
        const token = await signJwt(
            { id: user.id, email: user.email, permissions: user.permissions },
            env.JWT_SECRET,
            3600 // Token expira em 1 hora (3600 segundos)
        );

        // Retorne o token e informações básicas do usuário (sem o hash da senha)
        const userResponse = {
            id: user.id,
            email: user.email,
            permissions: JSON.parse(user.permissions)
        };

        return new Response(JSON.stringify({ token, user: userResponse }), { status: 200, headers: { 'Content-Type': 'application/json' } });

    } catch (error) {
        return handleDbError(error, 'Login failed');
    }
});

// --- Rotas de Usuários (requer autenticação e permissão 'users' ou 'admin') ---

// Criar Usuário (apenas admin)
router.post('/api/users', authenticate, authorize('users'), async (request, env) => {
    const { email, password, permissions } = await request.json();

    if (!email || !password) {
        return new Response(JSON.stringify({ message: 'Email and password are required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    try {
        const hashedPassword = await sha256(password); // Usando SHA-256
        const userId = generateUuid();
        const permissionsJson = JSON.stringify(permissions || []);

        await env.DB.prepare('INSERT INTO users (id, email, password_hash, permissions) VALUES (?, ?, ?, ?)')
            .bind(userId, email, hashedPassword, permissionsJson)
            .run();

        return new Response(JSON.stringify({ id: userId, email, permissions: permissions || [] }), { status: 201, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed: users.email')) {
            return new Response(JSON.stringify({ message: 'User with this email already exists' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
        }
        return handleDbError(error, 'Failed to create user');
    }
});

// Listar Usuários (apenas admin)
router.get('/api/users', authenticate, authorize('users'), async (request, env) => {
    try {
        const { results } = await env.DB.prepare('SELECT id, email, permissions FROM users').all();
        const users = results.map(user => ({
            ...user,
            permissions: JSON.parse(user.permissions)
        }));
        return new Response(JSON.stringify(users), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return handleDbError(error, 'Failed to fetch users');
    }
});

// Obter Usuário por ID (apenas admin ou o próprio usuário)
router.get('/api/users/:id', authenticate, authorize('users'), async (request, env) => {
    const { id } = request.params;

    // Permite que o próprio usuário acesse seus dados, mesmo sem permissão 'users'
    if (request.user.id !== id && !JSON.parse(request.user.permissions).includes('users')) {
        return new Response('Forbidden: You can only view your own user data', { status: 403 });
    }

    try {
        const { results } = await env.DB.prepare('SELECT id, email, permissions FROM users WHERE id = ?').bind(id).all();
        const user = results[0];

        if (!user) {
            return new Response(JSON.stringify({ message: 'User not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }

        return new Response(JSON.stringify({ ...user, permissions: JSON.parse(user.permissions) }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return handleDbError(error, 'Failed to fetch user');
    }
});

// Atualizar Usuário (apenas admin ou o próprio usuário)
router.put('/api/users/:id', authenticate, authorize('users'), async (request, env) => {
    const { id } = request.params;
    const { email, password, permissions } = await request.json();

    // Permite que o próprio usuário atualize seus dados (exceto permissões, se não for admin)
    const isAdmin = JSON.parse(request.user.permissions).includes('users');
    if (request.user.id !== id && !isAdmin) {
        return new Response('Forbidden: You can only update your own user data', { status: 403 });
    }

    try {
        let updateFields = [];
        let bindValues = [];

        if (email) {
            updateFields.push('email = ?');
            bindValues.push(email);
        }
        if (password) {
            const hashedPassword = await sha256(password); // Usando SHA-256
            updateFields.push('password_hash = ?');
            bindValues.push(hashedPassword);
        }
        if (permissions && isAdmin) { // Apenas admin pode alterar permissões
            updateFields.push('permissions = ?');
            bindValues.push(JSON.stringify(permissions));
        } else if (permissions && !isAdmin) {
            // Se um usuário comum tentar alterar permissões, ignore ou retorne erro
            console.warn(`User ${request.user.id} attempted to change permissions for ${id} without admin rights.`);
        }

        if (updateFields.length === 0) {
            return new Response(JSON.stringify({ message: 'No fields to update' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        bindValues.push(id); // Adiciona o ID para a cláusula WHERE

        const stmt = env.DB.prepare(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`);
        const { success } = await stmt.bind(...bindValues).run();

        if (!success) {
            return new Response(JSON.stringify({ message: 'User not found or could not be updated' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }

        // Se o usuário logado atualizou a si mesmo, atualize o token e o cache
        if (request.user.id === id) {
            const updatedUser = { ...request.user, email: email || request.user.email };
            if (isAdmin && permissions) {
                updatedUser.permissions = permissions;
            }
            const newToken = await signJwt(updatedUser, env.JWT_SECRET, 3600);
            return new Response(JSON.stringify({ message: 'User updated successfully', token: newToken, user: updatedUser }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }

        return new Response(JSON.stringify({ message: 'User updated successfully' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed: users.email')) {
            return new Response(JSON.stringify({ message: 'User with this email already exists' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
        }
        return handleDbError(error, 'Failed to update user');
    }
});

// Deletar Usuário (apenas admin)
router.delete('/api/users/:id', authenticate, authorize('users'), async (request, env) => {
    const { id } = request.params;

    if (request.user.id === id) {
        return new Response(JSON.stringify({ message: 'Cannot delete yourself' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }

    try {
        const { success } = await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();

        if (!success) {
            return new Response(JSON.stringify({ message: 'User not found or could not be deleted' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }

        return new Response(null, { status: 204 }); // No Content
    } catch (error) {
        return handleDbError(error, 'Failed to delete user');
    }
});


// --- Rotas CRUD Genéricas para Módulos ---
// Adapte as permissões conforme necessário para cada módulo

const collections = [
    'suppliers', 'contracts', 'expenses', 'services', 'tasks', 'inventory', 'invoices'
];

collections.forEach(collection => {
    // GET all items
    router.get(`/api/${collection}`, authenticate, authorize(collection), async (request, env) => {
        try {
            const { results } = await env.DB.prepare(`SELECT * FROM ${collection}`).all();
            return new Response(JSON.stringify(results), { status: 200, headers: { 'Content-Type': 'application/json' } });
        } catch (error) {
            return handleDbError(error, `Failed to fetch ${collection}`);
        }
    });

    // GET item by ID
    router.get(`/api/${collection}/:id`, authenticate, authorize(collection), async (request, env) => {
        const { id } = request.params;
        try {
            const { results } = await env.DB.prepare(`SELECT * FROM ${collection} WHERE id = ?`).bind(id).all();
            const item = results[0];
            if (!item) {
                return new Response(JSON.stringify({ message: `${collection} item not found` }), { status: 404, headers: { 'Content-Type': 'application/json' } });
            }
            return new Response(JSON.stringify(item), { status: 200, headers: { 'Content-Type': 'application/json' } });
        } catch (error) {
            return handleDbError(error, `Failed to fetch ${collection} item`);
        }
    });

    // POST new item
    router.post(`/api/${collection}`, authenticate, authorize(collection), async (request, env) => {
        const data = await request.json();
        const itemId = generateUuid();
        const columns = ['id'];
        const placeholders = ['?'];
        const values = [itemId];

        for (const key in data) {
            if (data.hasOwnProperty(key)) {
                columns.push(key);
                placeholders.push('?');
                values.push(data[key]);
            }
        }

        try {
            const stmt = env.DB.prepare(`INSERT INTO ${collection} (${columns.join(', ')}) VALUES (${placeholders.join(', ')})`);
            await stmt.bind(...values).run();
            return new Response(JSON.stringify({ id: itemId, ...data }), { status: 201, headers: { 'Content-Type': 'application/json' } });
        } catch (error) {
            return handleDbError(error, `Failed to create ${collection} item`);
        }
    });

    // PUT update item
    router.put(`/api/${collection}/:id`, authenticate, authorize(collection), async (request, env) => {
        const { id } = request.params;
        const data = await request.json();
        const updateFields = [];
        const bindValues = [];

        for (const key in data) {
            if (data.hasOwnProperty(key)) {
                updateFields.push(`${key} = ?`);
                bindValues.push(data[key]);
            }
        }

        if (updateFields.length === 0) {
            return new Response(JSON.stringify({ message: 'No fields to update' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        bindValues.push(id); // Add ID for WHERE clause

        try {
            const stmt = env.DB.prepare(`UPDATE ${collection} SET ${updateFields.join(', ')} WHERE id = ?`);
            const { success } = await stmt.bind(...bindValues).run();

            if (!success) {
                return new Response(JSON.stringify({ message: `${collection} item not found or could not be updated` }), { status: 404, headers: { 'Content-Type': 'application/json' } });
            }
            return new Response(JSON.stringify({ id, ...data }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        } catch (error) {
            return handleDbError(error, `Failed to update ${collection} item`);
        }
    });

    // DELETE item
    router.delete(`/api/${collection}/:id`, authenticate, authorize(collection), async (request, env) => {
        const { id } = request.params;
        try {
            const { success } = await env.DB.prepare(`DELETE FROM ${collection} WHERE id = ?`).bind(id).run();
            if (!success) {
                return new Response(JSON.stringify({ message: `${collection} item not found or could not be deleted` }), { status: 404, headers: { 'Content-Type': 'application/json' } });
            }
            return new Response(null, { status: 204 }); // No Content
        } catch (error) {
            return handleDbError(error, `Failed to delete ${collection} item`);
        }
    });
});


// Rota de fallback para 404
router.all('*', () => new Response('Not Found', { status: 404 }));

// Exporta o manipulador de requisições
export default {
    async fetch(request, env, ctx) {
        // Adiciona CORS Headers para permitir requisições do seu frontend
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*', // Altere para o domínio do seu frontend em produção (ex: 'https://your-frontend-domain.com')
            'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Max-Age': '86400',
        };

        // Lida com requisições OPTIONS (preflight)
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    ...corsHeaders,
                    'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '',
                },
            });
        }

        // Executa o roteador
        const response = await router.handle(request, env, ctx);

        // Adiciona CORS Headers à resposta
        for (const key in corsHeaders) {
            response.headers.set(key, corsHeaders[key]);
        }

        return response;
    },
};
