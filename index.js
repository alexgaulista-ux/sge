// Imports omitidos pois estamos em ambiente Cloudflare Worker

// Função simples SHA256 (como antes)
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Geração simples de UUID-like
function generateUuid() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return 'id-' + Math.floor(Math.random() * 1e9).toString(36);
}

// Funções JWT (sign e verify) simplificadas - reutilize as que você já tem do código anterior.

// ... (Use as funções signJwt e verifyJwt que te passei antes)

async function authenticate(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = await verifyJwt(token, env.JWT_SECRET);
    request.user = decoded;
    return null;
  } catch {
    return new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization",
    };
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (url.pathname === '/api/register' && request.method === 'POST') {
      // Criar usuário simples
      try {
        const { email, password } = await request.json();
        if (!email || !password) return new Response(JSON.stringify({ message: 'Email and password required' }), { status: 400, headers: corsHeaders });

        const hashedPassword = await sha256(password);
        const userId = generateUuid();
        const permissions = JSON.stringify(['user']); // padrão 'user'

        // Tentar inserir
        await env.DB.prepare('INSERT INTO users (id, email, password_hash, permissions) VALUES (?, ?, ?, ?)')
          .bind(userId, email, hashedPassword, permissions)
          .run();

        return new Response(JSON.stringify({ id: userId, email, permissions: ['user'] }), { status: 201, headers: corsHeaders });
      } catch (e) {
        if (e.message.includes('UNIQUE')) {
          return new Response(JSON.stringify({ message: 'Email already registered' }), { status: 409, headers: corsHeaders });
        }
        return new Response(JSON.stringify({ message: 'Error creating user', error: e.message }), { status: 500, headers: corsHeaders });
      }
    }

    if (url.pathname === '/api/login' && request.method === 'POST') {
      // Login simples
      try {
        const { email, password } = await request.json();
        if (!email || !password) return new Response(JSON.stringify({ message: 'Email and password required' }), { status: 400, headers: corsHeaders });

        const { results } = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).all();
        const user = results[0];
        if (!user) return new Response(JSON.stringify({ message: 'Invalid credentials' }), { status: 401, headers: corsHeaders });

        const hashedInput = await sha256(password);
        if (hashedInput !== user.password_hash) return new Response(JSON.stringify({ message: 'Invalid credentials' }), { status: 401, headers: corsHeaders });

        // Gerar token JWT por 1 hora
        const token = await signJwt({ id: user.id, email: user.email, permissions: JSON.parse(user.permissions) }, env.JWT_SECRET, 3600);

        return new Response(JSON.stringify({ token }), { status: 200, headers: corsHeaders });
      } catch (e) {
        return new Response(JSON.stringify({ message: 'Login error', error: e.message }), { status: 500, headers: corsHeaders });
      }
    }

    // Rota protegida de teste
    if (url.pathname === '/api/profile' && request.method === 'GET') {
      const authResp = await authenticate(request, env);
      if (authResp) return authResp;

      return new Response(JSON.stringify({ user: request.user }), { status: 200, headers: corsHeaders });
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders });
  }
};
