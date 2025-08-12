// Versão simplificada do Router para usar no Cloudflare Worker
class Router {
  constructor() {
    this.routes = [];
  }
  get(path, handler) { this.routes.push({ method: 'GET', path, handler }); return this; }
  post(path, handler) { this.routes.push({ method: 'POST', path, handler }); return this; }
  put(path, handler) { this.routes.push({ method: 'PUT', path, handler }); return this; }
  delete(path, handler) { this.routes.push({ method: 'DELETE', path, handler }); return this; }
  all(path, handler) { this.routes.push({ method: 'ALL', path, handler }); return this; }
  
  async handle(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    for (const route of this.routes) {
      if ((route.method === method || route.method === 'ALL') && this.matchPath(route.path, url.pathname)) {
        request.params = this.extractParams(route.path, url.pathname);
        // ctx params for compatibility
        ctx = ctx || {};
        ctx.params = request.params;
        return route.handler(request, env, ctx);
      }
    }
    return null;
  }

  matchPath(routePath, requestPath) {
    if (routePath === requestPath) return true;
    if (!routePath.includes(':')) return false;
    const routeParts = routePath.split('/');
    const reqParts = requestPath.split('/');
    if (routeParts.length !== reqParts.length) return false;
    for (let i = 0; i < routeParts.length; i++) {
      if (routeParts[i].startsWith(':')) continue;
      if (routeParts[i] !== reqParts[i]) return false;
    }
    return true;
  }

  extractParams(routePath, requestPath) {
    const params = {};
    const routeParts = routePath.split('/');
    const reqParts = requestPath.split('/');
    routeParts.forEach((part, i) => {
      if (part.startsWith(':')) {
        params[part.slice(1)] = reqParts[i];
      }
    });
    return params;
  }
}

const router = new Router();

function base64UrlDecode(str) {
  // Ajuste para base64Url decode
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

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
        // Convert base64url string para Uint8Array
        const signatureStr = base64UrlDecode(encodedSignature);
        const signatureBuffer = Uint8Array.from(signatureStr, c => c.charCodeAt(0));
        const isValid = await crypto.subtle.verify({ name: 'HMAC' }, key, signatureBuffer, textEncoder.encode(data));
        if (!isValid) throw new Error('Invalid signature');
        const payload = JSON.parse(base64UrlDecode(encodedPayload));
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
        return payload;
    } catch (err) {
        throw new Error('Invalid token');
    }
}

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

// Rotas do router seguem seu código original, só lembrando que agora o router é o acima

// ... seu código das rotas (login, users, etc) permanece igual

// Exemplo para rota login (copie e cole suas rotas no código final):

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

// E assim por diante para as demais rotas...

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
            const response = await router.handle(request, env, ctx);
            if (!response) return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
            for (const [k, v] of Object.entries(corsHeaders)) response.headers.set(k, v);
            if (!response.headers.get('Content-Type')) response.headers.set('Content-Type', 'application/json');
            return response;
        } catch (error) {
            return new Response(JSON.stringify({ message: 'Internal Server Error' }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
    }
};
