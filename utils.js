const JWT_TOKEN_KEY = 'jwt_token';
const USER_DATA_KEY = 'current_user_data';

let audioContext;
let successBuffer, errorBuffer, deleteBuffer;

function getAudioContext() {
    if (!audioContext) {
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
    }
    return audioContext;
}

async function loadSound(url) {
    const context = getAudioContext();
    try {
        const response = await fetch(url);
        const arrayBuffer = await response.arrayBuffer();
        return await context.decodeAudioData(arrayBuffer);
    } catch (err) {
        console.warn('Failed to load sound', url, err);
        return null;
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    try {
        successBuffer = await loadSound('success_sound.mp3');
        errorBuffer = await loadSound('error_sound.mp3');
        deleteBuffer = await loadSound('delete_sound.mp3');
    } catch (error) {
        console.error('Error loading sound effects:', error);
    }
});

export function playSuccessSound() { playSound(successBuffer); }
export function playErrorSound() { playSound(errorBuffer); }
export function playDeleteSound() { playSound(deleteBuffer); }

export function playSound(buffer) {
    if (!buffer) return;
    const context = getAudioContext();
    const source = context.createBufferSource();
    source.buffer = buffer;
    source.connect(context.destination);
    source.start(0);
}

export function showAlert(container, message, type = 'success', duration = 3000) {
    container.querySelectorAll('.alert').forEach(a => a.remove());
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    container.prepend(alertDiv);
    if (type === 'success') playSuccessSound();
    else if (type === 'error') playErrorSound();
    setTimeout(() => alertDiv.remove(), duration);
}

function getToken() { return localStorage.getItem(JWT_TOKEN_KEY); }
function getUserData() { const d = localStorage.getItem(USER_DATA_KEY); return d ? JSON.parse(d) : null; }

async function safeJson(response) {
    const text = await response.text();
    try { return JSON.parse(text); } catch { return { text }; }
}

export async function apiCall(endpoint, method = 'GET', data = null) {
    // Aqui chama rotas relativas, sem /api prefix
    const url = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const headers = { 'Content-Type': 'application/json' };
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const config = { method, headers };
    if (data) config.body = JSON.stringify(data);

    const res = await fetch(url, config);
    if (!res.ok) {
        const err = await safeJson(res).catch(() => ({ message: res.statusText }));
        const message = err.message || err.text || res.statusText || 'Erro na requisição da API.';
        throw new Error(`Erro ${res.status}: ${message}`);
    }
    if (res.status === 204) return {};
    return safeJson(res);
}

export async function loginUser(email, password) {
    try {
        const response = await apiCall('/login', 'POST', { email, password });
        if (response.token && response.user) {
            localStorage.setItem(JWT_TOKEN_KEY, response.token);
            localStorage.setItem(USER_DATA_KEY, JSON.stringify(response.user));
            document.dispatchEvent(new CustomEvent('userPermissionsChanged'));
            playSuccessSound();
            return true;
        }
        playErrorSound();
        return false;
    } catch (error) {
        console.error('Login API call failed:', error);
        playErrorSound();
        throw error;
    }
}

export async function logoutUser() {
    localStorage.removeItem(JWT_TOKEN_KEY);
    localStorage.removeItem(USER_DATA_KEY);
    document.dispatchEvent(new CustomEvent('userPermissionsChanged'));
    playSuccessSound();
    return true;
}

// (Restante dos helpers de usuário, saveUser, deleteUser, etc, idem, chamando apiCall com endpoints relativos)

