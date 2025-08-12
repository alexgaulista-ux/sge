/**
 * Utilities (frontend) - adjusted to auto-detect backend URL when hosted together on Cloudflare Pages + Workers.
 *
 * Important:
 * - API endpoints in this frontend call paths like '/login', '/users' (without the '/api' prefix),
 *   so API_BASE_URL is set to '<origin>/api' when running in a browser so final URL becomes '<origin>/api/login'.
 */

let audioContext;
let successBuffer, errorBuffer, deleteBuffer;

// Create audio context
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

// Detect API base URL:
// Antes usava `${window.location.origin}/api`, agora vamos remover o "/api"
// e usar a origem do site ou o fallback para o Worker.
let API_BASE_URL = null;
try {
    if (typeof window !== 'undefined' && window.location) {
        API_BASE_URL = `${window.location.origin}`;
    }
} catch (e) {
    API_BASE_URL = 'https://sge-backend.alexgaulista.workers.dev';
}

} catch (e) {
    // fallback to configured worker url (keep existing one as fallback)
    API_BASE_URL = 'https://sge-backend.alexgaulista.workers.dev';
}
const JWT_TOKEN_KEY = 'jwt_token';
const USER_DATA_KEY = 'current_user_data';

function getToken() { return localStorage.getItem(JWT_TOKEN_KEY); }
function getUserData() { const d = localStorage.getItem(USER_DATA_KEY); return d ? JSON.parse(d) : null; }

async function safeJson(response) {
    const text = await response.text();
    try { return JSON.parse(text); } catch (e) { return { text }; }
}

export async function apiCall(endpoint, method = 'GET', data = null) {
    const url = `${API_BASE_URL}${endpoint}`;
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

export async function saveData(collectionName, item, docId = null) {
    if (docId || item.id) {
        const idToUse = docId || item.id;
        const response = await apiCall(`/${collectionName}/${idToUse}`, 'PUT', item);
        return response.id || idToUse;
    } else {
        const response = await apiCall(`/${collectionName}`, 'POST', item);
        return response.id;
    }
}

export async function loadData(collectionName) {
    const data = await apiCall(`/${collectionName}`, 'GET');
    return data || [];
}

export async function getDocById(collectionName, id) {
    try {
        const item = await apiCall(`/${collectionName}/${id}`, 'GET');
        return item || null;
    } catch (error) {
        if (error.message && error.message.includes('404')) return null;
        throw error;
    }
}

export async function deleteData(collectionName, id) {
    await apiCall(`/${collectionName}/${id}`, 'DELETE');
}

// initModule remains the same as in original but we keep function signature
export function initModule(moduleName, renderListFunction, validateFunction = (item) => ({ valid: true })) {
    const appModuleContent = document.getElementById('app-module-content');

    let _handleFormSubmit = async (event) => {
        if (event.target.matches(`#${moduleName}-form`)) {
            event.preventDefault();
            const form = event.target;
            const id = form.dataset.id;
            const formData = new FormData(form);
            const newItem = {};
            for (const [key, value] of formData.entries()) newItem[key] = value.trim();

            const validationResult = validateFunction(newItem, !id);
            if (!validationResult.valid) {
                showAlert(form.parentElement, validationResult.message, 'error');
                return;
            }

            try {
                await saveData(moduleName, newItem, id);
                showAlert(form.parentElement, `Item ${id ? 'atualizado' : 'adicionado'} com sucesso!`, 'success');
                form.reset();
                delete form.dataset.id;
                await renderListFunction();
            } catch (error) {
                console.error('Erro ao salvar item em', moduleName, error);
                showAlert(form.parentElement, `Erro ao salvar item: ${error.message}`, 'error');
            }
        }
    };

    let _handleListActions = async (event) => {
        const target = event.target;
        const currentContainer = document.getElementById(`${moduleName}-list-container`) || appModuleContent;

        if (target.matches('.delete-btn')) {
            const id = target.dataset.id;
            if (confirm('Tem certeza que deseja deletar este item?')) {
                try {
                    await deleteData(moduleName, id);
                    playDeleteSound();
                    showAlert(appModuleContent, 'Item deletado com sucesso!', 'success');
                    await renderListFunction();
                } catch (error) {
                    console.error('Erro ao deletar item de', moduleName, error);
                    showAlert(appModuleContent, `Erro ao deletar item: ${error.message}`, 'error');
                }
            }
        } else if (target.matches('.edit-btn')) {
            const id = target.dataset.id;
            try {
                const itemToEdit = await getDocById(moduleName, id);
                if (itemToEdit) {
                    const form = appModuleContent.querySelector(`#${moduleName}-form`);
                    if (form) {
                        form.dataset.id = itemToEdit.id;
                        for (const key in itemToEdit) {
                            const input = form.querySelector(`[name="${key}"]`);
                            if (input) {
                                if (input.type === 'checkbox') input.checked = itemToEdit[key];
                                else input.value = itemToEdit[key];
                            }
                        }
                        showAlert(appModuleContent, 'Item carregado para edição.', 'success');
                    }
                }
            } catch (error) {
                console.error('Erro ao carregar item para edição', error);
                showAlert(appModuleContent, `Erro ao carregar item para edição: ${error.message}`, 'error');
            }
        }
    };

    appModuleContent.removeEventListener('submit', _handleFormSubmit);
    appModuleContent.removeEventListener('click', _handleListActions);

    appModuleContent.addEventListener('submit', _handleFormSubmit);
    appModuleContent.addEventListener('click', _handleListActions);
}

// Authentication & user helpers
let _currentLoggedInUser = null;

export async function loginUser(email, password) {
    try {
        const response = await apiCall('/login', 'POST', { email, password });
        if (response.token && response.user) {
            localStorage.setItem(JWT_TOKEN_KEY, response.token);
            localStorage.setItem(USER_DATA_KEY, JSON.stringify(response.user));
            _currentLoggedInUser = response.user;
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
    _currentLoggedInUser = null;
    document.dispatchEvent(new CustomEvent('userPermissionsChanged'));
    playSuccessSound();
    return true;
}

export function isLoggedIn() {
    if (_currentLoggedInUser) return true;
    const token = getToken();
    const userData = getUserData();
    if (token && userData) {
        _currentLoggedInUser = userData;
        return true;
    }
    return false;
}

export function getCurrentUserId() {
    const ud = getUserData();
    return ud ? ud.id : null;
}

export function getCurrentUserPermissions() {
    const ud = getUserData();
    return ud ? (ud.permissions || []) : [];
}

export async function getAllUsers() {
    return await apiCall('/users', 'GET');
}

export async function saveUser(userObj) {
    try {
        let response;
        if (userObj.id) response = await apiCall(`/users/${userObj.id}`, 'PUT', userObj);
        else response = await apiCall('/users', 'POST', userObj);

        if (_currentLoggedInUser && _currentLoggedInUser.id === (userObj.id || response.id)) {
            const updatedUser = userObj.id ? userObj : response;
            _currentLoggedInUser = { ..._currentLoggedInUser, ...updatedUser };
            localStorage.setItem(USER_DATA_KEY, JSON.stringify(_currentLoggedInUser));
            document.dispatchEvent(new CustomEvent('userPermissionsChanged'));
        }
        return true;
    } catch (error) {
        console.error('Error saving user via API:', error);
        throw error;
    }
}

export async function deleteUser(userIdToDelete) {
    await apiCall(`/users/${userIdToDelete}`, 'DELETE');
    if (_currentLoggedInUser && _currentLoggedInUser.id === userIdToDelete) await logoutUser();
    else document.dispatchEvent(new CustomEvent('userPermissionsChanged'));
    return true;
}

export function getInitialLoginState() {
    const token = getToken();
    const userData = getUserData();
    if (token && userData) {
        _currentLoggedInUser = userData;
        return { isLoggedIn: true, user: userData };
    }
    return { isLoggedIn: false, user: null };
}

// Run initial state check on module import
getInitialLoginState();
