/**
 * ****************************************************************************************************************
 * IMPORTANT NOTE ON PERSISTENCE AND SECURITY:
 * This utility file has been modified to use `localStorage` for data persistence and a mock authentication system.
 * This change was made because direct browser interaction with a server-side database like "SQL D1" (Cloudflare D1)
 * requires a **backend server** (e.g., Cloudflare Workers) to handle database queries securely and user authentication.
 *
 * As this environment strictly supports frontend HTML/CSS/JS (client-side code) only, a full backend implementation
 * (which would involve server-side code, database connection strings, API routes, and deployment to a platform
 * like Cloudflare Workers) is not possible here.
 *
 * **THIS IS FOR DEMONSTRATION PURPOSES ONLY.**
 * - Data is stored in your browser's local storage and is NOT persistent across different browsers or devices.
 * - Authentication is mocked and NOT secure. Passwords are stored in plain text.
 * - To achieve persistence, security, and true backend integration (e.g., with SQL D1 via Cloudflare Workers),
 *   you MUST implement a separate backend service. This frontend application would then send API requests to that backend.
 * ****************************************************************************************************************
 */

let audioContext;
let successBuffer, errorBuffer, deleteBuffer;

/**
 * Creates an AudioContext instance if one does not already exist.
 * @returns {AudioContext} The AudioContext instance.
 */
function getAudioContext() {
    if (!audioContext) {
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
    }
    return audioContext;
}

/**
 * Loads a sound file into an AudioBuffer.
 * @param {string} url - The URL of the sound file.
 * @returns {Promise<AudioBuffer>} A promise that resolves with the AudioBuffer.
 */
async function loadSound(url) {
    const context = getAudioContext();
    const response = await fetch(url);
    const arrayBuffer = await response.arrayBuffer();
    return new Promise((resolve, reject) => {
        context.decodeAudioData(arrayBuffer, resolve, reject);
    });
}

// Load sounds on utility module load
document.addEventListener('DOMContentLoaded', async () => {
    try {
        successBuffer = await loadSound('success_sound.mp3');
        errorBuffer = await loadSound('error_sound.mp3');
        deleteBuffer = await loadSound('delete_sound.mp3');
    } catch (error) {
        console.error('Error loading sound effects:', error);
    }
});

export function playSuccessSound() {
    playSound(successBuffer);
}

export function playErrorSound() {
    playSound(errorBuffer);
}

export function playDeleteSound() {
    playSound(deleteBuffer);
}

/**
 * Plays a sound from a given AudioBuffer.
 * @param {AudioBuffer} buffer - The AudioBuffer to play.
 */
export function playSound(buffer) {
    if (!buffer) return;
    const context = getAudioContext();
    const source = context.createBufferSource();
    source.buffer = buffer;
    source.connect(context.destination);
    source.start(0);
}

/**
 * Displays a temporary alert message.
 * @param {HTMLElement} container - The DOM element where the alert should be displayed.
 * @param {string} message - The message to display.
 * @param {'success'|'error'} type - The type of alert (success or error).
 * @param {number} duration - Duration in milliseconds before the alert disappears.
 */
export function showAlert(container, message, type = 'success', duration = 3000) {
    // Remove existing alerts in the container before adding a new one
    container.querySelectorAll('.alert').forEach(alert => alert.remove());

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    container.prepend(alertDiv);

    if (type === 'success') {
        playSuccessSound();
    } else if (type === 'error') {
        playErrorSound();
    }

    setTimeout(() => {
        alertDiv.remove();
    }, duration);
}

// --- API-based Data Management (replaces local storage for persistence) ---

// IMPORTANT: Replace this with your actual Cloudflare Worker URL
const API_BASE_URL = 'https://your-cloudflare-worker-url.workers.dev/api';
const JWT_TOKEN_KEY = 'jwt_token';
const USER_DATA_KEY = 'current_user_data'; // Store user ID and permissions here

/**
 * Helper to get the current JWT token from localStorage.
 * @returns {string|null} The JWT token or null if not found.
 */
function getToken() {
    return localStorage.getItem(JWT_TOKEN_KEY);
}

/**
 * Helper to get the current user data from localStorage.
 * @returns {Object|null} The user data object or null if not found.
 */
function getUserData() {
    const data = localStorage.getItem(USER_DATA_KEY);
    return data ? JSON.parse(data) : null;
}

/**
 * Generic API call function with authentication.
 * @param {string} endpoint - The API endpoint relative to API_BASE_URL.
 * @param {string} method - HTTP method (GET, POST, PUT, DELETE).
 * @param {Object} [data] - Data payload for POST/PUT.
 * @returns {Promise<Object>} The JSON response from the API.
 * @throws {Error} If the API call fails or returns an error status.
 */
async function apiCall(endpoint, method = 'GET', data = null) {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers = {
        'Content-Type': 'application/json',
    };

    const token = getToken();
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        method: method,
        headers: headers,
    };

    if (data) {
        config.body = JSON.stringify(data);
    }

    const response = await fetch(url, config);

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Erro desconhecido.' }));
        const errorMessage = errorData.message || response.statusText || 'Erro na requisição da API.';
        throw new Error(`Erro ${response.status}: ${errorMessage}`);
    }

    // Handle 204 No Content for DELETE operations
    if (response.status === 204) {
        return {};
    }

    return response.json();
}

/**
 * Saves/Updates an item via API.
 * @param {string} collectionName - The name of the collection (e.g., 'tasks', 'expenses').
 * @param {Object} item - The object to save. Must have an 'id' for updates.
 * @param {string} [docId] - Optional. If provided, saves the item with this specific ID (for PUT).
 * @returns {Promise<string>} A promise that resolves with the ID of the saved/updated item.
 */
export async function saveData(collectionName, item, docId = null) {
    try {
        if (docId || item.id) {
            // Update existing item
            const idToUse = docId || item.id;
            const response = await apiCall(`/${collectionName}/${idToUse}`, 'PUT', item);
            return response.id || idToUse; // Assuming API returns the updated item with ID
        } else {
            // Add new item
            const response = await apiCall(`/${collectionName}`, 'POST', item);
            return response.id; // Assuming API returns the new item with ID
        }
    } catch (error) {
        console.error(`Erro ao salvar item em ${collectionName}:`, error);
        throw error; // Re-throw to be caught by showAlert in initModule
    }
}

/**
 * Loads all items from a collection via API.
 * @param {string} collectionName - The name of the collection.
 * @returns {Promise<Array<Object>>} A promise that resolves with an array of items, each with an 'id' field.
 */
export async function loadData(collectionName) {
    try {
        const data = await apiCall(`/${collectionName}`, 'GET');
        return data || [];
    } catch (error) {
        console.error(`Erro ao carregar dados de ${collectionName}:`, error);
        throw error;
    }
}

/**
 * Retrieves a single item by its ID from a collection via API.
 * @param {string} collectionName - The name of the collection.
 * @param {string} id - The ID of the item to retrieve.
 * @returns {Promise<Object|null>} A promise that resolves with the item data (including its ID) or null if not found.
 */
export async function getDocById(collectionName, id) {
    try {
        const item = await apiCall(`/${collectionName}/${id}`, 'GET');
        return item || null;
    } catch (error) {
        console.error(`Erro ao obter documento ${id} de ${collectionName}:`, error);
        if (error.message.includes('404')) return null; // Specific handling for not found
        throw error;
    }
}

/**
 * Deletes an item from a collection via API.
 * @param {string} collectionName - The name of the collection.
 * @param {string} id - The ID of the item to delete.
 * @returns {Promise<void>}
 */
export async function deleteData(collectionName, id) {
    try {
        await apiCall(`/${collectionName}/${id}`, 'DELETE');
    } catch (error) {
        console.error(`Erro ao deletar item ${id} de ${collectionName}:`, error);
        throw error;
    }
}

/**
 * Sets up a module by adding common functionality (e.g., form submission, delete buttons).
 * @param {string} moduleName - The key used for collection name in the API.
 * @param {function(): Promise<string>} renderListFunction - Async function to re-render the list section.
 * @param {function(Object, boolean): {valid: boolean, message?: string}} validateFunction - Optional validation function for new/edited items. Takes item and isNewUser.
 */
export function initModule(moduleName, renderListFunction, validateFunction = (item) => ({ valid: true })) {
    const appModuleContent = document.getElementById('app-module-content');

    // Store event listener functions to allow proper removal and avoid duplicates
    let _handleFormSubmit = async (event) => {
        if (event.target.matches(`#${moduleName}-form`)) {
            event.preventDefault();
            const form = event.target;
            const id = form.dataset.id; // This will be the ID for updates
            const formData = new FormData(form);
            const newItem = {};
            for (const [key, value] of formData.entries()) {
                newItem[key] = value.trim();
            }

            const validationResult = validateFunction(newItem, !id); // Pass isNewUser to validation
            if (!validationResult.valid) {
                showAlert(form.parentElement, validationResult.message, 'error');
                return;
            }

            try {
                await saveData(moduleName, newItem, id);
                showAlert(form.parentElement, `Item ${id ? 'atualizado' : 'adicionado'} com sucesso!`, 'success');
                form.reset();
                delete form.dataset.id; // Clear ID for new entries
                await renderListFunction(); // Re-render the list
            } catch (error) {
                console.error(`Erro ao salvar item em ${moduleName}:`, error);
                showAlert(form.parentElement, `Erro ao salvar item: ${error.message}`, 'error');
            }
        }
    };

    let _handleListActions = async (event) => {
        const target = event.target;
        // Check for common parent element to ensure listeners are not removed prematurely for newly rendered content
        const currentContainer = document.getElementById(`${moduleName}-list-container`) || appModuleContent;

        if (target.matches('.delete-btn')) {
            const id = target.dataset.id;
            if (confirm('Tem certeza que deseja deletar este item?')) {
                try {
                    await deleteData(moduleName, id);
                    playDeleteSound(); // Play delete sound
                    showAlert(appModuleContent, 'Item deletado com sucesso!', 'success');
                    await renderListFunction(); // Re-render the list
                } catch (error) {
                    console.error(`Erro ao deletar item de ${moduleName}:`, error);
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
                                if (input.type === 'checkbox') {
                                    input.checked = itemToEdit[key];
                                } else {
                                    input.value = itemToEdit[key];
                                }
                            }
                        }
                        showAlert(appModuleContent, 'Item carregado para edição.', 'success');
                    }
                }
            } catch (error) {
                console.error(`Erro ao carregar item para edição em ${moduleName}:`, error);
                showAlert(appModuleContent, `Erro ao carregar item para edição: ${error.message}`, 'error');
            }
        }
    };

    // Remove previous listeners using named functions to prevent duplicates
    appModuleContent.removeEventListener('submit', _handleFormSubmit);
    appModuleContent.removeEventListener('click', _handleListActions);

    appModuleContent.addEventListener('submit', _handleFormSubmit);
    appModuleContent.addEventListener('click', _handleListActions);
}

// --- User Management (replaces Firebase Authentication and User interactions with external DB) ---

let _currentLoggedInUser = null; // Stores the logged-in user object from JWT/API response

/**
 * Attempts to log in a user via API.
 * @param {string} email - The user's email address.
 * @param {string} password - The user's password.
 * @returns {Promise<boolean>} True if login is successful, false otherwise.
 */
export async function loginUser(email, password) {
    try {
        const response = await apiCall('/login', 'POST', { email, password });
        if (response.token && response.user) {
            localStorage.setItem(JWT_TOKEN_KEY, response.token);
            localStorage.setItem(USER_DATA_KEY, JSON.stringify(response.user)); // Store full user object including permissions
            _currentLoggedInUser = response.user;
            document.dispatchEvent(new CustomEvent('userPermissionsChanged')); // Notify UI
            playSuccessSound();
            return true;
        }
        playErrorSound();
        return false;
    } catch (error) {
        console.error("Login API call failed:", error);
        playErrorSound();
        throw error; // Re-throw for specific login screen error message
    }
}

/**
 * Logs out the current user by clearing stored token and user data.
 * @returns {Promise<boolean>} True if logout is successful.
 */
export async function logoutUser() {
    localStorage.removeItem(JWT_TOKEN_KEY);
    localStorage.removeItem(USER_DATA_KEY);
    _currentLoggedInUser = null;
    document.dispatchEvent(new CustomEvent('userPermissionsChanged')); // Notify UI
    playSuccessSound();
    return true;
}

/**
 * Checks if a user is currently logged in based on JWT presence.
 * Also attempts to load user data if token exists but _currentLoggedInUser is null.
 * @returns {boolean}
 */
export function isLoggedIn() {
    // If we have current user data in memory, we are logged in.
    if (_currentLoggedInUser) return true;

    // Otherwise, check localStorage for a token and try to load user data.
    const token = getToken();
    const userData = getUserData(); // Retrieve user data from localStorage

    if (token && userData) {
        _currentLoggedInUser = userData; // Populate in-memory cache
        return true;
    }
    return false;
}

/**
 * Gets the ID of the current logged-in user.
 * @returns {string|null} The user ID or null if not logged in.
 */
export function getCurrentUserId() {
    const userData = getUserData();
    return userData ? userData.id : null;
}

/**
 * Gets the cached permissions of the current logged-in user.
 * @returns {Array<string>} An array of module keys the user has access to.
 */
export function getCurrentUserPermissions() {
    const userData = getUserData();
    return userData ? (userData.permissions || []) : [];
}

/**
 * Retrieves all registered users from the API.
 * @returns {Promise<Array<Object>>} An array of user objects.
 */
export async function getAllUsers() {
    try {
        const users = await apiCall('/users', 'GET');
        return users || [];
    } catch (error) {
        console.error('Error fetching all users:', error);
        throw error;
    }
}

/**
 * Saves a user (adds new or updates existing) via API.
 * @param {Object} userObj - The user object to save. Must have username, email, permissions.
 *                           If new, must have password.
 * @returns {Promise<boolean>} True if save was successful.
 */
export async function saveUser(userObj) {
    try {
        let response;
        if (userObj.id) {
            // Update existing user
            response = await apiCall(`/users/${userObj.id}`, 'PUT', userObj);
        } else {
            // Create new user
            response = await apiCall('/users', 'POST', userObj);
        }

        // If the current logged-in user's data was updated, refresh client-side cache
        if (_currentLoggedInUser && _currentLoggedInUser.id === (userObj.id || response.id)) {
            const updatedUser = userObj.id ? userObj : response; // Use the response if it's a new user (to get ID)
            // Ensure permissions are updated
            _currentLoggedInUser = { ..._currentLoggedInUser, ...updatedUser };
            localStorage.setItem(USER_DATA_KEY, JSON.stringify(_currentLoggedInUser));
            document.dispatchEvent(new CustomEvent('userPermissionsChanged'));
        }
        return true;
    } catch (error) {
        console.error("Error saving user via API:", error);
        throw error;
    }
}

/**
 * Deletes a user via API.
 * @param {string} userIdToDelete - The ID of the user to delete.
 * @returns {Promise<boolean>} True if deletion was successful.
 */
export async function deleteUser(userIdToDelete) {
    try {
        await apiCall(`/users/${userIdToDelete}`, 'DELETE');

        // If the deleted user was the currently logged-in user, log them out
        if (_currentLoggedInUser && _currentLoggedInUser.id === userIdToDelete) {
            await logoutUser(); // This clears JWT and user data
        } else {
            document.dispatchEvent(new CustomEvent('userPermissionsChanged')); // Permissions might have changed for other modules too (if user was admin)
        }
        return true;
    } catch (error) {
        console.error("Error deleting user via API:", error);
        throw error;
    }
}

/**
 * Checks for initial login state based on JWT and user data in localStorage.
 * Populates _currentLoggedInUser if valid token/data found.
 * @returns {{isLoggedIn: boolean, user: Object|null}}
 */
export function getInitialLoginState() {
    const token = getToken();
    const userData = getUserData();

    if (token && userData) {
        // Here, you might want to validate the token with the backend
        // For simplicity, we assume token and stored user data means logged in.
        // A real app might have a /me endpoint to validate token and fetch fresh user data.
        _currentLoggedInUser = userData;
        return { isLoggedIn: true, user: userData };
    }
    return { isLoggedIn: false, user: null };
}

// Perform initial login state check when utils is imported
getInitialLoginState();