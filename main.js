import { 
  isLoggedIn, 
  loginUser, 
  logoutUser, 
  getCurrentUserPermissions,  // Corrigido: removeu espaço e maiúscula correta
  getCurrentUserId,           // Corrigido: removeu espaço
  showAlert, 
  getInitialLoginState 
} from 'utils';

// Define the available modules and their paths
const modules = {
    dashboard: () => import('./modules/dashboard.js'),
    tasks: () => import('./modules/tasks.js'),
    inventory: () => import('./modules/inventory.js'),
    suppliers: () => import('./modules/suppliers.js'),
    contracts: () => import('./modules/contracts.js'),
    expenses: () => import('./modules/expenses.js'),
    services: () => import('./modules/services.js'),
    invoices: () => import('./modules/invoices.js'),
    users: () => import('./modules/users.js')
};

const appContainer = document.getElementById('app-container');
const loginScreen = document.getElementById('login-screen');
const loginForm = document.getElementById('login-form');
const loginAlertContainer = document.getElementById('login-alert-container');
const logoutBtn = document.getElementById('logout-btn');

const appModuleContent = document.getElementById('app-module-content');
const sidebarNav = document.querySelector('#sidebar nav ul');
const mainHeaderTitle = document.getElementById('main-header-title');

/**
 * Renders the sidebar links based on user permissions.
 */
function renderSidebar() {
    const allowedModules = getCurrentUserPermissions();
    document.querySelectorAll('#sidebar nav ul li a').forEach(link => {
        const moduleName = link.dataset.module;
        if (allowedModules.includes(moduleName) || allowedModules.includes('admin')) {
            link.classList.remove('disabled');
            link.style.pointerEvents = 'auto'; // Re-enable pointer events
        } else {
            link.classList.add('disabled');
            link.classList.remove('active'); // Ensure disabled links are not active
            link.style.pointerEvents = 'none'; // Disable pointer events
        }
    });
}

/**
 * Handles user login.
 * @param {Event} event - The form submission event.
 */
async function handleLoginSubmit(event) {
    event.preventDefault();
    const email = loginForm.username.value.trim(); // good practice to trim
    const password = loginForm.password.value;

    try {
        const success = await loginUser(email, password);
        if (success) {
            loginScreen.classList.remove('active');
            loginScreen.classList.add('hidden');
            appContainer.classList.remove('hidden');
            appContainer.classList.add('active');
            renderSidebar(); // Render sidebar based on new permissions
            loadModule('dashboard'); // Load dashboard after successful login
        } else {
            showAlert(loginAlertContainer, 'Usuário ou senha inválidos. Verifique suas credenciais.', 'error');
        }
    } catch (error) {
        console.error("Login attempt failed:", error);
        showAlert(loginAlertContainer, `Erro ao tentar login: ${error.message}. Certifique-se de que o backend está configurado corretamente.`, 'error');
    }
}

/**
 * Handles user logout.
 */
async function handleLogout() {
    try {
        await logoutUser();
        appContainer.classList.remove('active');
        appContainer.classList.add('hidden');
        loginScreen.classList.remove('hidden');
        loginScreen.classList.add('active');
        // Clear content and reset header
        appModuleContent.innerHTML = '<p>Selecione uma opção no menu lateral para começar.</p>';
        mainHeaderTitle.textContent = 'Bem-vindo ao Sistema de Gestão';
        // Remove active state from all sidebar links
        document.querySelectorAll('#sidebar nav ul li a').forEach(link => {
            link.classList.remove('active');
        });
        // Re-render sidebar after logout (no user, so all disabled)
        renderSidebar();
    } catch (error) {
        console.error("Logout attempt failed:", error);
        showAlert(loginAlertContainer, `Erro ao fazer logout: ${error.message}`, 'error');
    }
}

/**
 * Loads a specific module into the main content area.
 * @param {string} moduleName - The name of the module to load.
 */
async function loadModule(moduleName) {
    // Check if user is logged in
    if (!isLoggedIn()) {
        handleLogout(); // Redirect to login if not logged in
        return;
    }

    // Get permissions after login state is confirmed
    const userPermissions = getCurrentUserPermissions();

    // Check module permissions
    if (!userPermissions.includes(moduleName) && !userPermissions.includes('admin')) {
        showAlert(appModuleContent, 'Você não tem permissão para acessar este módulo.', 'error');
        mainHeaderTitle.textContent = 'Acesso Negado';
        appModuleContent.innerHTML = '<p class="alert alert-error">Você não tem permissão para acessar este módulo.</p>'; // Clear previous content
        return;
    }

    if (!modules[moduleName]) {
        console.error(`Module "${moduleName}" not found.`);
        appModuleContent.innerHTML = '<p class="alert alert-error">Módulo não encontrado.</p>';
        mainHeaderTitle.textContent = 'Erro';
        return;
    }

    try {
        const module = await modules[moduleName]();
        if (module && typeof module.render === 'function') {
            appModuleContent.innerHTML = await module.render(); // Render the module's HTML

            // Re-initialize module logic and event listeners
            if (typeof module.init === 'function') {
                module.init();
            }

            // Update header title
            mainHeaderTitle.textContent = module.title || moduleName.charAt(0).toUpperCase() + moduleName.slice(1);

            // Update active state in sidebar
            document.querySelectorAll('#sidebar nav ul li a').forEach(link => {
                link.classList.remove('active');
            });
            const activeLink = document.querySelector(`#sidebar nav ul li a[data-module="${moduleName}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
            }

        } else {
            console.error(`Module "${moduleName}" does not have a render function.`);
            appModuleContent.innerHTML = '<p class="alert alert-error">Não foi possível carregar o módulo.</p>';
            mainHeaderTitle.textContent = 'Erro';
        }
    } catch (error) {
        console.error(`Error loading module "${moduleName}":`, error);
        showAlert(appModuleContent, `Erro ao carregar o módulo: ${error.message}`, 'error');
        mainHeaderTitle.textContent = 'Erro de Carregamento';
    }
}

// Event listener for sidebar navigation clicks
sidebarNav.addEventListener('click', (event) => {
    const targetLink = event.target.closest('a[data-module]');
    if (targetLink && !targetLink.classList.contains('disabled')) {
        event.preventDefault(); // Prevent default link behavior
        const moduleName = targetLink.dataset.module;
        loadModule(moduleName);
    }
});

// Event listeners for login and logout
loginForm.addEventListener('submit', handleLoginSubmit);
logoutBtn.addEventListener('click', handleLogout);

// Custom event listener for when user permissions change (e.g., from users module or auth state changes)
document.addEventListener('userPermissionsChanged', () => {
    renderSidebar(); // Re-render sidebar to reflect new permissions
    // If current module is now inaccessible, redirect to dashboard or login
    const currentModuleLink = document.querySelector('#sidebar nav ul li a.active');
    if (currentModuleLink && currentModuleLink.classList.contains('disabled')) {
        showAlert(appModuleContent, 'Suas permissões foram atualizadas. Você não tem mais acesso a este módulo.', 'error');
        loadModule('dashboard'); // Redirect to dashboard
    }
});

// Initialize the app based on stored login state (if any)
document.addEventListener('DOMContentLoaded', () => {
    const initialState = getInitialLoginState();
    if (initialState.isLoggedIn) {
        loginScreen.classList.remove('active');
        loginScreen.classList.add('hidden');
        appContainer.classList.remove('hidden');
        appContainer.classList.add('active');
        renderSidebar(); // Initial sidebar render
        loadModule('dashboard'); // Load dashboard after successful login
    } else {
        loginScreen.classList.add('active');
        loginScreen.classList.remove('hidden');
        appContainer.classList.add('hidden');
        renderSidebar(); // Render sidebar for logged out state (all disabled)
        appModuleContent.innerHTML = '<p>Selecione uma opção no menu lateral para começar.</p>';
        mainHeaderTitle.textContent = 'Bem-vindo ao Sistema de Gestão';
        document.querySelectorAll('#sidebar nav ul li a').forEach(link => {
            link.classList.remove('active');
        });
    }
});
