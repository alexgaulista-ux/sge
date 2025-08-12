-- Tabela de Usuários
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    permissions TEXT DEFAULT '[]' NOT NULL, -- JSON string of allowed modules (e.g., '["dashboard", "tasks"]')
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Fornecedores
CREATE TABLE IF NOT EXISTS suppliers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    contact TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Contratos
CREATE TABLE IF NOT EXISTS contracts (
    id TEXT PRIMARY KEY,
    supplier_id TEXT,
    contract_number TEXT UNIQUE NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    value REAL NOT NULL,
    description TEXT,
    status TEXT NOT NULL, -- e.g., "active", "expired", "pending"
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id) ON DELETE SET NULL
);

-- Tabela de Despesas
CREATE TABLE IF NOT EXISTS expenses (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    date TEXT NOT NULL,
    category TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Serviços
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    duration_hours REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Tarefas
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    due_date TEXT,
    status TEXT NOT NULL, -- e.g., "pending", "completed", "in_progress"
    priority TEXT, -- e.g., "high", "medium", "low"
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Inventário (Equipamentos)
CREATE TABLE IF NOT EXISTS inventory (
    id TEXT PRIMARY KEY,
    item_name TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price REAL,
    purchase_date TEXT,
    location TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Notas Fiscais
CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    invoice_number TEXT UNIQUE NOT NULL,
    issue_date TEXT NOT NULL,
    due_date TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL, -- e.g., "paid", "pending", "overdue"
    client_name TEXT,
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Inserir um usuário administrador padrão
-- Senha: 'admin123' (hashada com SHA-256 para simplicidade, NÃO USE EM PRODUÇÃO REAL SEM UM HASH MAIS FORTE COMO BCRYPT)
-- Para produção, você DEVE usar bcrypt ou Argon2. Como não temos Node.js para bcrypt,
-- estou usando SHA-256 para demonstração.
-- O hash SHA-256 de 'admin123' é: 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
INSERT OR IGNORE INTO users (id, email, password_hash, permissions) VALUES
('admin-uuid-123', 'admin@example.com', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', '["dashboard", "tasks", "inventory", "suppliers", "contracts", "expenses", "services", "invoices", "users"]');