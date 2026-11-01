"""Constants and database schema (SQLite; portable SQL, can be moved to MySQL)."""

STATUSES = ("Open", "In Progress", "Resolved", "Risk Accepted")
ACTIVE = ("Open", "In Progress")
ROLES = ("viewer", "analyst", "admin")
ASSET_TYPES = ("Server", "Workstation", "Network Device", "Service",
               "Application", "Database", "Other")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    ip TEXT,
    asset_type TEXT NOT NULL,
    os TEXT,
    criticality INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    internet_exposed INTEGER NOT NULL DEFAULT 0,
    owner TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'import',
    fmt TEXT,
    total_rows INTEGER NOT NULL DEFAULT 0,
    imported INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0,
    verified_resolved INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_key TEXT NOT NULL UNIQUE,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity REAL NOT NULL CHECK (severity > 0 AND severity <= 10),
    source TEXT,
    epss REAL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    vuln_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open','In Progress','Resolved','Risk Accepted')),
    priority REAL NOT NULL DEFAULT 0,
    priority_adj REAL NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_scan_id INTEGER REFERENCES scans(id),
    due_date TEXT,
    resolved_at TEXT,
    UNIQUE (asset_id, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, priority);
CREATE TABLE IF NOT EXISTS tasks_remediation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    assignee TEXT,
    due_date TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    action TEXT,
    updated_at TEXT NOT NULL,
    updated_by TEXT
);
CREATE TABLE IF NOT EXISTS history_risk (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL,
    severity REAL,
    criticality INTEGER,
    score REAL NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);
"""
