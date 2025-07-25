CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    environment TEXT NOT NULL,
    security_level TEXT NOT NULL,
    groups TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    added_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_count INTEGER NOT NULL,
    secured_count INTEGER NOT NULL,
    vulnerabilities_count INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Données initiales
INSERT INTO stats (host_count, secured_count, vulnerabilities_count) 
VALUES (0, 0, 0);