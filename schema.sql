-- Schema for the combos database

-- combos table
CREATE TABLE IF NOT EXISTS combos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    spells TEXT NOT NULL,
    description TEXT,
    requirement TEXT,
    tags TEXT,
    creator TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    patched BOOLEAN DEFAULT 0
);

-- votes table
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    combo_id INTEGER,
    vote INTEGER CHECK(vote IN (0,1)),          -- 1 = Yes, 0 = No
    voter_hash TEXT,                            -- hash(IP)
    voted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(combo_id, voter_hash),               -- 1 vote/machine
    FOREIGN KEY (combo_id) REFERENCES combos(id)
);

-- reports table for tracking inappropriate and patched reports
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    combo_id INTEGER,
    report_type TEXT CHECK(report_type IN ('inappropriate', 'patched')),
    reporter_hash TEXT,                         -- hash(IP)
    reported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(combo_id, reporter_hash, report_type), -- 1 report of each type per machine
    FOREIGN KEY (combo_id) REFERENCES combos(id)
);

-- Create index for faster vote queries
CREATE INDEX IF NOT EXISTS idx_votes_combo_id ON votes(combo_id);
CREATE INDEX IF NOT EXISTS idx_votes_voted_at ON votes(voted_at);

-- Create index for faster report queries
CREATE INDEX IF NOT EXISTS idx_reports_combo_id ON reports(combo_id);
CREATE INDEX IF NOT EXISTS idx_reports_reported_at ON reports(reported_at);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);

-- users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster user queries
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
