CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_uuid   TEXT UNIQUE NOT NULL,
    hostname    TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    overall_score    INTEGER,
    grade            TEXT,
    total_critical   INTEGER DEFAULT 0,
    total_high       INTEGER DEFAULT 0,
    total_medium     INTEGER DEFAULT 0,
    total_low        INTEGER DEFAULT 0,
    total_info       INTEGER DEFAULT 0,
    total_pass       INTEGER DEFAULT 0,
    report_path      TEXT,
    notes            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module_name     TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL,
    passed          INTEGER NOT NULL DEFAULT 0,
    recommendation  TEXT,
    raw_output      TEXT,
    ref_links       TEXT,
    tags            TEXT
);

CREATE TABLE IF NOT EXISTS module_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module_name     TEXT NOT NULL,
    display_name    TEXT,
    duration_seconds REAL,
    finding_count   INTEGER,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
