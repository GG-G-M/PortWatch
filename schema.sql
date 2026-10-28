-- PortWatch schema (Phase 2)
-- Matches Architecture.md and D-21 (no exposure_score)

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  active INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT UNIQUE NOT NULL,
  mac_address TEXT,
  hostname TEXT,
  location TEXT,
  criticality INTEGER DEFAULT 1 CHECK(criticality BETWEEN 1 AND 3),
  is_authorized INTEGER NOT NULL DEFAULT 1,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS authorizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL,
  authorized_by TEXT,
  reason TEXT,
  issued_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL,
  port INTEGER,
  protocol TEXT DEFAULT 'tcp',
  service TEXT,
  allowed_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(device_id, port, protocol),
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requested_by INTEGER,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed')),
  nmap_args TEXT,
  started_at TEXT,
  finished_at TEXT,
  notes TEXT,
  FOREIGN KEY (requested_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scan_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  device_id INTEGER,
  ip_address TEXT NOT NULL,
  hostname TEXT,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  port INTEGER NOT NULL,
  state TEXT NOT NULL,
  service TEXT,
  product TEXT,
  version TEXT,
  extrainfo TEXT,
  scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  device_id INTEGER NOT NULL,
  ip_address TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  finding_type TEXT NOT NULL DEFAULT 'unexpected_port' CHECK(finding_type IN ('unexpected_port','risky_service','new_listener')),
  severity TEXT NOT NULL CHECK(severity IN ('low','medium','high')),
  verdict TEXT NOT NULL CHECK(verdict IN ('approved','unapproved')),
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','closed')),
  note TEXT,
  first_seen_scan INTEGER,
  last_seen_scan INTEGER,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(device_id, port, protocol, finding_type),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
  FOREIGN KEY (first_seen_scan) REFERENCES scans(id) ON DELETE SET NULL,
  FOREIGN KEY (last_seen_scan) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now')),
  actor_id INTEGER,
  action TEXT NOT NULL,
  target_ip TEXT,
  details_json TEXT,
  FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip_port ON scan_results(ip_address, port);
CREATE INDEX IF NOT EXISTS idx_findings_device ON findings(device_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_sev_verdict ON findings(severity, verdict);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_authorizations_device ON authorizations(device_id);
CREATE INDEX IF NOT EXISTS idx_allowlist_device ON allowlist(device_id);
