# PortWatch database layer (Phase 2)
import os
import sqlite3
from typing import Any, Dict, List, Optional

from config import Config


def get_connection(db_path: str = None) -> sqlite3.Connection:
    db_path = db_path or Config.DATABASE
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = None, schema_path: str = None) -> None:
    db_path = db_path or Config.DATABASE
    schema_path = schema_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema.sql")
    schema_path = os.path.abspath(schema_path)
    conn = get_connection(db_path)
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    if row is None:
        return {}
    return dict(row)


def rows_to_list(rows) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows]


class DB:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or Config.DATABASE

    def connect(self) -> sqlite3.Connection:
        return get_connection(self.db_path)

    # Roles
    def upsert_role(self, name: str, description: str = "") -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
                (name, description),
            )
            conn.commit()
            if cur.lastrowid:
                return cur.lastrowid
            cur2 = conn.execute("SELECT id FROM roles WHERE name = ?", (name,))
            r = cur2.fetchone()
            return r["id"] if r else 0
        finally:
            conn.close()

    # Devices
    def add_device(self, ip_address: str, hostname: str = "", location: str = "", criticality: int = 1, notes: str = "") -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO devices (ip_address, hostname, location, criticality, notes) VALUES (?, ?, ?, ?, ?)",
                (ip_address, hostname, location, criticality, notes),
            )
            conn.commit()
            if cur.lastrowid:
                return cur.lastrowid
            cur2 = conn.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,))
            r = cur2.fetchone()
            return r["id"] if r else 0
        finally:
            conn.close()

    def get_device_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        conn = self.connect()
        try:
            cur = conn.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            r = cur.fetchone()
            return dict(r) if r else None
        finally:
            conn.close()

    # Authorizations
    def add_authorization(self, device_id: int, authorized_by: str = "", reason: str = "", expires_at: str = None) -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO authorizations (device_id, authorized_by, reason, expires_at) VALUES (?, ?, ?, ?)",
                (device_id, authorized_by, reason, expires_at),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    # Allowlist
    def add_allowlist_entry(self, device_id: int, port: int, protocol: str = "tcp", service: str = "", allowed_by: str = "") -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO allowlist (device_id, port, protocol, service, allowed_by) VALUES (?, ?, ?, ?, ?)",
                (device_id, port, protocol, service, allowed_by),
            )
            conn.commit()
            if cur.lastrowid:
                return cur.lastrowid
            cur2 = conn.execute("SELECT id FROM allowlist WHERE device_id = ? AND port = ? AND protocol = ?", (device_id, port, protocol))
            r = cur2.fetchone()
            return r["id"] if r else 0
        finally:
            conn.close()

    def get_allowlist(self, device_id: int) -> List[Dict[str, Any]]:
        conn = self.connect()
        try:
            cur = conn.execute("SELECT * FROM allowlist WHERE device_id = ?", (device_id,))
            return rows_to_list(cur.fetchall())
        finally:
            conn.close()

    # Scans
    def create_scan(self, requested_by: int = None, nmap_args: str = "") -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO scans (requested_by, status, nmap_args, started_at) VALUES (?, 'running', ?, datetime('now'))",
                (requested_by, nmap_args),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def finish_scan(self, scan_id: int, status: str = "completed") -> None:
        conn = self.connect()
        try:
            conn.execute("UPDATE scans SET status = ?, finished_at = datetime('now') WHERE id = ?", (status, scan_id))
            conn.commit()
        finally:
            conn.close()

    # Scan results
    def add_scan_result(self, scan_id: int, ip_address: str, port: int, protocol: str, state: str, service: str = "", product: str = "", version: str = "", extrainfo: str = "", hostname: str = "", device_id: int = None) -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO scan_results (scan_id, device_id, ip_address, hostname, protocol, port, state, service, product, version, extrainfo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, device_id, ip_address, hostname, protocol, port, state, service, product, version, extrainfo),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    # Findings
    def upsert_finding(self, device_id: int, ip_address: str, port: int, protocol: str, finding_type: str, severity: str, verdict: str, reason: str = "", scan_id: int = None) -> int:
        conn = self.connect()
        try:
            # Try update first
            cur = conn.execute(
                "SELECT id, occurrence_count FROM findings WHERE device_id = ? AND port = ? AND protocol = ? AND finding_type = ?",
                (device_id, port, protocol, finding_type),
            )
            row = cur.fetchone()
            if row:
                new_count = (row["occurrence_count"] or 1) + 1
                conn.execute(
                    "UPDATE findings SET last_seen_scan = ?, last_seen_at = datetime('now'), occurrence_count = ?, severity = ?, verdict = ?, reason = ?, status = 'open' WHERE id = ?",
                    (scan_id, new_count, severity, verdict, reason, row["id"]),
                )
                conn.commit()
                return row["id"]
            else:
                cur2 = conn.execute(
                    "INSERT INTO findings (scan_id, device_id, ip_address, port, protocol, finding_type, severity, verdict, reason, first_seen_scan, last_seen_scan, occurrence_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                    (scan_id, device_id, ip_address, port, protocol, finding_type, severity, verdict, reason, scan_id, scan_id),
                )
                conn.commit()
                return cur2.lastrowid
        finally:
            conn.close()

    # Audit log
    def log_audit(self, action: str, target_ip: str = "", actor_id: int = None, details: Dict[str, Any] = None) -> int:
        import json
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO audit_log (actor_id, action, target_ip, details_json) VALUES (?, ?, ?, ?)",
                (actor_id, action, target_ip, json.dumps(details or {})),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()
