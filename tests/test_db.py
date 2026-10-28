from core.db import init_db, DB
import os
import tempfile


def test_init_db_creates_tables():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_db(db_path=path)
        db = DB(db_path=path)
        conn = db.connect()
        try:
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            names = [r["name"] for r in cur.fetchall()]
            for t in ["roles", "users", "devices", "authorizations", "allowlist", "scans", "scan_results", "findings", "audit_log"]:
                assert t in names
        finally:
            conn.close()
    finally:
        os.unlink(path)


def test_add_device_and_get():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_db(db_path=path)
        db = DB(db_path=path)
        did = db.add_device("192.168.1.100", hostname="test-pc")
        assert did > 0
        d = db.get_device_by_ip("192.168.1.100")
        assert d is not None
        assert d["hostname"] == "test-pc"
    finally:
        os.unlink(path)


def test_upsert_finding_increments():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_db(db_path=path)
        db = DB(db_path=path)
        did = db.add_device("192.168.1.200")
        sid = db.create_scan(nmap_args="-T3 -sT")
        fid1 = db.upsert_finding(did, "192.168.1.200", 3389, "tcp", "risky_service", "high", "unapproved", "RDP not in allowlist", scan_id=sid)
        fid2 = db.upsert_finding(did, "192.168.1.200", 3389, "tcp", "risky_service", "high", "unapproved", "RDP not in allowlist", scan_id=sid)
        assert fid1 == fid2
        conn = db.connect()
        try:
            cur = conn.execute("SELECT occurrence_count FROM findings WHERE id = ?", (fid1,))
            r = cur.fetchone()
            assert r["occurrence_count"] == 2
        finally:
            conn.close()
        db.finish_scan(sid, "completed")
    finally:
        os.unlink(path)


def test_audit_log():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_db(db_path=path)
        db = DB(db_path=path)
        aid = db.log_audit("GATE_REJECT", target_ip="8.8.8.8", details={"code": 4})
        assert aid > 0
    finally:
        os.unlink(path)
