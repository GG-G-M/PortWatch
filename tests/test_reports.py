from app.reports import export_findings_csv, export_scan_results_csv
import os, tempfile


def test_export_findings_csv():
    findings = [{"id": 1, "ip_address": "192.168.1.10", "port": 3389, "protocol": "tcp", "severity": "high", "verdict": "unapproved", "finding_type": "risky_service", "reason": "test", "status": "open", "occurrence_count": 1, "first_seen_at": "2026-01-01", "last_seen_at": "2026-01-01"}]
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        out = export_findings_csv(findings, path)
        assert os.path.exists(out)
        with open(out) as f:
            content = f.read()
        assert "severity" in content
        assert "verdict" in content
        assert "exposure_score" not in content
    finally:
        os.unlink(path)
