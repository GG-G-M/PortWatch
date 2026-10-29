# PortWatch CSV export
import csv
import os
from typing import List, Dict, Any


def export_findings_csv(findings: List[Dict[str, Any]], output_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fieldnames = ["id", "ip_address", "port", "protocol", "severity", "verdict", "finding_type", "reason", "status", "occurrence_count", "first_seen_at", "last_seen_at"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for item in findings:
            row = {k: item.get(k, "") for k in fieldnames}
            w.writerow(row)
    return output_path


def export_scan_results_csv(results: List[Dict[str, Any]], output_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fieldnames = ["id", "scan_id", "ip_address", "port", "protocol", "state", "service", "product", "version"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for item in results:
            row = {k: item.get(k, "") for k in fieldnames}
            w.writerow(row)
    return output_path
