# PortWatch severity classifier (D-21)
from typing import Dict, Any, List


# Service risk table (1-10)
SERVICE_RISK = {
    "ssh": 5,
    "http": 3,
    "https": 2,
    "ms-wbt-server": 9,  # RDP
    "rdp": 9,
    "mysql": 7,
    "ms-sql-s": 8,
    "postgresql": 7,
    "telnet": 9,
    "ftp": 7,
    "smb": 8,
    "microsoft-ds": 8,
    "netbios-ssn": 6,
    "vnc": 8,
    "vncs": 8,
    "redis": 7,
    "mongodb": 7,
    "http-alt": 4,
}


def get_base_risk(service: str) -> int:
    if not service:
        return 9  # unknown/unfingerprinted -> High
    svc = service.lower().strip()
    if svc in SERVICE_RISK:
        return SERVICE_RISK[svc]
    # Unknown service -> treat as high risk
    return 9


def classify_severity(service: str, verdict: str = "unapproved") -> str:
    """Classify severity band. No numeric score."""
    risk = get_base_risk(service)
    if risk >= 8:
        return "high"
    elif risk >= 4:
        return "medium"
    else:
        return "low"


def classify_device(compliance_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute device compliance status.

    Device is compliant only if every open port is approved AND no finding is High.
    """
    if not compliance_results:
        return {"compliant": True, "ratio": 1.0, "high_count": 0, "unapproved_count": 0}

    total = len(compliance_results)
    approved = 0
    unapproved_count = 0
    high_count = 0

    for r in compliance_results:
        if r.get("verdict") == "approved":
            approved += 1
        elif r.get("verdict") == "unapproved":
            unapproved_count += 1
        if r.get("severity") == "high":
            high_count += 1

    ratio = approved / total if total > 0 else 1.0
    compliant = (unapproved_count == 0) and (high_count == 0)

    return {
        "compliant": compliant,
        "ratio": round(ratio, 3),
        "high_count": high_count,
        "unapproved_count": unapproved_count,
        "total_open_ports": total,
    }
