# PortWatch allowlist conformance
from typing import Dict, Any, List


# Risky services as per PortWatch design
RISKY_SERVICES = {
    "telnet", "ftp", "tftp", "smb", "microsoft-ds", "netbios-ssn",
    "rdp", "ms-wbt-server", "vnc", "vncs", "mysql", "ms-sql-s",
    "postgresql", "oracle-tns", "redis", "mongodb", "couchdb",
    "elasticsearch", "telnetd"
}


def check_conformance(ip: str, port: int, service: str, allowlist: Dict[str, Any]) -> Dict[str, Any]:
    """Check if a port/service is in the allowlist for a device.

    allowlist format: {ip: {"ports": [22, 80], "services": ["ssh", "http"]}, ...}
    or more detailed. We keep it simple and flexible.
    """
    device = allowlist.get(ip, {}) if isinstance(allowlist, dict) else {}
    allowed_ports = set(device.get("ports", [])) if isinstance(device, dict) else set()
    allowed_services = set(s.lower() for s in device.get("services", [])) if isinstance(device, dict) else set()

    service_l = (service or "").lower()
    is_allowed = (port in allowed_ports) or (service_l in allowed_services)
    is_risky = service_l in RISKY_SERVICES

    if is_allowed and not is_risky:
        verdict = "approved"
    elif is_allowed and is_risky:
        verdict = "approved-but-risky"
    else:
        verdict = "unapproved"

    return {
        "ip": ip,
        "port": port,
        "service": service,
        "is_allowed": is_allowed,
        "is_risky": is_risky,
        "verdict": verdict,
    }
