# PortWatch core exports
from .gate import authorize_target, GateError, GATE_REJECTIONS
from .parser import parse_nmap_xml
from .conformance import check_conformance, RISKY_SERVICES
from .classifier import classify_severity, classify_device, get_base_risk, SERVICE_RISK

__all__ = [
    "authorize_target", "GateError", "GATE_REJECTIONS",
    "parse_nmap_xml",
    "check_conformance", "RISKY_SERVICES",
    "classify_severity", "classify_device", "get_base_risk", "SERVICE_RISK",
]
