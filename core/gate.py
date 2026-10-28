# PortWatch authorization gate
import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from config import Config

GATE_REJECTIONS = {
    1: "MISSING_AUTHORIZATION",
    2: "NOT_REGISTERED",
    3: "OUT_OF_SCOPE_RANGE",
    4: "NON_PRIVATE_RANGE",
    5: "INVALID_IP",
    6: "DISALLOWED_PROTOCOL",
    7: "EMPTY_TARGET",
    8: "EXPIRED_AUTHORIZATION",
}

class GateError(Exception):
    def __init__(self, code: int, reason: str, details: Dict[str, Any] = None):
        self.code = code
        self.reason = reason
        self.details = details or {}
        super().__init__(f"{code}:{reason} {self.details}")


def _load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _log_rejection(ip: str, code: int, reason: str, details: Dict[str, Any]):
    log_path = os.path.join(Config.INSTANCE_DIR, "gate_rejections.log")
    os.makedirs(Config.INSTANCE_DIR, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target_ip": ip,
        "code": code,
        "reason": reason,
        "details": details,
    }
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def authorize_target(ip_str: str, db_path: str = None, auth_db_path: str = None) -> Tuple[bool, Dict[str, Any]]:
    db_path = db_path or os.path.join(Config.INSTANCE_DIR, "devices.json")
    auth_db_path = auth_db_path or os.path.join(Config.INSTANCE_DIR, "authorizations.json")

    if ip_str is None or str(ip_str).strip() == "":
        _log_rejection("", 7, GATE_REJECTIONS[7], {})
        raise GateError(7, GATE_REJECTIONS[7], {})

    ip_str = str(ip_str).strip()

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        _log_rejection(ip_str, 5, GATE_REJECTIONS[5], {"input": ip_str})
        raise GateError(5, GATE_REJECTIONS[5], {"input": ip_str})

    if not ip_obj.is_private:
        _log_rejection(ip_str, 4, GATE_REJECTIONS[4], {"is_private": False})
        raise GateError(4, GATE_REJECTIONS[4], {"is_private": False})

    allowed = False
    for p in Config.SCAN_PREFIXES:
        try:
            if ip_obj in ipaddress.ip_network(p, strict=False):
                allowed = True
                break
        except Exception:
            continue
    if not allowed:
        _log_rejection(ip_str, 3, GATE_REJECTIONS[3], {"prefixes": Config.SCAN_PREFIXES})
        raise GateError(3, GATE_REJECTIONS[3], {"prefixes": Config.SCAN_PREFIXES})

    devices = _load_json(db_path, {})
    device_map = devices if isinstance(devices, dict) and "devices" not in devices else devices.get("devices", {})
    if ip_str not in device_map:
        _log_rejection(ip_str, 2, GATE_REJECTIONS[2], {})
        raise GateError(2, GATE_REJECTIONS[2], {})

    auths = _load_json(auth_db_path, {})
    auth_map = auths if isinstance(auths, dict) and "authorizations" not in auths else auths.get("authorizations", {})
    auth = auth_map.get(ip_str) or auth_map.get(ip_str.lower())

    if not auth:
        _log_rejection(ip_str, 1, GATE_REJECTIONS[1], {})
        raise GateError(1, GATE_REJECTIONS[1], {})

    expires = auth.get("expires_at") or auth.get("expires")
    if expires:
        try:
            exp = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if exp < now:
                _log_rejection(ip_str, 8, GATE_REJECTIONS[8], {"expires_at": expires})
                raise GateError(8, GATE_REJECTIONS[8], {"expires_at": expires})
        except GateError:
            raise
        except Exception:
            pass

    return True, {"ip": ip_str, "authorized_by": auth.get("authorized_by"), "expires_at": expires}
