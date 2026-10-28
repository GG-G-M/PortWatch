# PortWatch scanner wrapper
import os
import subprocess
import tempfile
from typing import List, Dict, Any

from core.gate import authorize_target, GateError


def build_nmap_args(ips: List[str], ports: str = None, timeout: int = 300) -> List[str]:
    args = ["nmap", "-T3", "-sT", "--open", "-oX", "-"]
    if ports:
        args.extend(["-p", ports])
    args.extend(ips)
    return args


def run_scan(ips: List[str], ports: str = None, timeout: int = 300) -> str:
    """Run Nmap scan only after authorization checks.

    All IPs must pass the gate. Returns XML string.
    """
    for ip in ips:
        authorize_target(ip)  # will raise GateError if not allowed

    args = build_nmap_args(ips, ports, timeout)
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
            check=False,
        )
        return proc.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        raise
    except FileNotFoundError:
        raise RuntimeError("nmap not found in PATH. Install Nmap or ensure it's accessible.")


def scan_to_file(ips: List[str], output_path: str, ports: str = None, timeout: int = 300) -> str:
    xml = run_scan(ips, ports, timeout)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml)
    return output_path
