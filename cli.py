from core.gate import authorize_target, GateError
from core.parser import parse_nmap_xml
from core.conformance import check_conformance
from core.classifier import classify_severity, classify_device
from core.scanner import run_scan, build_nmap_args
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python cli.py <ip> [<ip2> ...]")
        sys.exit(1)
    ips = sys.argv[1:]
    try:
        for ip in ips:
            authorize_target(ip)
        print(f"[OK] Gate passed for: {', '.join(ips)}")
        print("[INFO] Ready to scan. Use run_scan() or integrate with app routes.")
    except GateError as e:
        print(f"[REJECTED] code={e.code} reason={e.reason} details={e.details}")
        sys.exit(1)


if __name__ == "__main__":
    main()
