from core.gate import authorize_target, GateError, GATE_REJECTIONS
from core.parser import parse_nmap_xml
from core.conformance import check_conformance
from core.classifier import classify_severity, classify_device


def test_full_pipeline_localhost8080():
    import os, json
    from config import Config
    import tempfile

    inst = tempfile.mkdtemp()
    old = Config.INSTANCE_DIR
    try:
        Config.INSTANCE_DIR = inst
        devices = {"127.0.0.1": {"ip": "127.0.0.1"}}
        auths = {"127.0.0.1": {"authorized_by": "admin", "expires_at": "2099-12-31T23:59:59Z"}}
        with open(os.path.join(inst, "devices.json"), "w") as f:
            json.dump(devices, f)
        with open(os.path.join(inst, "authorizations.json"), "w") as f:
            json.dump(auths, f)

        ok, info = authorize_target("127.0.0.1")
        assert ok

        xml_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures", "nmap_xml", "localhost_8080.xml")
        rows = parse_nmap_xml(xml_path=xml_path)
        assert len(rows) == 1

        allowlist = {"127.0.0.1": {"ports": [22, 80], "services": ["ssh", "http"]}}
        results = []
        for r in rows:
            c = check_conformance(r["ip"], r["port"], r["service"], allowlist)
            sev = classify_severity(r["service"], c["verdict"])
            c["severity"] = sev
            c["reason"] = f"{r['port']}/tcp {r['service']} -> {c['verdict']}, severity {sev}"
            results.append(c)

        dev = classify_device(results)
        assert dev["compliant"] is False  # unapproved 8080
        assert dev["unapproved_count"] == 1
        assert results[0]["severity"] == "medium"
        assert results[0]["verdict"] == "unapproved"
    finally:
        Config.INSTANCE_DIR = old
