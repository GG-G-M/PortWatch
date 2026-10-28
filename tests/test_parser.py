from core.parser import parse_nmap_xml
import os


def test_parse_sample_open():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures", "nmap_xml", "sample_open.xml")
    rows = parse_nmap_xml(xml_path=path)
    assert len(rows) == 3
    ips = {r["ip"] for r in rows}
    assert "192.168.1.10" in ips
    ports = {(r["port"], r["protocol"]) for r in rows}
    assert (22, "tcp") in ports
    assert (80, "tcp") in ports
    assert (3389, "tcp") in ports


def test_parse_service_fields():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures", "nmap_xml", "sample_open.xml")
    rows = parse_nmap_xml(xml_path=path)
    ssh = [r for r in rows if r["port"] == 22][0]
    assert ssh["service"] == "ssh"
    assert ssh["state"] == "open"
    assert "OpenSSH" in ssh["product"]


def test_parse_localhost_8080():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures", "nmap_xml", "localhost_8080.xml")
    rows = parse_nmap_xml(xml_path=path)
    assert len(rows) == 1
    assert rows[0]["ip"] == "127.0.0.1"
    assert rows[0]["port"] == 8080
    assert rows[0]["service"] == "http-alt"
