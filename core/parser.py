# PortWatch Nmap XML parser
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional


def parse_nmap_xml(xml_path: str = None, xml_data: str = None) -> List[Dict[str, Any]]:
    """Parse Nmap XML into normalized rows.

    Returns a list of dicts with keys:
    - ip: IPv4/IPv6 address
    - hostname: PTR hostname if present
    - protocol: tcp/udp
    - port: int
    - state: open/closed/filtered/etc
    - service: service name
    - product: product string if probed
    - version: version string if probed
    - extrainfo: extra info if probed
    """
    if xml_path:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    elif xml_data:
        root = ET.fromstring(xml_data)
    else:
        raise ValueError("Either xml_path or xml_data must be provided")

    results = []
    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            continue
        ip_addr = addr_elem.attrib.get("addr", "").strip()

        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name", "").strip()

        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            protocol = port.attrib.get("protocol", "tcp").strip()
            portid = port.attrib.get("portid", "").strip()
            try:
                port_num = int(portid)
            except ValueError:
                continue
            state_elem = port.find("state")
            state = state_elem.attrib.get("state", "") if state_elem is not None else ""
            svc_elem = port.find("service")
            service = ""
            product = ""
            version = ""
            extrainfo = ""
            if svc_elem is not None:
                service = svc_elem.attrib.get("name", "") or ""
                product = svc_elem.attrib.get("product", "") or ""
                version = svc_elem.attrib.get("version", "") or ""
                extrainfo = svc_elem.attrib.get("extrainfo", "") or ""
            results.append({
                "ip": ip_addr,
                "hostname": hostname,
                "protocol": protocol,
                "port": port_num,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
            })
    return results
