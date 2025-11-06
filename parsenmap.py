"""
nmap_xml_reader.py

Utilities to read nmap -oX XML output and extract targets for RTSP scanning.

Usage:
    targets = parse_nmap_xml("nmap_output.xml")
    # targets is a list of dicts:
    #   { "ip": "192.168.1.5", "hostname": "cam1.local", "ports": [ { "port": 554, "service": "rtsp", "product": "SomeCam" }, ... ] }
"""
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional

def parse_nmap_xml(path: str) -> List[Dict]:
    """
    Parse an nmap XML file and return a list of hosts with open ports.

    Each returned dict structure:
    {
      "ip": "192.168.1.5",
      "hostname": "cam1.local",   # may be None
      "ports": [
         { "port": 554, "protocol": "tcp", "state": "open", "service": "rtsp", "product": "ONVIF Camera" },
         ...
      ]
    }

    Only hosts with at least one open port are included.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    result = []
    for host in root.findall("host"):
        # get address (ipv4 or ipv6)
        ip = None
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        # hostname (optional)
        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        # ports
        ports_el = host.find("ports")
        ports = []
        if ports_el is not None:
            for p in ports_el.findall("port"):
                protocol = p.get("protocol")
                portid = int(p.get("portid"))
                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else None
                service_el = p.find("service")
                service = service_el.get("name") if service_el is not None and service_el.get("name") else None
                product = service_el.get("product") if service_el is not None and service_el.get("product") else None
                # Only include open ports
                if state == "open":
                    ports.append({
                        "port": portid,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "product": product
                    })

        if ports:
            result.append({
                "ip": ip,
                "hostname": hostname,
                "ports": ports
            })

    return result


def expand_to_job_list(parsed_hosts: List[Dict], prefer_rtsp_only: bool=True, default_ports=[554, 8554]) -> List[Dict]:
    """
    Convert parsed nmap output to a flat list of scan jobs.

    Returns list of dicts:
      { "ip": "1.2.3.4", "port": 554, "hostname": "cam.local", "service": "rtsp" }

    Behavior:
      - If prefer_rtsp_only=True: include only ports where service == 'rtsp' OR service is None but port in default_ports.
      - Otherwise include all open ports.
    """
    jobs = []
    for host in parsed_hosts:
        ip = host["ip"]
        hostname = host.get("hostname")
        for p in host["ports"]:
            port = p["port"]
            service = (p.get("service") or "").lower()
            product = p.get("product")
            if prefer_rtsp_only:
                if service == "rtsp" or port in default_ports:
                    jobs.append({"ip": ip, "port": port, "hostname": hostname, "service": service, "product": product})
            else:
                jobs.append({"ip": ip, "port": port, "hostname": hostname, "service": service, "product": product})
    return jobs


# Example CLI-style quick test function (not required)
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python nmap_xml_reader.py nmap_output.xml")
        sys.exit(1)
    parsed = parse_nmap_xml(sys.argv[1])
    jobs = expand_to_job_list(parsed)
    for j in jobs:
        print(f"{j['ip']}:{j['port']} ({j.get('service') or 'unknown'}) {j.get('hostname') or ''}")
