import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional


DEFAULT_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
}

OUI_VENDOR_HINTS = {
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "VirtualBox",
    "00155D": "Microsoft Hyper-V",
    "525400": "QEMU/KVM",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def expand_targets(targets: str) -> List[str]:
    """Expand comma-separated IPs/CIDRs into individual host addresses."""
    expanded: List[str] = []
    for item in [part.strip() for part in targets.split(",") if part.strip()]:
        try:
            network = ipaddress.ip_network(item, strict=False)
            if network.num_addresses == 1:
                expanded.append(str(network.network_address))
            else:
                expanded.extend(str(ip) for ip in network.hosts())
        except ValueError:
            expanded.append(item)
    return list(dict.fromkeys(expanded))


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def tcp_probe(ip: str, port: int, timeout: float) -> Optional[dict]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = grab_banner(sock, port)
            return {
                "port": port,
                "service": DEFAULT_PORTS.get(port, "unknown"),
                "banner": banner,
            }
    except OSError:
        return None


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    try:
        if port in {80, 8080}:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443:
            return "TLS service detected; banner not collected by lightweight scanner"
        else:
            sock.sendall(b"\r\n")
        data = sock.recv(256)
        text = data.decode("utf-8", errors="replace").strip()
        return text[:180] or None
    except OSError:
        return None


def mac_vendor_for(ip: str) -> dict:
    """Best effort local ARP lookup. Usually only works for local LAN hosts."""
    try:
        output = subprocess.check_output(["arp", "-a", ip], text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return {"mac": None, "vendor": None}

    match = re.search(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}", output)
    if not match:
        return {"mac": None, "vendor": None}

    mac = match.group(0).replace("-", ":").upper()
    oui = mac.replace(":", "")[:6]
    return {"mac": mac, "vendor": OUI_VENDOR_HINTS.get(oui)}


def scan_host(ip: str, ports: Iterable[int], timeout: float) -> dict:
    ports = list(ports)
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(32, len(ports) or 1)) as executor:
        futures = [executor.submit(tcp_probe, ip, port, timeout) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    mac_info = mac_vendor_for(ip) if open_ports else {"mac": None, "vendor": None}
    return {
        "ip": ip,
        "hostname": resolve_hostname(ip),
        "mac": mac_info["mac"],
        "mac_vendor": mac_info["vendor"],
        "reachable": bool(open_ports),
        "open_ports": sorted(open_ports, key=lambda item: item["port"]),
    }


def scan_targets(targets: List[str], ports: List[int], timeout: float = 0.8, workers: int = 64) -> dict:
    started_at = utc_now()
    devices = []
    with ThreadPoolExecutor(max_workers=min(workers, len(targets) or 1)) as executor:
        futures = {executor.submit(scan_host, ip, ports, timeout): ip for ip in targets}
        for future in as_completed(futures):
            devices.append(future.result())

    reachable = [device for device in devices if device["reachable"]]
    return {
        "started_at": started_at,
        "finished_at": utc_now(),
        "target_count": len(targets),
        "responsive_count": len(reachable),
        "nonresponsive_hosts": sorted(device["ip"] for device in devices if not device["reachable"]),
        "devices": sorted(reachable, key=sort_target_key),
    }


def sort_target_key(device: dict):
    try:
        address = ipaddress.ip_address(device["ip"])
        return (0, address.version, int(address))
    except ValueError:
        return (1, 0, device["ip"])
