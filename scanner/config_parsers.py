import ipaddress
import json
import re
from pathlib import Path
from typing import Dict, List


def parse_firewall_config(path: str, config_type: str) -> dict:
    if config_type == "cisco":
        return parse_cisco_config(Path(path).read_text(encoding="utf-8"))
    if config_type == "aws-sg":
        return parse_aws_security_group(json.loads(Path(path).read_text(encoding="utf-8")))
    raise ValueError(f"Unsupported config type: {config_type}")


def parse_cisco_config(text: str) -> dict:
    rules: List[dict] = []
    snmp_communities: List[str] = []
    logging_hosts: List[str] = []
    http_server_enabled = False
    ssh_restricted_sources: List[str] = []
    current_acl = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        if line.startswith("ip http server"):
            http_server_enabled = True
        elif line.startswith("logging host"):
            parts = line.split()
            if len(parts) >= 3:
                logging_hosts.append(parts[-1])
        elif line.startswith("snmp-server community"):
            parts = line.split()
            if len(parts) >= 3:
                snmp_communities.append(parts[2])
        elif line.startswith("access-list"):
            parsed = parse_cisco_acl_line(line)
            if parsed:
                rules.append(parsed)
        elif line.startswith("ip access-list"):
            current_acl = line
        elif current_acl and re.match(r"^(permit|deny)\s+", line):
            parsed = parse_cisco_acl_line(f"{current_acl} {line}")
            if parsed:
                rules.append(parsed)
        elif "transport input ssh" in line:
            ssh_restricted_sources.append("vty transport input ssh")

    return {
        "source_type": "cisco",
        "rules": rules,
        "metadata": {
            "snmp_communities": snmp_communities,
            "logging_hosts": logging_hosts,
            "http_server_enabled": http_server_enabled,
            "ssh_transport_configured": bool(ssh_restricted_sources),
        },
    }


def parse_cisco_acl_line(line: str) -> dict:
    action_match = re.search(r"\b(permit|deny)\b\s+(\w+)", line)
    if not action_match:
        return {}

    raw_action = action_match.group(1)
    action = "allow" if raw_action == "permit" else "deny"
    protocol = action_match.group(2)
    tail = line[action_match.end() :].strip().split()
    source, tail = parse_cisco_address(tail)
    destination, tail = parse_cisco_address(tail)
    port = "any"

    if len(tail) >= 2 and tail[0] == "eq":
        port = service_to_port(tail[1])

    return {
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "port": port,
        "action": action,
        "direction": "egress" if re.search(r"\b(OUTBOUND|EGRESS|OUT)\b", line, re.IGNORECASE) else "ingress",
        "evidence": line,
    }


def parse_cisco_address(tokens: List[str]):
    if not tokens:
        return "any", []
    first = tokens.pop(0)
    if first == "any":
        return "0.0.0.0/0", tokens
    if first == "host" and tokens:
        return f"{tokens.pop(0)}/32", tokens
    if tokens:
        wildcard = tokens.pop(0)
        try:
            network = wildcard_to_cidr(first, wildcard)
            return network, tokens
        except ValueError:
            return first, tokens
    return first, tokens


def wildcard_to_cidr(address: str, wildcard: str) -> str:
    wildcard_int = int(ipaddress.IPv4Address(wildcard))
    netmask_int = wildcard_int ^ 0xFFFFFFFF
    prefix = bin(netmask_int).count("1")
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def service_to_port(value: str):
    names = {
        "ssh": 22,
        "telnet": 23,
        "ftp": 21,
        "http": 80,
        "https": 443,
        "snmp": 161,
        "rdp": 3389,
        "mysql": 3306,
        "postgresql": 5432,
        "www": 80,
    }
    return names.get(value.lower(), int(value) if value.isdigit() else value)


def parse_aws_security_group(document: Dict) -> dict:
    rules = []
    for group in document.get("SecurityGroups", []):
        group_name = group.get("GroupName", "unknown")
        for permission in group.get("IpPermissions", []):
            rules.extend(aws_permission_to_rules(group_name, permission, "ingress"))
        for permission in group.get("IpPermissionsEgress", []):
            rules.extend(aws_permission_to_rules(group_name, permission, "egress"))

    return {
        "source_type": "aws-sg",
        "rules": rules,
        "metadata": {
            "snmp_communities": [],
            "logging_hosts": [],
            "http_server_enabled": False,
            "ssh_transport_configured": False,
        },
    }


def aws_permission_to_rules(group_name: str, permission: dict, direction: str) -> List[dict]:
    protocol = permission.get("IpProtocol", "-1")
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    port = "all" if protocol == "-1" else from_port if from_port == to_port else f"{from_port}-{to_port}"
    cidrs = [item.get("CidrIp") for item in permission.get("IpRanges", []) if item.get("CidrIp")]
    cidrs += [item.get("CidrIpv6") for item in permission.get("Ipv6Ranges", []) if item.get("CidrIpv6")]

    rules = []
    for cidr in cidrs or ["security-group-reference"]:
        rules.append(
            {
                "source": cidr if direction == "ingress" else group_name,
                "destination": group_name if direction == "ingress" else cidr,
                "protocol": "all" if protocol == "-1" else protocol,
                "port": port,
                "action": "allow",
                "direction": direction,
                "evidence": f"{group_name} {direction} {protocol} {port} {cidr}",
            }
        )
    return rules
