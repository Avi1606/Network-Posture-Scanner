from typing import Iterable, List


SENSITIVE_PORTS = {22, 23, 3389, 445, 3306, 5432}
INSECURE_MANAGEMENT_PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    161: "SNMP",
}
WEAK_SNMP_COMMUNITIES = {"public", "private", "community", "cisco"}


def run_benchmarks(devices: List[dict], firewall: dict, management_subnets: Iterable[str]) -> List[dict]:
    rules = firewall.get("rules", [])
    metadata = firewall.get("metadata", {})
    checks = [
        check_insecure_management_protocols(devices, rules),
        check_ssh_restricted(rules, management_subnets),
        check_weak_snmp(metadata),
        check_sensitive_ports_world(rules),
        check_egress_filtered(rules),
        check_remote_logging(metadata),
        check_default_deny_inbound(rules),
        check_http_management(metadata, devices, rules),
    ]
    return checks


def result(check_id: str, title: str, cis_control: str, passed: bool, evidence: List[str], recommendation: str) -> dict:
    return {
        "check_id": check_id,
        "title": title,
        "cis_control": cis_control,
        "status": "pass" if passed else "fail",
        "evidence": evidence or ["No offending evidence found."],
        "recommendation": recommendation,
    }


def check_insecure_management_protocols(devices: List[dict], rules: List[dict]) -> dict:
    evidence = []
    for device in devices:
        for open_port in device.get("open_ports", []):
            port = open_port.get("port")
            if port in INSECURE_MANAGEMENT_PORTS:
                evidence.append(f"{device['ip']} exposes {INSECURE_MANAGEMENT_PORTS[port]} on port {port}")
    for rule in rules:
        if normalize_port(rule.get("port")) in INSECURE_MANAGEMENT_PORTS and rule.get("action") == "allow":
            evidence.append(rule.get("evidence", str(rule)))
    return result(
        "CIS-NET-001",
        "No insecure management protocols exposed",
        "CIS Controls v8 4.8, 12.3",
        not evidence,
        evidence,
        "Disable Telnet, FTP, HTTP management, and SNMPv1/v2c. Prefer SSH/HTTPS with strong auth.",
    )


def check_ssh_restricted(rules: List[dict], management_subnets: Iterable[str]) -> dict:
    mgmt = set(management_subnets)
    evidence = []
    for rule in ingress_allow_rules(rules):
        if port_matches(rule.get("port"), 22) and rule.get("source") not in mgmt:
            evidence.append(rule.get("evidence", str(rule)))
    return result(
        "CIS-NET-002",
        "SSH is restricted to a management subnet",
        "CIS Controls v8 6.6, 12.8",
        not evidence,
        evidence,
        "Limit SSH ingress to a dedicated management subnet or VPN range.",
    )


def check_weak_snmp(metadata: dict) -> dict:
    communities = metadata.get("snmp_communities", [])
    evidence = [f'SNMP community "{value}" configured' for value in communities if value.lower() in WEAK_SNMP_COMMUNITIES]
    return result(
        "CIS-NET-003",
        "Default or weak SNMP communities are not used",
        "CIS Controls v8 4.1, 12.3",
        not evidence,
        evidence,
        "Remove default SNMP communities and use SNMPv3 with unique credentials.",
    )


def check_sensitive_ports_world(rules: List[dict]) -> dict:
    evidence = []
    for rule in ingress_allow_rules(rules):
        if is_world(rule.get("source")) and any(port_matches(rule.get("port"), port) for port in SENSITIVE_PORTS):
            evidence.append(rule.get("evidence", str(rule)))
    return result(
        "CIS-NET-004",
        "Sensitive ports are not exposed to the internet",
        "CIS Controls v8 12.2, 13.3",
        not evidence,
        evidence,
        "Remove 0.0.0.0/0 ingress to SSH, Telnet, RDP, SMB, and database ports.",
    )


def check_egress_filtered(rules: List[dict]) -> dict:
    evidence = []
    egress = [rule for rule in rules if rule.get("direction") == "egress" and rule.get("action") == "allow"]
    for rule in egress:
        if is_world(rule.get("destination")) and rule.get("port") in {"all", "any"}:
            evidence.append(rule.get("evidence", str(rule)))
    return result(
        "CIS-NET-005",
        "Egress traffic is filtered",
        "CIS Controls v8 12.2, 13.7",
        bool(egress) and not evidence,
        evidence if egress else ["No egress rules were found to prove filtering."],
        "Use default-deny outbound and allow only required destinations and ports.",
    )


def check_remote_logging(metadata: dict) -> dict:
    logging_hosts = metadata.get("logging_hosts", [])
    return result(
        "CIS-NET-006",
        "Remote logging/syslog is enabled",
        "CIS Controls v8 8.2, 8.9",
        bool(logging_hosts),
        [f"Logging host: {host}" for host in logging_hosts],
        "Forward logs to a remote collector or SIEM.",
    )


def check_default_deny_inbound(rules: List[dict]) -> dict:
    deny_rules = [rule for rule in rules if rule.get("direction") == "ingress" and rule.get("action") == "deny"]
    evidence = [rule.get("evidence", str(rule)) for rule in deny_rules]
    return result(
        "CIS-NET-007",
        "Default-deny inbound posture exists",
        "CIS Controls v8 4.4, 12.2",
        bool(deny_rules),
        evidence,
        "Add an explicit final deny rule and only permit required inbound traffic.",
    )


def check_http_management(metadata: dict, devices: List[dict], rules: List[dict]) -> dict:
    evidence = []
    if metadata.get("http_server_enabled"):
        evidence.append("Config contains: ip http server")
    for device in devices:
        if any(open_port.get("port") == 80 for open_port in device.get("open_ports", [])):
            evidence.append(f"{device['ip']} has port 80 open")
    for rule in ingress_allow_rules(rules):
        if port_matches(rule.get("port"), 80):
            evidence.append(rule.get("evidence", str(rule)))
    return result(
        "CIS-NET-008",
        "Unencrypted HTTP management is disabled",
        "CIS Controls v8 3.10, 12.3",
        not evidence,
        evidence,
        "Disable HTTP management and use HTTPS or SSH from trusted management networks.",
    )


def ingress_allow_rules(rules: List[dict]) -> List[dict]:
    return [rule for rule in rules if rule.get("direction") == "ingress" and rule.get("action") == "allow"]


def normalize_port(port):
    if isinstance(port, int):
        return port
    if isinstance(port, str) and port.isdigit():
        return int(port)
    return port


def port_matches(value, desired: int) -> bool:
    value = normalize_port(value)
    if value in {"all", "any"}:
        return True
    if isinstance(value, int):
        return value == desired
    if isinstance(value, str) and "-" in value:
        start, end = value.split("-", 1)
        if start.isdigit() and end.isdigit():
            return int(start) <= desired <= int(end)
    return False


def is_world(value) -> bool:
    return value in {"0.0.0.0/0", "::/0", "any", "Anywhere"}
