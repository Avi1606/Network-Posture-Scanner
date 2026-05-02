import argparse
import json
import sys
import urllib.request
from pathlib import Path

from scanner.benchmarks import run_benchmarks
from scanner.config_parsers import parse_firewall_config
from scanner.network_scan import DEFAULT_PORTS, expand_targets, scan_targets, utc_now


def parse_args():
    parser = argparse.ArgumentParser(description="Network posture scanner")
    parser.add_argument("--targets", required=True, help="Comma-separated IPs/hosts or CIDR ranges")
    parser.add_argument("--ports", default=",".join(str(port) for port in DEFAULT_PORTS), help="Comma-separated TCP ports")
    parser.add_argument("--config", required=True, help="Firewall/network config path")
    parser.add_argument("--config-type", choices=["cisco", "aws-sg"], default="cisco")
    parser.add_argument("--management-subnet", action="append", default=["10.0.0.0/24"], help="Allowed management subnet")
    parser.add_argument("--timeout", type=float, default=0.8)
    parser.add_argument("--api-url", help="Backend ingestion URL")
    parser.add_argument("--api-key", default="dev-key")
    parser.add_argument("--out", default="results/latest_scan.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    targets = expand_targets(args.targets)
    ports = [int(port.strip()) for port in args.ports.split(",") if port.strip()]

    discovery = scan_targets(targets, ports, args.timeout)
    firewall = parse_firewall_config(args.config, args.config_type)
    cis_results = run_benchmarks(discovery["devices"], firewall, args.management_subnet)
    payload = {
        "scan_id": f"scan-{utc_now()}",
        "generated_at": utc_now(),
        "scanner": {
            "method": "TCP connect scan",
            "ports": ports,
            "targets": targets,
            "nonresponsive_hosts": discovery["nonresponsive_hosts"],
        },
        "devices": discovery["devices"],
        "firewall_rules": firewall["rules"],
        "firewall_metadata": firewall["metadata"],
        "cis_results": cis_results,
        "summary": {
            "target_count": discovery["target_count"],
            "responsive_count": discovery["responsive_count"],
            "rule_count": len(firewall["rules"]),
            "checks_passed": sum(1 for check in cis_results if check["status"] == "pass"),
            "checks_failed": sum(1 for check in cis_results if check["status"] == "fail"),
        },
    }

    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote scan results to {output_path}")

    if args.api_url:
        send_to_backend(args.api_url, args.api_key, payload)
        print(f"Sent scan results to {args.api_url}")

    failed = payload["summary"]["checks_failed"]
    print(f"Completed scan: {payload['summary']['responsive_count']} hosts responsive, {failed} checks failed")
    return 0


def send_to_backend(api_url: str, api_key: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        api_url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status >= 300:
            raise RuntimeError(f"Backend returned HTTP {response.status}")


if __name__ == "__main__":
    sys.exit(main())
