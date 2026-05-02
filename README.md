# Network Posture Scanner

Lightweight MVP for Assignment 3. It discovers reachable hosts, parses firewall/network-device configuration, runs CIS-aligned security checks, sends JSON results to a backend, and displays everything in a small dashboard.

## What This Project Covers

- Device discovery with a TCP connect scan against common management/service ports.
- Host evidence: IP address, hostname, local MAC/vendor when available, open ports, and service banners.
- Firewall/config parsing from:
  - `samples/cisco_ios_config.txt`
  - `samples/aws_security_group.json`
- 8 CIS Controls v8 aligned benchmark checks.
- HTTPS/API-key ready ingestion contract.
- Local backend for demo plus AWS Lambda/SAM deployment files.
- Frontend dashboard for devices, firewall rules, and benchmark results.

## Quick Demo

1. Start the local backend:

```powershell
python backend/local_server.py
```

2. In another terminal, run a scan against localhost and the included sample config:

```powershell
python -m scanner.main --targets 127.0.0.1 --config samples/cisco_ios_config.txt --config-type cisco --api-url http://127.0.0.1:8000/ingest --api-key dev-key
```

3. Open the dashboard:

```text
http://127.0.0.1:8000
```

4. Optional AWS Security Group sample run:

```powershell
python -m scanner.main --targets 127.0.0.1 --config samples/aws_security_group.json --config-type aws-sg --api-url http://127.0.0.1:8000/ingest --api-key dev-key
```

## Useful Scanner Options

```powershell
python -m scanner.main --targets 192.168.1.0/30 --config samples/cisco_ios_config.txt --config-type cisco --out results/latest_scan.json
```

```powershell
python -m scanner.main --targets 127.0.0.1,192.168.1.10 --ports 22,23,80,443,161,3389 --config samples/cisco_ios_config.txt --config-type cisco
```

## Benchmark Checks

The benchmark engine maps checks to CIS Controls v8:

1. No insecure management protocols exposed.
2. SSH is not open to the world.
3. Weak SNMP communities are not used.
4. Sensitive ports are not open from `0.0.0.0/0`.
5. Egress is filtered and not allow-all.
6. Remote logging/syslog is configured.
7. Default-deny inbound posture exists.
8. Unencrypted HTTP management is not enabled.

## AWS Backend Path

The assignment prefers API Gateway to Lambda to DynamoDB/S3. This repo includes a SAM template in `infra/template.yaml` and a Lambda handler in `backend/lambda_handler.py`.

High-level deployment steps:

```powershell
sam build -t infra/template.yaml
sam deploy --guided
```

After deployment, set the scanner API URL to your API Gateway `/ingest` endpoint and use the configured API key:

```powershell
python -m scanner.main --targets 127.0.0.1 --config samples/cisco_ios_config.txt --config-type cisco --api-url https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/ingest --api-key CHANGE_ME
```

For the interview demo, you can show the local server first, then explain that the Lambda handler has the same REST surface:

- `POST /ingest`
- `GET /devices`
- `GET /firewall-rules`
- `GET /cis-results`
- `GET /scan-runs`

## Project Structure

```text
backend/          Local server and AWS Lambda handler
frontend/         Static dashboard
infra/            AWS SAM template
samples/          Sample Cisco and AWS Security Group configs
scanner/          Discovery, parsing, and benchmark code
results/          Local scan output, created at runtime
```

## Demo Talking Points

- Discovery uses TCP connect scans, so it works without raw socket/admin privileges. Non-responsive hosts are recorded in scan metadata.
- The scanner captures banners opportunistically; some services intentionally do not return banners.
- Benchmark checks use both discovered services and firewall/config evidence.
- Results are sent as JSON with an API key.
- The backend exposes read APIs for the dashboard.
- Improvements: add authenticated AWS SigV4 ingestion, UDP SNMP probing, credentialed Linux firewall collection, scheduled scans, and richer CIS benchmark mappings.
