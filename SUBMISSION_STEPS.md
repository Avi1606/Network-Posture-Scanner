# Assignment 3 Step-by-Step Guide

## Step 1: Understand the Goal

You are submitting a lightweight network posture scanner. The project must show:

- Device discovery.
- Firewall/config collection from at least one source.
- At least 6 benchmark checks.
- JSON result upload to a backend.
- REST APIs to retrieve results.
- A dashboard to view devices, rules, and pass/fail checks.

This repo implements all of those in MVP form.

## Step 2: Start the Backend

Open PowerShell in the project folder:

```powershell
cd "C:\Users\HP\OneDrive\Documents\New project"
python backend/local_server.py
```

Keep this terminal open. It serves both the API and dashboard at:

```text
http://127.0.0.1:8000
```

## Step 3: Run the Scanner

Open a second PowerShell terminal in the same folder and run:

```powershell
python -m scanner.main --targets 127.0.0.1 --config samples/cisco_ios_config.txt --config-type cisco --api-url http://127.0.0.1:8000/ingest --api-key dev-key
```

What this does:

- Scans localhost with a TCP connect scan.
- Captures open ports and service banners when available.
- Parses the Cisco-style sample config.
- Runs 8 CIS-aligned checks.
- Sends the JSON result to the backend.
- Saves a local copy in `results/latest_scan.json`.

## Step 4: View the Dashboard

Open this in your browser:

```text
http://127.0.0.1:8000
```

You should see:

- Discovered devices.
- Open ports/services.
- Firewall rules.
- CIS benchmark results with pass/fail evidence.

## Step 5: Show the REST APIs

Open these URLs during the demo:

```text
http://127.0.0.1:8000/devices
http://127.0.0.1:8000/firewall-rules
http://127.0.0.1:8000/cis-results
http://127.0.0.1:8000/scan-runs
```

These match the assignment requirement for retrieval APIs.

## Step 6: Explain the Benchmark Checks

The scanner runs these checks:

1. No insecure management protocols exposed.
2. SSH is restricted to a management subnet.
3. Weak SNMP communities such as `public` and `private` are not used.
4. Sensitive ports are not exposed to `0.0.0.0/0`.
5. Egress is filtered and not allow-all.
6. Remote logging/syslog is enabled.
7. Default-deny inbound rule exists.
8. Unencrypted HTTP management is disabled.

These are mapped to CIS Controls v8 in the result output.

## Step 7: Explain Non-Responsive Hosts

The scanner uses TCP connect probes instead of raw ICMP/SYN packets. This avoids admin privileges and works on normal laptops.

If a host has no open scanned ports, it is recorded in:

```json
"nonresponsive_hosts": []
```

That lets you explain how unreachable or filtered hosts are handled.

## Step 8: Explain the AWS Design

For local demo speed, the project uses `backend/local_server.py`.

For AWS, the repo includes:

- `backend/lambda_handler.py`
- `infra/template.yaml`

The intended AWS architecture is:

```text
Scanner -> API Gateway -> Lambda -> DynamoDB
```

Deploy with AWS SAM:

```powershell
sam build -t infra/template.yaml
sam deploy --guided
```

Then point the scanner to the API Gateway `/ingest` URL.

## Step 9: What to Submit

Submit the project folder or a GitHub repo containing:

- `scanner/`
- `backend/`
- `frontend/`
- `samples/`
- `infra/`
- `README.md`
- `SUBMISSION_STEPS.md`

Include `results/latest_scan.json` only if your instructor wants proof of a sample run.

## Step 10: Interview Demo Script

Use this flow:

1. “This is a lightweight posture scanner for a target subnet or list of IPs.”
2. Run the backend.
3. Run the scanner command.
4. Open the dashboard.
5. Show discovered devices and ports.
6. Show parsed firewall rules.
7. Show CIS results and explain one pass and one fail.
8. Show `/devices`, `/firewall-rules`, and `/cis-results`.
9. Explain AWS path: API Gateway to Lambda to DynamoDB.
10. Mention future improvements: UDP SNMP probing, credentialed firewall collection, scheduled scans, and stronger authentication.
