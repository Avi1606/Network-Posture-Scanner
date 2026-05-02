import json
import os
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key


TABLE_NAME = os.environ["TABLE_NAME"]
API_KEY = os.environ.get("API_KEY", "CHANGE_ME")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    path = event.get("rawPath") or event.get("path", "/")
    method = event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod", "GET")

    if method == "POST" and path == "/ingest":
        return ingest(event)
    if method == "GET" and path == "/scan-runs":
        return response(scan_runs())
    if method == "GET" and path in {"/devices", "/firewall-rules", "/cis-results"}:
        latest = latest_scan()
        key = {"devices": "devices", "firewall-rules": "firewall_rules", "cis-results": "cis_results"}[path.strip("/")]
        return response(latest.get(key, []))
    return response({"error": "not found"}, 404)


def ingest(event):
    headers = {key.lower(): value for key, value in (event.get("headers") or {}).items()}
    if headers.get("x-api-key") != API_KEY:
        return response({"error": "invalid API key"}, 401)

    body = event.get("body") or "{}"
    payload = json.loads(body)
    scan_id = payload.get("scan_id") or f"scan-{datetime.now(timezone.utc).isoformat()}"
    payload["scan_id"] = scan_id
    table.put_item(
        Item={
            "pk": "SCAN",
            "sk": scan_id,
            "generated_at": payload.get("generated_at"),
            "payload": payload,
        }
    )
    return response({"ok": True, "scan_id": scan_id}, 201)


def scan_runs():
    result = table.query(KeyConditionExpression=Key("pk").eq("SCAN"), ScanIndexForward=False)
    return [item["payload"] for item in result.get("Items", [])]


def latest_scan():
    runs = scan_runs()
    return runs[0] if runs else {}


def response(payload, status=200):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
        },
        "body": json.dumps(payload),
    }
