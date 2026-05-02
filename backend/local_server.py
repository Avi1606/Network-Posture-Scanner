import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
DATA_FILE = ROOT / "results" / "backend_store.json"
API_KEY = os.environ.get("NPS_API_KEY", "dev-key")


def load_store() -> dict:
    if DATA_FILE.exists():
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    return {"scan_runs": []}


def save_store(store: dict):
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(store, indent=2), encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/ingest":
            self.json_response({"error": "not found"}, 404)
            return
        if self.headers.get("X-API-Key") != API_KEY:
            self.json_response({"error": "invalid API key"}, 401)
            return

        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        store = load_store()
        store.setdefault("scan_runs", []).append(payload)
        save_store(store)
        self.json_response({"ok": True, "scan_id": payload.get("scan_id")}, 201)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/devices":
            self.json_response(flatten_latest("devices"))
        elif path == "/firewall-rules":
            self.json_response(flatten_latest("firewall_rules"))
        elif path == "/cis-results":
            self.json_response(flatten_latest("cis_results"))
        elif path == "/scan-runs":
            self.json_response(load_store().get("scan_runs", []))
        elif path == "/" or path.startswith("/app"):
            self.serve_static("index.html")
        else:
            static_path = path.lstrip("/")
            self.serve_static(static_path)

    def serve_static(self, relative_path: str):
        path = (FRONTEND_DIR / relative_path).resolve()
        if FRONTEND_DIR not in path.parents and path != FRONTEND_DIR:
            self.json_response({"error": "invalid path"}, 400)
            return
        if not path.exists() or path.is_dir():
            self.json_response({"error": "not found"}, 404)
            return
        content_type = "text/html"
        if path.suffix == ".css":
            content_type = "text/css"
        elif path.suffix == ".js":
            content_type = "application/javascript"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def json_response(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def latest_scan() -> dict:
    runs = load_store().get("scan_runs", [])
    return runs[-1] if runs else {}


def flatten_latest(key: str):
    return latest_scan().get(key, [])


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Network Posture Scanner backend running at http://127.0.0.1:{port}")
    print(f"API key: {API_KEY}")
    server.serve_forever()


if __name__ == "__main__":
    main()
