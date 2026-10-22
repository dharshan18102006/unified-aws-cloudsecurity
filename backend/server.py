"""
REST API Backend Server for Cloud Security Posture & Secret Leakage Prevention Platform
Handles CORS, live/simulated AWS scans, secret detection, and serves dashboard assets.
Zero external server dependencies required - runs natively on Python 3.
"""

import os
import sys
import json
import csv
import io
import traceback
import mimetypes
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from scanner import CloudSecurityScanner
    scanner = CloudSecurityScanner()
    print(f"[OK] Scanner initialized. Mode: {scanner.get_status()['mode']}")
except Exception as e:
    print(f"[CRITICAL] Failed to initialize scanner: {e}")
    traceback.print_exc()
    sys.exit(1)

# Pre-populate with simulated findings
last_scan_results = {
    "cloud": scanner._get_simulated_cloud_findings(),
    "secrets": None
}

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class SecurityApiHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress default access logs, we handle our own
        pass

    def do_GET(self):
        try:
            self._handle_get()
        except Exception as e:
            print(f"[ERROR] GET {self.path}: {e}\n{traceback.format_exc()}")
            self._send_json(500, {"error": "Internal server error", "detail": str(e)})

    def _handle_get(self):
        path = self.path.split('?')[0]

        if path == '/api/status':
            self._send_json(200, scanner.get_status())

        elif path in ('/api/summary', '/api/findings'):
            all_findings = []
            if last_scan_results.get("cloud"):
                all_findings.extend(last_scan_results["cloud"].get("findings", []))
            if last_scan_results.get("secrets"):
                all_findings.extend(last_scan_results["secrets"].get("findings", []))

            summary = scanner._calculate_summary(all_findings)
            if path == '/api/summary':
                self._send_json(200, summary)
            else:
                self._send_json(200, {
                    "summary": summary,
                    "findings": all_findings,
                    "count": len(all_findings)
                })

        elif path == '/api/export':
            all_findings = []
            if last_scan_results.get("cloud"):
                all_findings.extend(last_scan_results["cloud"].get("findings", []))
            if last_scan_results.get("secrets"):
                all_findings.extend(last_scan_results["secrets"].get("findings", []))

            query = self.path
            if 'format=csv' in query:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["ID", "Service", "Severity", "Resource", "Title", "Description", "Compliance"])
                for f in all_findings:
                    writer.writerow([
                        f.get("id", ""),
                        f.get("service", ""),
                        f.get("severity", ""),
                        f.get("resource", ""),
                        f.get("title", ""),
                        f.get("description", ""),
                        "; ".join(f.get("compliance", []))
                    ])
                csv_bytes = output.getvalue().encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv')
                self.send_header('Content-Disposition', 'attachment; filename="cloud-security-report.csv"')
                self.send_header('Content-Length', str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
            else:
                self._send_json(200, {
                    "export_date": datetime.now(timezone.utc).isoformat(),
                    "total_findings": len(all_findings),
                    "findings": all_findings
                })

        else:
            # Serve static frontend files
            frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
            requested_path = path.lstrip('/')
            if not requested_path or requested_path == '/':
                requested_path = 'index.html'

            target_file = os.path.join(frontend_dir, requested_path)
            if os.path.exists(target_file) and os.path.isfile(target_file):
                mime, _ = mimetypes.guess_type(target_file)
                mime = mime or 'application/octet-stream'
                with open(target_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json(404, {"error": "Endpoint or resource not found", "path": path})

    def do_POST(self):
        try:
            self._handle_post()
        except Exception as e:
            print(f"[ERROR] POST {self.path}: {e}\n{traceback.format_exc()}")
            self._send_json(500, {"error": "Internal server error", "detail": str(e)})

    def _handle_post(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = {}
        if content_length > 0:
            try:
                raw = self.rfile.read(content_length)
                body = json.loads(raw.decode('utf-8'))
            except Exception:
                body = {}

        print(f"[POST] {self.path}")

        if self.path == '/api/scan/cloud':
            print("[INFO] Starting live cloud CSPM scan...")
            result = scanner.scan_cloud_posture()
            last_scan_results["cloud"] = result
            print(f"[INFO] Cloud scan done. {result['summary']['total']} findings.")
            self._send_json(200, result)

        elif self.path == '/api/scan/secrets':
            target_path = body.get("path", ".")
            print(f"[INFO] Starting secrets scan on path: {target_path}")
            result = scanner.scan_secrets(target_path)
            last_scan_results["secrets"] = result
            print(f"[INFO] Secrets scan done. {result['summary']['total']} findings.")
            self._send_json(200, result)

        elif self.path == '/api/remediate':
            finding_id = body.get("id")
            all_findings = []
            if last_scan_results.get("cloud"):
                all_findings.extend(last_scan_results["cloud"].get("findings", []))
            if last_scan_results.get("secrets"):
                all_findings.extend(last_scan_results["secrets"].get("findings", []))

            target = next((f for f in all_findings if f.get("id") == finding_id), None)
            if target:
                self._send_json(200, {
                    "id": target["id"],
                    "title": target["title"],
                    "resource": target["resource"],
                    "remediation_cli": target.get("remediation_cli", "# Manual verification required"),
                    "remediation_tf": target.get("remediation_tf", "# Terraform configuration not available"),
                    "status": "ready"
                })
            else:
                self._send_json(404, {"error": "Finding not found", "id": finding_id})
        else:
            self._send_json(404, {"error": "Unknown POST route", "path": self.path})

    def _send_json(self, status_code, data):
        try:
            response_bytes = json.dumps(data, indent=2, default=str).encode('utf-8')
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        except Exception as e:
            print(f"[ERROR] Failed to send JSON response: {e}")


def run_server(port=8000):
    server_address = ('', port)
    httpd = ThreadedHTTPServer(server_address, SecurityApiHandler)
    status = scanner.get_status()
    print(f"\n{'='*62}")
    print(f"  [*] ShieldCloud Security Platform")
    print(f"  [>] Listening on: http://localhost:{port}")
    print(f"  [>] Dashboard:    http://localhost:{port}/index.html")
    print(f"  [>] AWS Mode:     {status['mode']}")
    print(f"  [>] Account ID:   {status['account_id']}")
    print(f"  [>] Region:       {status['region']}")
    print(f"{'='*62}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down server gracefully...")
        httpd.server_close()


if __name__ == '__main__':
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
