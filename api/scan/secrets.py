"""Vercel Serverless Function: POST /api/scan/secrets"""
import sys, os, json
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lib'))
from scanner import CloudSecurityScanner

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = {}
            if length > 0:
                try:
                    body = json.loads(self.rfile.read(length).decode('utf-8'))
                except Exception:
                    pass

            scanner = CloudSecurityScanner()
            # On Vercel, filesystem scanning only works in the /tmp directory
            target = body.get("path", "/tmp")
            result = scanner.scan_secrets(target)
            self._respond(200, result)
        except Exception as e:
            self._respond(500, {"error": "Secrets scan failed", "detail": str(e)})

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def _respond(self, code, data):
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(code)
        self._cors()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
