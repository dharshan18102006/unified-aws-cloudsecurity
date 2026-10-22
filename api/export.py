"""Vercel Serverless Function: GET /api/export — exports simulated findings as CSV or JSON."""
import sys, os, json, csv, io
from http.server import BaseHTTPRequestHandler
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from scanner import CloudSecurityScanner

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        scanner = CloudSecurityScanner()
        data = scanner._get_simulated_cloud_findings()
        all_findings = data.get("findings", [])

        if 'format=csv' in self.path:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Service", "Severity", "Resource", "Title", "Description", "Compliance"])
            for f in all_findings:
                writer.writerow([
                    f.get("id",""), f.get("service",""), f.get("severity",""),
                    f.get("resource",""), f.get("title",""), f.get("description",""),
                    "; ".join(f.get("compliance", []))
                ])
            csv_bytes = output.getvalue().encode('utf-8')
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition', 'attachment; filename="cloud-security-report.csv"')
            self.send_header('Content-Length', str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
        else:
            body = json.dumps({
                "export_date": datetime.now(timezone.utc).isoformat(),
                "total_findings": len(all_findings),
                "findings": all_findings
            }, default=str).encode('utf-8')
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
