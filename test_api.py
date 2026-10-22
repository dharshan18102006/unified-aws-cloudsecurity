import urllib.request, json

# Test cloud scan
print("=== Testing /api/scan/cloud ===")
body = json.dumps({}).encode()
req = urllib.request.Request(
    "http://localhost:8000/api/scan/cloud",
    method="POST",
    data=body,
    headers={"Content-Type": "application/json"}
)
try:
    resp = urllib.request.urlopen(req, timeout=60)
    data = json.loads(resp.read().decode())
    print("STATUS: 200 OK")
    print("Summary:", json.dumps(data["summary"], indent=2))
    print("Findings count:", len(data["findings"]))
    print("Mode:", data["mode"])
except Exception as e:
    print("CLOUD SCAN FAILED:", e)

print()

# Test secrets scan
print("=== Testing /api/scan/secrets ===")
body2 = json.dumps({"path": "."}).encode()
req2 = urllib.request.Request(
    "http://localhost:8000/api/scan/secrets",
    method="POST",
    data=body2,
    headers={"Content-Type": "application/json"}
)
try:
    resp2 = urllib.request.urlopen(req2, timeout=30)
    data2 = json.loads(resp2.read().decode())
    print("STATUS: 200 OK")
    print("Summary:", json.dumps(data2["summary"], indent=2))
    print("Findings count:", len(data2["findings"]))
except Exception as e:
    print("SECRET SCAN FAILED:", e)
