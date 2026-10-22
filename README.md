# ShieldCloud - Cloud Security Posture Management (CSPM) & Secret Leakage Prevention

An enterprise-grade Cloud Security Operations Platform designed to detect cloud misconfigurations (CIS AWS Benchmarks v1.4, NIST, PCI-DSS) and hardcoded secret leaks in source code and repositories.

---

## 🛡️ Key Features

- **Live & Simulation Engine**:
  - Automatically connects to your local AWS profile via `boto3` without exposing credentials.
  - Seamlessly falls back to simulated CIS AWS benchmark telemetry if AWS credentials are not configured or offline.
- **Cloud Security Posture Management (CSPM)**:
  - **Amazon S3**: Detects public access block vulnerabilities, unencrypted buckets, and public ACL risks.
  - **AWS IAM**: Identifies root account missing MFA, access keys older than 90 days, and wildcard `*` admin policies.
  - **Amazon EC2 / VPC**: Audits Security Groups allowing `0.0.0.0/0` ingress on management ports (SSH 22, RDP 3389).
  - **AWS CloudTrail**: Verifies cryptographic log file validation and multi-region logging.
- **Secret Leakage Prevention**:
  - Scans files and codebases for hardcoded credentials: AWS Access Keys, Secret Keys, GitHub PATs, Stripe API keys, Slack tokens, and Private RSA keys.
- **Remediation Blueprints**:
  - 1-Click copyable **AWS CLI** commands and **Terraform (IaC)** code fixes for every detected vulnerability.
- **Compliance & Analytics**:
  - Live compliance mapping for CIS AWS Benchmark, NIST CSF, PCI-DSS v4.0, and SOC 2 Type II.
  - Real-time severity breakdown donut chart and service risk distribution bar chart.
  - Instant CSV / JSON audit report export.

---

## 🔒 Crucial Security Notice: AWS Credentials & Provisioning

> **IMPORTANT:** Never share your AWS root account credentials, access keys, or secret access keys directly in chat or public forums.

### How ShieldCloud Handles AWS Credentials Safely:
1. **Local Execution**: The backend runs entirely on your local machine (`http://localhost:8000`).
2. **Standard AWS CLI Integration**: It automatically uses your local credentials (`~/.aws/credentials`) configured via standard `aws configure`.
3. **Least Privilege Principle**: Create an IAM user or role with **read-only audit permissions** (`SecurityAudit` or `ReadOnlyAccess`). The scanner never modifies or deletes your cloud resources.

```bash
# Attach read-only security audit permissions to your scanner user:
aws iam attach-user-policy --user-name SecurityScannerBot --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

---

## 🚀 Quick Start Guide

### 1. Launch the Backend Server
Double-click `run.bat` or run in your terminal:
```powershell
python backend\server.py
```
*Server starts at `http://localhost:8000`.*

### 2. Open the Dashboard
Open your web browser and navigate to:
```text
http://localhost:8000
```
Or open `frontend/index.html` directly in any modern browser.

---

## 📡 REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Returns AWS connection status, account ID, and region |
| `POST` | `/api/scan/cloud` | Executes CSPM audit across S3, IAM, EC2, and CloudTrail |
| `POST` | `/api/scan/secrets` | Scans workspace/code for hardcoded credentials |
| `GET` | `/api/findings` | Returns consolidated findings with severity and compliance |
| `POST` | `/api/remediate` | Returns AWS CLI & Terraform remediation snippets |
| `GET` | `/api/export?format=csv` | Downloads CSV security audit report |
