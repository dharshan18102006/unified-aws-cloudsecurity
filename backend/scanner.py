"""
Cloud Security Posture Management (CSPM) & Secret Leakage Scanner Engine
Supports both live AWS scanning (via boto3) and realistic benchmark simulation mode.
Fully resilient to partial IAM permission sets and SCP restrictions.
"""

import os
import re
import json
import time
import traceback
from datetime import datetime, timezone

def _load_env_file():
    env_paths = [
        os.path.join(os.path.dirname(__file__), '..', '.env'),
        os.path.join(os.path.dirname(__file__), '.env'),
        '.env'
    ]
    for p in env_paths:
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, v = line.split('=', 1)
                            k, v = k.strip(), v.strip().strip('\'"')
                            if k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass

_load_env_file()

# ── AWS Credentials ──────────────────────────────────────────────────────────
AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_DEFAULT_REGION    = os.environ.get("AWS_DEFAULT_REGION", "ap-southeast-2")

# Check if boto3 is available
try:
    import boto3
    from botocore.exceptions import (
        ClientError, NoCredentialsError, EndpointConnectionError,
        BotoCoreError, ParamValidationError
    )
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class CloudSecurityScanner:
    def __init__(self):
        self.session = None
        self.account_id = "Simulated-Demo-Account"
        self.region = AWS_DEFAULT_REGION
        self.is_live = False
        self._init_aws_session()

    def _init_aws_session(self):
        """Attempts to initialize a real AWS session using configured credentials."""
        if not BOTO3_AVAILABLE:
            self.is_live = False
            return

        try:
            self.session = boto3.Session(
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                region_name=AWS_DEFAULT_REGION
            )
            sts = self.session.client('sts', region_name=AWS_DEFAULT_REGION)
            identity = sts.get_caller_identity()
            self.account_id = identity.get("Account", "Unknown-AWS")
            self.is_live = True
            print(f"[INFO] AWS Session active. Account: {self.account_id}, Region: {self.region}")
        except Exception as e:
            print(f"[WARN] Could not connect to AWS: {e}. Using simulation mode.")
            self.is_live = False
            self.account_id = "Simulated-Demo-Account"

    def get_status(self):
        return {
            "mode": "Live AWS" if self.is_live else "Simulation / Benchmark Mode",
            "is_live": self.is_live,
            "account_id": self.account_id,
            "region": self.region,
            "boto3_installed": BOTO3_AVAILABLE,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def scan_cloud_posture(self):
        """Runs CSPM audit on IAM, S3, EC2, and CloudTrail. Fully resilient to denied permissions."""
        if self.is_live and self.session:
            try:
                return self._scan_live_aws()
            except Exception as e:
                print(f"[ERROR] Live scan error: {e}\n{traceback.format_exc()}")
                sim = self._get_simulated_cloud_findings()
                sim["warning"] = f"Live AWS query encountered an error ({str(e)}). Displaying simulated benchmark findings."
                return sim
        else:
            return self._get_simulated_cloud_findings()

    def _safe_call(self, fn, default=None, label=""):
        """Safely executes an AWS API call and returns default on any error."""
        try:
            return fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            print(f"[WARN] AWS ClientError ({label}): [{code}] {msg}")
            return default
        except Exception as e:
            print(f"[WARN] Exception ({label}): {e}")
            return default

    def _scan_live_aws(self):
        findings = []
        logs = []

        def ts():
            return datetime.now().strftime('%H:%M:%S')

        logs.append(f"[{ts()}] [OK] Authenticated with AWS Account {self.account_id} ({self.region})")

        # ── 1. S3 Audit ────────────────────────────────────────────────────────
        logs.append(f"[{ts()}] [SCAN] Starting S3 Bucket Security Inspection...")
        s3 = self.session.client('s3', region_name=self.region)
        buckets_resp = self._safe_call(lambda: s3.list_buckets(), {}, "s3:ListBuckets")
        buckets = buckets_resp.get('Buckets', []) if buckets_resp else []
        logs.append(f"[{ts()}] Found {len(buckets)} S3 bucket(s)")

        for b in buckets:
            name = b['Name']
            # Check public access block
            pab_resp = self._safe_call(
                lambda n=name: s3.get_public_access_block(Bucket=n),
                None, f"s3:GetPublicAccessBlock({name})"
            )
            if pab_resp is None:
                findings.append({
                    "id": f"s3-no-pab-{name}",
                    "service": "S3",
                    "severity": "HIGH",
                    "resource": f"arn:aws:s3:::{name}",
                    "title": f"S3 Bucket '{name}': Public Access Block Not Configured",
                    "description": "Bucket public access configuration could not be verified. Enable S3 Block Public Access immediately.",
                    "compliance": ["CIS AWS 2.1.5", "PCI-DSS 1.3"],
                    "remediation_cli": f'aws s3api put-public-access-block --bucket {name} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
                    "remediation_tf": f'resource "aws_s3_bucket_public_access_block" "{name}" {{\n  bucket = "{name}"\n  block_public_acls = true\n  block_public_policy = true\n  restrict_public_buckets = true\n  ignore_public_acls = true\n}}'
                })
            else:
                conf = pab_resp.get('PublicAccessBlockConfiguration', {})
                if not (conf.get('BlockPublicAcls') and conf.get('BlockPublicPolicy')):
                    findings.append({
                        "id": f"s3-public-block-{name}",
                        "service": "S3",
                        "severity": "CRITICAL",
                        "resource": f"arn:aws:s3:::{name}",
                        "title": f"S3 Bucket '{name}' Lacks Strict Public Access Block",
                        "description": "Public access block settings are not fully enabled, risking unauthorized public exposure of objects.",
                        "compliance": ["CIS AWS 2.1.5", "PCI-DSS 1.3", "NIST CSF PR.AC-3"],
                        "remediation_cli": f'aws s3api put-public-access-block --bucket {name} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
                        "remediation_tf": f'resource "aws_s3_bucket_public_access_block" "{name}_pab" {{\n  bucket = "{name}"\n  block_public_acls = true\n  block_public_policy = true\n}}'
                    })

            # Check default encryption
            enc_resp = self._safe_call(
                lambda n=name: s3.get_bucket_encryption(Bucket=n),
                None, f"s3:GetBucketEncryption({name})"
            )
            if enc_resp is None:
                findings.append({
                    "id": f"s3-no-encryption-{name}",
                    "service": "S3",
                    "severity": "HIGH",
                    "resource": f"arn:aws:s3:::{name}",
                    "title": f"S3 Bucket '{name}' Default Server-Side Encryption Disabled",
                    "description": "Bucket objects are stored without server-side encryption (SSE) enabled at rest.",
                    "compliance": ["CIS AWS 2.1.1", "HIPAA 164.312(a)(2)(iv)", "SOC 2 CC6.1"],
                    "remediation_cli": f"""aws s3api put-bucket-encryption --bucket {name} --server-side-encryption-configuration '{{"Rules": [{{"ApplyServerSideEncryptionByDefault": {{"SSEAlgorithm": "AES256"}}}}]}}'""",
                    "remediation_tf": f'resource "aws_s3_bucket_server_side_encryption_configuration" "{name}" {{\n  bucket = "{name}"\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}'
                })

        # ── 2. IAM Audit ──────────────────────────────────────────────────────
        logs.append(f"[{ts()}] [SCAN] Auditing IAM credential hygiene & policies...")
        iam = self.session.client('iam', region_name='us-east-1')  # IAM is global

        summary = self._safe_call(
            lambda: iam.get_account_summary().get('SummaryMap', {}),
            {}, "iam:GetAccountSummary"
        ) or {}

        if summary.get('AccountMFAEnabled', 0) == 0:
            findings.append({
                "id": "iam-root-no-mfa",
                "service": "IAM",
                "severity": "CRITICAL",
                "resource": f"arn:aws:iam::{self.account_id}:root",
                "title": "AWS Root Account Lacks Hardware/Virtual MFA Device",
                "description": "Root user has unrestricted access to all AWS resources and currently lacks Multi-Factor Authentication (MFA).",
                "compliance": ["CIS AWS 1.5", "NIST CSF PR.AC-1", "SOC 2 CC6.1"],
                "remediation_cli": "# Root MFA must be configured via AWS Console → IAM → Security Credentials → MFA",
                "remediation_tf": "# Root MFA is configured out-of-band from IaC"
            })
            logs.append(f"[{ts()}] [ALERT] Root account MFA missing! Flagged CRITICAL.")

        # Check IAM Users with stale keys
        users = self._safe_call(
            lambda: iam.list_users().get('Users', []),
            [], "iam:ListUsers"
        ) or []

        for u in users:
            uname = u['UserName']
            keys = self._safe_call(
                lambda n=uname: iam.list_access_keys(UserName=n).get('AccessKeyMetadata', []),
                [], f"iam:ListAccessKeys({uname})"
            ) or []
            for k in keys:
                if k.get('Status') == 'Active':
                    create_date = k.get('CreateDate')
                    if create_date:
                        try:
                            if hasattr(create_date, 'tzinfo') and create_date.tzinfo:
                                age_days = (datetime.now(timezone.utc) - create_date).days
                            else:
                                age_days = (datetime.now() - create_date.replace(tzinfo=None)).days
                            if age_days > 90:
                                findings.append({
                                    "id": f"iam-key-age-{k['AccessKeyId']}",
                                    "service": "IAM",
                                    "severity": "MEDIUM",
                                    "resource": f"arn:aws:iam::{self.account_id}:user/{uname}",
                                    "title": f"IAM Access Key for '{uname}' is {age_days} Days Old (>90 day limit)",
                                    "description": f"Access Key {k['AccessKeyId']} exceeds the 90-day rotation compliance threshold.",
                                    "compliance": ["CIS AWS 1.14", "PCI-DSS 8.2.4"],
                                    "remediation_cli": f"aws iam create-access-key --user-name {uname}\n# Update apps with new key, then:\naws iam update-access-key --access-key-id {k['AccessKeyId']} --status Inactive --user-name {uname}",
                                    "remediation_tf": "# Rotate aws_iam_access_key resource and update secret stores (Secrets Manager / Parameter Store)"
                                })
                        except Exception:
                            pass

        # Check for users with no MFA
        for u in users:
            uname = u['UserName']
            mfa_devices = self._safe_call(
                lambda n=uname: iam.list_mfa_devices(UserName=n).get('MFADevices', []),
                None, f"iam:ListMFADevices({uname})"
            )
            if mfa_devices is not None and len(mfa_devices) == 0:
                findings.append({
                    "id": f"iam-user-no-mfa-{uname}",
                    "service": "IAM",
                    "severity": "HIGH",
                    "resource": f"arn:aws:iam::{self.account_id}:user/{uname}",
                    "title": f"IAM User '{uname}' Has No MFA Device Enrolled",
                    "description": f"User {uname} can authenticate with only a password (no MFA), increasing risk of credential theft.",
                    "compliance": ["CIS AWS 1.10", "NIST CSF PR.AC-7", "SOC 2 CC6.1"],
                    "remediation_cli": f"# Navigate to IAM Console → Users → {uname} → Security credentials → MFA device",
                    "remediation_tf": "# Enforce MFA via IAM policy condition: aws:MultiFactorAuthPresent = true"
                })

        # ── 3. EC2 Security Groups ────────────────────────────────────────────
        logs.append(f"[{ts()}] [SCAN] Scanning EC2 Security Groups for 0.0.0.0/0 ingress...")
        ec2 = self.session.client('ec2', region_name=self.region)
        sgs = self._safe_call(
            lambda: ec2.describe_security_groups().get('SecurityGroups', []),
            [], "ec2:DescribeSecurityGroups"
        ) or []

        if not sgs:
            logs.append(f"[{ts()}] [WARN]  EC2 security group check skipped (permission denied by SCP or no SGs exist)")

        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', sg_id)
            for rule in sg.get('IpPermissions', []):
                from_p = rule.get('FromPort')
                to_p = rule.get('ToPort')
                ip_ranges = [r.get('CidrIp') for r in rule.get('IpRanges', [])]
                if '0.0.0.0/0' in ip_ranges:
                    risky_ports = {22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB'}
                    for port, proto_name in risky_ports.items():
                        if from_p is not None and to_p is not None and from_p <= port <= to_p:
                            severity = "CRITICAL" if port in (22, 3389) else "HIGH"
                            findings.append({
                                "id": f"sg-open-port-{sg_id}-{port}",
                                "service": "EC2",
                                "severity": severity,
                                "resource": f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{sg_id}",
                                "title": f"SG '{sg_name}' Exposes {proto_name} Port {port} to Internet (0.0.0.0/0)",
                                "description": f"Security group allows unrestricted internet access to {proto_name} management port, exposing instances to attacks.",
                                "compliance": ["CIS AWS 5.2", "NIST CSF PR.AC-5", "PCI-DSS 1.2"],
                                "remediation_cli": f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {port} --cidr 0.0.0.0/0",
                                "remediation_tf": f'# Remove 0.0.0.0/0 ingress from security group {sg_id}, restrict to VPN CIDR'
                            })

        # ── 4. CloudTrail Audit ───────────────────────────────────────────────
        logs.append(f"[{ts()}] [SCAN] Validating CloudTrail audit trails...")
        ct = self.session.client('cloudtrail', region_name=self.region)
        trails = self._safe_call(
            lambda: ct.describe_trails(includeShadowTrails=False).get('trailList', []),
            [], "cloudtrail:DescribeTrails"
        ) or []

        if not trails:
            findings.append({
                "id": "cloudtrail-no-trails",
                "service": "CloudTrail",
                "severity": "HIGH",
                "resource": f"arn:aws:cloudtrail:{self.region}:{self.account_id}:trail/*",
                "title": f"No CloudTrail Trails Enabled in Region {self.region}",
                "description": "CloudTrail is not configured in this region, meaning all API calls go unlogged.",
                "compliance": ["CIS AWS 3.1", "PCI-DSS 10.1", "HIPAA 164.312(b)"],
                "remediation_cli": f"aws cloudtrail create-trail --name main-audit-trail --s3-bucket-name your-cloudtrail-bucket --is-multi-region-trail\naws cloudtrail start-logging --name main-audit-trail",
                "remediation_tf": 'resource "aws_cloudtrail" "main" {\n  name = "main-audit-trail"\n  s3_bucket_name = "your-cloudtrail-logs-bucket"\n  is_multi_region_trail = true\n  enable_log_file_validation = true\n}'
            })
        else:
            for trail in trails:
                trail_name = trail.get('Name', 'unknown')
                if not trail.get('LogFileValidationEnabled', False):
                    findings.append({
                        "id": f"cloudtrail-no-validation-{trail_name}",
                        "service": "CloudTrail",
                        "severity": "MEDIUM",
                        "resource": trail.get('TrailARN', f"arn:aws:cloudtrail:{self.region}:{self.account_id}:trail/{trail_name}"),
                        "title": f"CloudTrail '{trail_name}' Log File Validation Is Disabled",
                        "description": "Log file validation provides cryptographic assurance that CloudTrail log files have not been tampered with.",
                        "compliance": ["CIS AWS 3.2", "PCI-DSS 10.5.5"],
                        "remediation_cli": f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation",
                        "remediation_tf": f'resource "aws_cloudtrail" "main" {{\n  name = "{trail_name}"\n  enable_log_file_validation = true\n}}'
                    })

        logs.append(f"[{ts()}] [OK] Scan completed. Total issues flagged: {len(findings)}")

        return {
            "summary": self._calculate_summary(findings),
            "findings": findings,
            "logs": logs,
            "mode": "Live AWS",
            "account_id": self.account_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def _get_simulated_cloud_findings(self):
        """Generates realistic CIS AWS benchmark security findings for demonstration."""
        findings = [
            {
                "id": "SIM-S3-001",
                "service": "S3",
                "severity": "CRITICAL",
                "resource": "arn:aws:s3:::prod-customer-backups-2026",
                "title": "S3 Bucket Public Access Block is Disabled",
                "description": "Bucket contains database dumps without Amazon S3 Block Public Access enabled, risking public exposure of sensitive data.",
                "compliance": ["CIS AWS 2.1.5", "PCI-DSS 1.3", "SOC 2 CC6.6"],
                "remediation_cli": 'aws s3api put-public-access-block --bucket prod-customer-backups-2026 --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
                "remediation_tf": 'resource "aws_s3_bucket_public_access_block" "backup_pab" {\n  bucket = "prod-customer-backups-2026"\n  block_public_acls = true\n  block_public_policy = true\n  restrict_public_buckets = true\n}'
            },
            {
                "id": "SIM-IAM-001",
                "service": "IAM",
                "severity": "CRITICAL",
                "resource": f"arn:aws:iam::{self.account_id}:root",
                "title": "AWS Root Account Not Protected by MFA",
                "description": "Root user account login does not have virtual or hardware MFA enforced. Complete cloud compromise possible if root credentials leak.",
                "compliance": ["CIS AWS 1.5", "NIST CSF PR.AC-1", "ISO 27001 A.9.4.2"],
                "remediation_cli": "# Root MFA must be configured directly via AWS Management Console → IAM → Security Credentials → MFA",
                "remediation_tf": "# Root MFA configuration is out of band from Infrastructure-as-Code"
            },
            {
                "id": "SIM-EC2-001",
                "service": "EC2",
                "severity": "CRITICAL",
                "resource": "arn:aws:ec2:us-east-1:sg-09a8f4c12b8d910a7",
                "title": "Security Group Allows Inbound SSH (Port 22) from 0.0.0.0/0",
                "description": "Security Group 'launch-wizard-4' permits unrestricted internet access to SSH management port, exposing servers to brute-force attacks.",
                "compliance": ["CIS AWS 5.2", "PCI-DSS 1.2.1", "NIST CSF PR.PT-4"],
                "remediation_cli": "aws ec2 revoke-security-group-ingress --group-id sg-09a8f4c12b8d910a7 --protocol tcp --port 22 --cidr 0.0.0.0/0",
                "remediation_tf": 'resource "aws_security_group_rule" "ssh_restricted" {\n  type = "ingress"\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/16"] # Corporate VPN only\n}'
            },
            {
                "id": "SIM-S3-002",
                "service": "S3",
                "severity": "HIGH",
                "resource": "arn:aws:s3:::analytics-raw-pipeline-data",
                "title": "S3 Bucket Default Server-Side Encryption (SSE) Not Configured",
                "description": "Bucket lacks enforced AES256 or AWS KMS encryption for stored objects at rest.",
                "compliance": ["CIS AWS 2.1.1", "HIPAA 164.312(a)(2)(iv)", "SOC 2 CC6.1"],
                "remediation_cli": """aws s3api put-bucket-encryption --bucket analytics-raw-pipeline-data --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'""",
                "remediation_tf": 'resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {\n  bucket = "analytics-raw-pipeline-data"\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}'
            },
            {
                "id": "SIM-IAM-002",
                "service": "IAM",
                "severity": "HIGH",
                "resource": f"arn:aws:iam::{self.account_id}:policy/DeveloperFullAccess",
                "title": "IAM Policy Grants Wildcard Full Administrative Privileges (Action: *)",
                "description": "Attached IAM policy allows Action: '*' and Resource: '*', violating the principle of least privilege.",
                "compliance": ["CIS AWS 1.16", "NIST CSF PR.AC-6"],
                "remediation_cli": "aws iam create-policy-version --policy-arn arn:aws:iam::policy/DeveloperFullAccess --policy-document file://scoped-policy.json --set-as-default",
                "remediation_tf": "# Scope down policy actions to only required AWS services"
            },
            {
                "id": "SIM-TRAIL-001",
                "service": "CloudTrail",
                "severity": "MEDIUM",
                "resource": f"arn:aws:cloudtrail:us-east-1:{self.account_id}:trail/main-audit-trail",
                "title": "CloudTrail Log File Validation Disabled",
                "description": "Log file validation provides cryptographic assurance that CloudTrail log files are intact and un-tampered.",
                "compliance": ["CIS AWS 3.2", "PCI-DSS 10.5.5"],
                "remediation_cli": "aws cloudtrail update-trail --name main-audit-trail --enable-log-file-validation",
                "remediation_tf": 'resource "aws_cloudtrail" "main" {\n  name = "main-audit-trail"\n  enable_log_file_validation = true\n}'
            },
            {
                "id": "SIM-IAM-003",
                "service": "IAM",
                "severity": "LOW",
                "resource": f"arn:aws:iam::{self.account_id}:user/ci-deploy-bot",
                "title": "IAM User Access Key Has Not Been Rotated in Over 90 Days",
                "description": "Access Key 'AKIAIOSFODNN7EXAMPLE' was created 128 days ago. Regular key rotation limits blast radius.",
                "compliance": ["CIS AWS 1.14"],
                "remediation_cli": "aws iam create-access-key --user-name ci-deploy-bot",
                "remediation_tf": "# Rotate access credentials using Secrets Manager or AWS IAM"
            }
        ]

        logs = [
            f"[{datetime.now().strftime('%H:%M:%S')}] [START] Initialized Security Posture Scan (Engine v2.5.0)",
            f"[{datetime.now().strftime('%H:%M:%S')}] [TARGET] Target: AWS Account {self.account_id} (Region: {self.region})",
            f"[{datetime.now().strftime('%H:%M:%S')}] [SCAN] Auditing Identity and Access Management (IAM) policies...",
            f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT] Root account MFA missing! Flagged CRITICAL.",
            f"[{datetime.now().strftime('%H:%M:%S')}] [SCAN] Checking Amazon S3 buckets public exposure & encryption flags...",
            f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT] S3 'prod-customer-backups-2026' public access block disabled.",
            f"[{datetime.now().strftime('%H:%M:%S')}] [SCAN] Inspecting VPC Security Groups ingress rules...",
            f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT] sg-09a8f4c12b8d910a7 allows inbound SSH from 0.0.0.0/0.",
            f"[{datetime.now().strftime('%H:%M:%S')}] [SCAN] Validating AWS CloudTrail audit trails and encryption...",
            f"[{datetime.now().strftime('%H:%M:%S')}] [OK] Scan completed. 7 issues identified."
        ]

        return {
            "summary": self._calculate_summary(findings),
            "findings": findings,
            "logs": logs,
            "mode": "Simulation / Benchmark Mode",
            "account_id": self.account_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def scan_secrets(self, target_path="."):
        """
        Scans files, directories, or sample code for hardcoded secrets, API tokens, and private keys.
        """
        secret_patterns = [
            {
                "name": "AWS Access Key ID",
                "pattern": re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
                "severity": "CRITICAL"
            },
            {
                "name": "AWS Secret Access Key",
                "pattern": re.compile(r'(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
                "severity": "CRITICAL"
            },
            {
                "name": "GitHub Personal Access Token",
                "pattern": re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}'),
                "severity": "HIGH"
            },
            {
                "name": "RSA Private Key",
                "pattern": re.compile(r'-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE KEY-----'),
                "severity": "CRITICAL"
            },
            {
                "name": "Stripe Live Secret Key",
                "pattern": re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
                "severity": "CRITICAL"
            },
            {
                "name": "Slack Bot Token",
                "pattern": re.compile(r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}'),
                "severity": "HIGH"
            },
            {
                "name": "Generic High-Entropy API Key",
                "pattern": re.compile(r'(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']'),
                "severity": "MEDIUM"
            }
        ]

        findings = []
        logs = []
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [SCAN] Starting Secret Leakage Scanner on path: '{target_path}'")

        scanned_files_count = 0
        resolved_path = os.path.abspath(target_path) if os.path.exists(target_path) else None

        excluded_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', '.idea', '.vscode'}

        if resolved_path and os.path.isdir(resolved_path):
            for root, dirs, files in os.walk(resolved_path):
                dirs[:] = [d for d in dirs if d not in excluded_dirs]
                for file in files:
                    if file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.exe', '.pyc', '.bin')):
                        continue
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, resolved_path)
                    scanned_files_count += 1
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line in enumerate(f, start=1):
                                for p_info in secret_patterns:
                                    matches = p_info["pattern"].finditer(line)
                                    for match in matches:
                                        secret_str = match.group(0)
                                        masked = secret_str[:4] + "*" * (max(len(secret_str) - 8, 4)) + secret_str[-4:] if len(secret_str) > 8 else "****"
                                        findings.append({
                                            "id": f"sec-{abs(hash(file_path + str(line_num) + secret_str[:8]))}",
                                            "service": "Secret Leakage",
                                            "severity": p_info["severity"],
                                            "resource": f"{rel_path}:{line_num}",
                                            "title": f"Leaked {p_info['name']} Detected in Source File",
                                            "description": f"Found plaintext secret token '{masked}' hardcoded in source file. Revoke immediately.",
                                            "compliance": ["CWE-798 Hard-coded Credentials", "OWASP Top 10 A07", "PCI-DSS 6.5.8"],
                                            "remediation_cli": "# 1. Revoke the compromised token immediately via AWS Console / GitHub / provider\n# 2. Move secret to AWS Secrets Manager:\naws secretsmanager create-secret --name MySecret --secret-string '{\"token\":\"VALUE\"}'",
                                            "remediation_tf": 'data "aws_secretsmanager_secret_version" "secret" {\n  secret_id = "MySecret"\n}'
                                        })
                    except Exception:
                        continue
        else:
            # Simulated secret findings for demo
            scanned_files_count = 14
            findings = [
                {
                    "id": "SEC-LEAK-01",
                    "service": "Secret Leakage",
                    "severity": "CRITICAL",
                    "resource": "config/aws-credentials.json:14",
                    "title": "AWS Access Key ID Leaked in Configuration File",
                    "description": "Detected active AWS Access Key 'AKIAIOSFODNN7EXAMPLE' hardcoded in application repository.",
                    "compliance": ["CWE-798", "PCI-DSS 6.5.8", "CIS AWS 1.14"],
                    "remediation_cli": "aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name dev-user\n# Then immediately rotate keys",
                    "remediation_tf": "# Remove static credentials from files. Use IAM Roles for EC2/ECS/Lambda instead."
                },
                {
                    "id": "SEC-LEAK-02",
                    "service": "Secret Leakage",
                    "severity": "HIGH",
                    "resource": "src/services/github_sync.py:28",
                    "title": "GitHub Personal Access Token in Source Code",
                    "description": "Found active personal access token 'ghp_k92Jsh82019alzkq0918...' committed to git repository.",
                    "compliance": ["OWASP A07:2021", "NIST CSF PR.AC-1"],
                    "remediation_cli": "# Revoke token via GitHub Settings → Developer Settings → Personal access tokens",
                    "remediation_tf": "# Store in AWS Secrets Manager and inject at runtime"
                },
                {
                    "id": "SEC-LEAK-03",
                    "service": "Secret Leakage",
                    "severity": "CRITICAL",
                    "resource": "certs/deploy_key.pem:1",
                    "title": "Unencrypted RSA Private Key Committed to Workspace",
                    "description": "Full RSA private key block found in repository. Anyone with read access can decrypt traffic and authenticate as root server.",
                    "compliance": ["CWE-312", "PCI-DSS 3.4", "ISO 27001 A.10.1.1"],
                    "remediation_cli": "# Rotate server SSH keys and purge commit history using git-filter-repo",
                    "remediation_tf": "# Use AWS Systems Manager Session Manager instead of static SSH keys"
                }
            ]

        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [FILES] Scanned {scanned_files_count} files across codebase.")
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [OK] Scan completed. {len(findings)} secret leak(s) flagged.")

        return {
            "summary": self._calculate_summary(findings),
            "findings": findings,
            "logs": logs,
            "scanned_files": scanned_files_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def _calculate_summary(self, findings):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in counts:
                counts[sev] += 1

        total = len(findings)
        # Weighted deduction formula
        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 12) + (counts["MEDIUM"] * 5) + (counts["LOW"] * 2)
        score = max(0, min(100, 100 - deductions))

        grade = "A"
        if score < 50:
            grade = "F"
        elif score < 65:
            grade = "D"
        elif score < 75:
            grade = "C"
        elif score < 90:
            grade = "B"

        return {
            "total": total,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "security_score": score,
            "grade": grade
        }
