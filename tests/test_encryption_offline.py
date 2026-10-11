"""Offline regression test for encryption.py. No AWS calls.

Run: python test_encryption_offline.py
"""

import sys
from botocore.exceptions import ClientError

from plexavo.checks import encryption


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class FakeEC2:
    def __init__(self, volumes):
        self._pages = [{"Volumes": volumes}]

    def get_paginator(self, name):
        return FakePaginator(self._pages)


class FakeRDS:
    def __init__(self, db_instances):
        self._pages = [{"DBInstances": db_instances}]

    def get_paginator(self, name):
        return FakePaginator(self._pages)


class FakeS3:
    def __init__(self, encryption_configs=None, bucket_names=None, denied=None):
        self._encryption_configs = encryption_configs or {}
        self._bucket_names = bucket_names or list(self._encryption_configs)
        self._denied = denied or set()

    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in self._bucket_names]}

    def get_bucket_encryption(self, Bucket):
        if Bucket in self._denied:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetBucketEncryption")
        if Bucket not in self._encryption_configs:
            raise ClientError(
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "x"}},
                "GetBucketEncryption",
            )
        return {"ServerSideEncryptionConfiguration": self._encryption_configs[Bucket]}


class FakeSession:
    """Only ENC-31 matters for the AccessDenied regression below, so ec2/rds
    come back empty rather than being modeled in detail."""

    def __init__(self, s3):
        self._s3 = s3

    def client(self, name):
        if name == "s3":
            return self._s3
        if name == "ec2":
            return FakeEC2([])
        if name == "rds":
            return FakeRDS([])
        raise AssertionError(f"unexpected client: {name}")


failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


print("=== ENC-29: unencrypted EBS volume ===")
volumes = [{"VolumeId": "vol-unenc", "Encrypted": False, "Attachments": [{"InstanceId": "i-abc123"}]}]
findings = encryption.check_29_unencrypted_ebs_volumes(FakeEC2(volumes))
assert_true(any(f.resource_arn == "vol-unenc" for f in findings), "Fires on Encrypted=False")
assert_true(any("i-abc123" in f.raw_detail for f in findings), "Names the attached instance")

print("\n=== FALSE POSITIVE GUARD: encrypted EBS volume ===")
volumes = [{"VolumeId": "vol-enc", "Encrypted": True, "Attachments": []}]
findings = encryption.check_29_unencrypted_ebs_volumes(FakeEC2(volumes))
assert_true(len(findings) == 0, "Does NOT fire on Encrypted=True")

print("\n=== ENC-29: unattached unencrypted volume still fires ===")
volumes = [{"VolumeId": "vol-orphan", "Encrypted": False, "Attachments": []}]
findings = encryption.check_29_unencrypted_ebs_volumes(FakeEC2(volumes))
assert_true(any("not attached to any instance" in f.raw_detail for f in findings),
            "Still fires on an unattached unencrypted volume, correctly labeled")

print("\n=== ENC-30: unencrypted RDS instance ===")
dbs = [{"DBInstanceIdentifier": "db-unenc", "Engine": "mysql", "StorageEncrypted": False,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db-unenc"}]
findings = encryption.check_30_unencrypted_rds_instances(FakeRDS(dbs))
assert_true(any("db-unenc" in f.resource_arn for f in findings), "Fires on StorageEncrypted=False")

print("\n=== FALSE POSITIVE GUARD: encrypted RDS instance ===")
dbs = [{"DBInstanceIdentifier": "db-enc", "Engine": "postgres", "StorageEncrypted": True,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db-enc"}]
findings = encryption.check_30_unencrypted_rds_instances(FakeRDS(dbs))
assert_true(len(findings) == 0, "Does NOT fire on StorageEncrypted=True")

print("\n=== ENC-31: bucket with no encryption configuration ===")
s3 = FakeS3(encryption_configs={})
findings = encryption.check_31_s3_missing_default_encryption(s3, ["no-enc-bucket"])
assert_true(any(f.check_id == "ENC-31" for f in findings), "Fires when GetBucketEncryption raises NotFound")

print("\n=== FALSE POSITIVE GUARD: bucket with default encryption configured ===")
s3 = FakeS3(encryption_configs={"enc-bucket": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}})
findings = encryption.check_31_s3_missing_default_encryption(s3, ["enc-bucket"])
assert_true(len(findings) == 0, "Does NOT fire when a default encryption config exists")

print("\n=== REGRESSION: an AccessDenied bucket must not crash the whole scan ===")
s3 = FakeS3(encryption_configs={}, bucket_names=["no-enc-bucket", "denied-bucket"],
            denied={"denied-bucket"})
skipped = set()
try:
    findings = encryption.check_31_s3_missing_default_encryption(
        s3, ["no-enc-bucket", "denied-bucket"], skipped)
except ClientError:
    assert_true(False, "ENC-31: AccessDenied on 'denied-bucket' incorrectly raised and crashed the scan")
else:
    assert_true(True, "ENC-31: AccessDenied on 'denied-bucket' does not raise")
    assert_true("denied-bucket" in skipped, "ENC-31: 'denied-bucket' recorded in skipped set")
    assert_true(not any("denied-bucket" in f.resource_arn for f in findings),
                "ENC-31: never fabricates a 'no encryption' finding for the bucket it couldn't read")
    assert_true(any("no-enc-bucket" in f.resource_arn for f in findings),
                "ENC-31: still evaluates the reachable bucket instead of aborting")

print("\n=== REGRESSION: run_all() returns (findings, skipped_buckets) and keeps scanning past AccessDenied ===")
s3 = FakeS3(encryption_configs={}, bucket_names=["no-enc-bucket", "denied-bucket"],
            denied={"denied-bucket"})
findings, skipped_buckets = encryption.run_all(FakeSession(s3))
assert_true(skipped_buckets == ["denied-bucket"], "run_all() reports the denied bucket in skipped_buckets")
assert_true(any(f.check_id == "ENC-31" and "no-enc-bucket" in f.resource_arn for f in findings),
            "run_all() still evaluates the reachable bucket instead of aborting the whole scan")
assert_true(not any("denied-bucket" in f.resource_arn for f in findings),
            "run_all() never fabricates a finding for a bucket it couldn't read")

print("\n=== Backward guard: skipped is optional, AccessDenied still doesn't raise without it ===")
s3 = FakeS3(encryption_configs={}, bucket_names=["denied-bucket"], denied={"denied-bucket"})
try:
    findings = encryption.check_31_s3_missing_default_encryption(s3, ["denied-bucket"])
except ClientError:
    assert_true(False, "ENC-31: raised when called without a skipped set")
else:
    assert_true(len(findings) == 0, "ENC-31: no finding, no crash, when called without a skipped set")

print("\n=== Non-AccessDenied, non-NotFound errors still surface, not swallowed ===")
class AngryS3:
    def get_bucket_encryption(self, Bucket):
        raise ClientError({"Error": {"Code": "InternalError", "Message": "x"}}, "GetBucketEncryption")
try:
    encryption.check_31_s3_missing_default_encryption(AngryS3(), ["b1"], set())
except ClientError as e:
    assert_true(e.response["Error"]["Code"] == "InternalError",
                "An unexpected error code still raises instead of being silently skipped")
else:
    assert_true(False, "An unexpected error code was swallowed — real failures would hide as clean results")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
