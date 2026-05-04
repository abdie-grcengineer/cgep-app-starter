######################################################################
# Layer 1 — Evidence vault.
#
# This is where every pipeline run lands a signed, timestamped
# artifact (Layer 3 in a future commit). The bucket exists in a
# different trust boundary than the workload: the Lambda role has
# no access (verified via the aws_kms_key.evidence policy in
# kms.tf, which deliberately omits the Lambda principal).
#
# Required properties (per the capstone brief):
#   - S3 bucket with Object Lock
#   - Versioning Enabled (Object Lock REQUIRES versioning)
#   - Encrypted with our KMS key (aws_kms_key.evidence)
#   - The bucket must reject plain-HTTP requests
#   - Public access fully blocked
#
# Layered with our own design choices:
#   - Object Lock mode: COMPLIANCE (D-05 in WRITEUP.md)
#   - Default retention: 90 days (D-05 in WRITEUP.md)
#
# HIPAA mapping:
#   - 164.312(b)        Audit Controls (the bucket IS the audit log)
#   - 164.312(c)(1)     Integrity (Object Lock prevents tampering)
#   - 164.312(e)(1)     Transmission Security (TLS deny)
#   - 164.312(a)(2)(iv) Encryption at rest (CMK)
#   - 164.308(a)(7)     Contingency Plan (versioning, immutability)
######################################################################

resource "aws_s3_bucket" "evidence" {
  bucket = "${local.name_prefix}-evidence-${local.suffix}"

  # Object Lock must be declared at bucket-creation time to be
  # enforceable from day 1. AWS now permits enabling it later, but
  # only on a per-bucket request to AWS Support, and it complicates
  # the audit story. We do it the clean way.
  object_lock_enabled = true

  # Override the default_tags DataClass = "phi" inherited from the
  # provider block. This bucket holds audit evidence, not PHI.
  tags = {
    Name       = "acme-health-evidence"
    Compliance = "hipaa"
    Control    = "164.312.b"
    Purpose    = "audit-evidence-vault"
    DataClass  = "audit-evidence"
  }
}

# Block all four public access vectors. AWS turns these on for new
# buckets by default since 2023, but auditors still expect to see
# them explicit in IaC.
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-KMS encryption with the evidence CMK. Different key from the
# workload bucket on purpose (D-01).
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

# Versioning is a HARD requirement for Object Lock. AWS will reject
# the object_lock_configuration apply if versioning is not Enabled.
# We use a depends_on on the lock config below to make the apply
# order deterministic.
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Default Object Lock retention: every object PUT into this bucket
# inherits this retention automatically. Pipelines (Layer 3) MAY
# override per-object for shorter or longer retention if needed.
#
# COMPLIANCE mode: even the AWS account root cannot delete or modify
# an object during retention. The only override path is an AWS
# Support escalation, which produces its own audit trail. This is
# the property auditors care about.
#
# 90 days: long enough to span an audit cycle plus a quarterly review
# window, short enough that the lab/sandbox can iterate without
# being permanently stuck. Production for HIPAA-grade record keeping
# would extend this to align with the 6-year PHI retention floor.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 90
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

# TLS-only: same pattern as the uploads bucket. Audit evidence in
# transit must also be encrypted, both for confidentiality of the
# bundles themselves and for integrity of the chain of custody.
resource "aws_s3_bucket_policy" "evidence_tls_only" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

# Output the bucket name. Layer 3's pipeline workflow will consume
# this via terraform output to know where to upload.
output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "S3 bucket holding signed pipeline artifacts (audit chain of custody)."
}
