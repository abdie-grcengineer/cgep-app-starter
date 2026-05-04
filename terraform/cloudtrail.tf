######################################################################
# Layer 1 — CloudTrail (multi-region, log-file-validation enabled).
#
# CloudTrail is the account-wide audit log of every API call, and is
# the single most-cited evidence source in HIPAA/SOC 2/CMMC audits.
# Without it, "who deleted that PHI record at 2am" has no answer.
#
# Required properties (per the capstone brief):
#   - Multi-region trail
#   - Log-file validation enabled (cryptographic integrity)
#   - Writes management events to a DEDICATED bucket
#
# Layered with our own choices:
#   - KMS encryption with aws_kms_key.evidence (D-06; reuse from D-01)
#   - The trail bucket is hardened the same way as the evidence vault
#     (versioning, SSE-KMS, BPA, TLS-deny), minus Object Lock —
#     CloudTrail's built-in log file validation already provides
#     tamper-evidence via SHA-256 hash chains, so Object Lock on top
#     would be redundant integrity machinery.
#
# HIPAA mapping:
#   - 164.312(b)        Audit Controls (the trail IS the audit
#                       record of "who did what when")
#   - 164.312(c)(1)     Integrity (LFV gives tamper-evidence)
#   - 164.308(a)(1)(ii)(D) Information system activity review
######################################################################

######################################################################
# Trail-dedicated S3 bucket (separate from the evidence vault).
######################################################################

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${local.name_prefix}-cloudtrail-${local.suffix}"

  tags = {
    Name       = "acme-health-cloudtrail-logs"
    Compliance = "hipaa"
    Control    = "164.312.b"
    Purpose    = "cloudtrail-management-events"
    DataClass  = "audit-evidence"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Trail bucket policy: AWS REQUIRES this exact set of permissions or
# CloudTrail cannot write logs. The aws:SourceArn condition scopes
# write access to only OUR trail (defense against a "confused deputy"
# where another account's CloudTrail is used to write into our
# bucket). The aws:SecureTransport=false deny is the same TLS-only
# pattern as every other bucket we have.
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-${local.suffix}"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-${local.suffix}"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*",
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

######################################################################
# The trail itself.
######################################################################

resource "aws_cloudtrail" "main" {
  name           = "${local.name_prefix}-${local.suffix}"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  # Multi-region: capture API activity in every region, even ones
  # we don't use today, in case a future change spins up resources
  # elsewhere. Brief explicitly requires this.
  is_multi_region_trail = true

  # Apply the trail to the org root (= just this account here, since
  # we're single-account). For an org-trail in a real prod setup
  # you'd set this on the management account and remove it here.
  is_organization_trail = false

  # Log file validation: AWS writes a digest file every hour
  # containing SHA-256 hashes of the log files plus a signature.
  # Auditors verify integrity by recomputing the chain. The brief
  # makes this required.
  enable_log_file_validation = true

  # Encrypt the log files with our evidence CMK (D-06). The key
  # policy was extended in kms.tf to grant CloudTrail's service
  # principal kms:GenerateDataKey* with a tight EncryptionContext
  # condition.
  kms_key_id = aws_kms_key.evidence.arn

  # We don't need data events for this lab (every S3 GetObject in
  # the workload would multiply log volume by ~100x). Management
  # events are the audit-required minimum.
  enable_logging = true

  # Make sure the bucket policy is fully in place before CloudTrail
  # tries to write. Without this depends_on, the apply may race and
  # fail with "InsufficientS3BucketPolicyException".
  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

output "cloudtrail_bucket" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "S3 bucket holding CloudTrail management-event log files."
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.main.arn
  description = "ARN of the multi-region CloudTrail trail."
}
