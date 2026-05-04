######################################################################
# Layer 3 prerequisite — Terraform remote state backend.
#
# The GRC gate workflow runs in GitHub Actions, which starts a fresh
# runner for every job. Without a remote backend, the runner has no
# state file and `terraform plan` would propose creating every
# resource from scratch every time. We need state in S3 with locking
# in DynamoDB so concurrent jobs don't clobber each other.
#
# This file creates the bucket and lock table. Bootstrapping order:
#   1. apply with LOCAL state once -> creates these resources
#   2. add `backend "s3" {}` block to main.tf
#   3. terraform init -migrate-state -force-copy -> moves state in
#
# After step 3 the .tfstate file lives in S3 and pipelines can read
# it via the OIDC role's s3:GetObject + s3:PutObject grants on the
# state bucket. The local terraform.tfstate file should be deleted
# after the migration completes successfully.
#
# HIPAA mapping: 164.312(b) Audit Controls (state file is part of
# the change-management evidence chain).
######################################################################

resource "aws_s3_bucket" "tfstate" {
  bucket = "${local.name_prefix}-tfstate-${local.suffix}"

  tags = {
    Name      = "acme-health-tfstate"
    Purpose   = "terraform-remote-state"
    DataClass = "infra-metadata"
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning is critical for state. If a corrupt apply truncates the
# file we want the previous version available for rollback.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encrypt with the evidence CMK. State files contain resource ARNs
# and configuration, which are sensitive infra metadata. Same trust
# boundary as the evidence vault: only CI/CD principals and audit
# verifiers should ever read them.
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

# TLS-only. Same pattern as every other bucket we manage.
resource "aws_s3_bucket_policy" "tfstate_tls_only" {
  bucket = aws_s3_bucket.tfstate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.tfstate.arn,
          "${aws_s3_bucket.tfstate.arn}/*",
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

# DynamoDB lock table. Terraform's S3 backend uses this to acquire a
# lock named "<bucket>/<key>-md5" before any state-mutating
# operation. Without it, two concurrent CI runs could race and
# produce a corrupt state file.
resource "aws_dynamodb_table" "tfstate_lock" {
  name         = "${local.name_prefix}-tfstate-lock-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  # Encrypt with the evidence CMK for the same reason the state
  # bucket uses it: the lock table contains state checksums and
  # resource paths, which is sensitive infra metadata.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.evidence.arn
  }

  # NOTE: point-in-time recovery is intentionally NOT enabled on
  # the lock table. Lock entries are transient (a few seconds) and
  # have no data-recovery value; PITR would only add cost.
  # checkov:skip=CKV_AWS_28:Lock table holds transient lock state, not data worth restoring

  tags = {
    Name      = "acme-health-tfstate-lock"
    Purpose   = "terraform-state-locking"
    DataClass = "infra-metadata"
  }
}

output "tfstate_bucket" {
  value       = aws_s3_bucket.tfstate.id
  description = "S3 bucket holding terraform.tfstate."
}

output "tfstate_lock_table" {
  value       = aws_dynamodb_table.tfstate_lock.name
  description = "DynamoDB table used by the S3 backend for state locking."
}
