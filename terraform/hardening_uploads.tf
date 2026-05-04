######################################################################
# Hardening overlay — S3 uploads bucket.
#
# This file closes GAP-01 (SSE-KMS), GAP-03 (TLS-only access),
# and GAP-04 (versioning).
#
# HIPAA mapping:
#   - 164.312(a)(2)(iv) Encryption at rest (customer-controlled key)
#   - 164.312(b)        Audit Controls (CMK use logs to CloudTrail
#                       under our account context, unlike SSE-S3)
#   - 164.312(e)(1)     Transmission Security (no plaintext PHI on
#                       the wire to or from this bucket)
#   - 164.308(a)(7)     Contingency Plan (recoverability of PHI
#                       attachments via versioning)
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  # Reference the starter's bucket by its Terraform address. We are
  # NOT redefining the bucket here, just attaching an encryption
  # configuration to the existing one. The starter's resource keeps
  # ownership of the bucket lifecycle.
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      # "aws:kms" says: encrypt with KMS, don't fall back to SSE-S3.
      # Specifying kms_master_key_id pins the key. Without it, AWS
      # would use the account's default S3 KMS key (still customer-
      # managed but not the one we provisioned with our policy).
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.app.arn
    }

    # bucket_key_enabled caches the data key at the bucket level so
    # uploads don't make a KMS API call on every PUT. Cuts KMS request
    # cost by ~99% on busy buckets and reduces CloudTrail volume
    # without weakening confidentiality. Best-practice default.
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-03 closure — deny any S3 request that did not arrive over TLS.
#
# AWS does NOT enforce HTTPS on S3 by default. Without this resource
# policy, a misconfigured client (Lambda using an http:// URL, an SDK
# with TLS verification disabled, an internal proxy stripping HTTPS)
# can PUT or GET PHI in cleartext over the network. The bucket would
# still "work" and nothing in CloudTrail would flag the issue.
#
# The aws:SecureTransport condition key resolves to true on HTTPS
# requests and false on HTTP requests. Denying when it is "false"
# refuses every plain-HTTP call before S3 reads a single byte of
# data — the response is 403 Forbidden.
#
# Principal "*" is intentional. Defense in depth: even root, even
# IAM-allowed services, even pre-signed URLs must use TLS. There is
# no PHI workload reason to allow plaintext on the wire.
#
# HIPAA mapping: 164.312(e)(1) Transmission Security.
######################################################################

resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*",
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
# GAP-04 closure — enable versioning on the uploads bucket.
#
# Without versioning, a PUT to an existing key overwrites the prior
# object with no recovery, and a DELETE is permanent. Failure modes
# this prevents:
#   - Buggy Lambda overwrites a patient's intake attachment
#   - Ransomware encrypts-in-place by writing over each key
#   - Accidental admin DELETE
#
# Versioning is the floor of recoverability for object stores. It is
# not a backup strategy by itself, but HIPAA's contingency-plan
# obligation expects at least this much for PHI object storage.
#
# We deliberately do NOT add a lifecycle rule to expire noncurrent
# versions in this layer. That is a deletion policy and belongs in
# its own decision; aggressive expiry would defeat the recovery
# intent. Documented in WRITEUP.md if/when added.
#
# HIPAA mapping: 164.308(a)(7) Contingency Plan (data backup plan).
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# Defense-in-depth — explicit public access block on uploads.
#
# AWS sets BPA on by default for new buckets since 2023, but
# auditors expect to see an aws_s3_bucket_public_access_block
# resource declared explicitly so a Terraform reader does not have
# to know the default. Same pattern used on every other bucket we
# manage (evidence, cloudtrail, tfstate, config).
######################################################################

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
