######################################################################
# Hardening overlay — S3 uploads bucket.
#
# This file closes GAP-01 (and will grow to close GAP-03 TLS-deny and
# GAP-04 versioning when those gaps are addressed).
#
# What it does today:
#   Forces the starter's aws_s3_bucket.uploads to use SSE-KMS with our
#   customer-managed key (aws_kms_key.app), instead of the AWS-managed
#   SSE-S3 default the starter ships with.
#
# HIPAA mapping:
#   - 164.312(a)(2)(iv) Encryption (PHI at rest, customer-controlled key)
#   - 164.312(b)        Audit Controls (CMK use is logged in CloudTrail
#                       under our account context, unlike SSE-S3)
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
