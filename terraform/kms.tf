######################################################################
# KMS — Customer-Managed Keys (CMKs) for the Acme Health workload.
#
# This file is part of the GRC hardening overlay added on top of the
# starter. It closes (in part) GAP-01 and GAP-02 by giving the workload
# customer-controlled keys instead of AWS-owned defaults.
#
# Design decision: TWO keys, not one shared key.
#
#   - aws_kms_key.app       protects PHI workload data
#                           (S3 uploads bucket, DynamoDB submissions)
#   - aws_kms_key.evidence  protects audit evidence
#                           (S3 evidence vault, signed pipeline bundles)
#
# Two keys means a compromise of the workload (e.g. the Lambda role)
# cannot reach the audit evidence. A single shared key would let the
# same incident compromise both the PHI and the auditor's chain of
# custody. Defended in WRITEUP.md.
#
# HIPAA mapping: 164.312(a)(2)(iv) Encryption — both addressable
# specifications are treated as required (industry consensus).
######################################################################

# We need the account ID to build the root principal ARN in the key
# policy. AWS requires the root principal in every CMK policy or the
# account itself can be locked out of its own key.
data "aws_caller_identity" "current" {}

######################################################################
# Workload CMK — protects PHI data created by the patient intake API.
######################################################################

resource "aws_kms_key" "app" {
  description = "Acme Health workload CMK — PHI at rest (S3 uploads, DynamoDB submissions)"

  # Rotates the key material annually. HIPAA does not name a rotation
  # cadence, but auditors universally expect rotation on PHI-protecting
  # keys. AWS handles the rotation transparently; key ID stays the same.
  enable_key_rotation = true

  # Window during which a deleted key sits in PendingDeletion before
  # AWS actually destroys it. 30 days is the maximum and the most
  # forgiving setting; we choose it because losing a PHI-protecting key
  # is an availability incident with no recovery (data becomes
  # permanently unreadable). Trade-off documented in WRITEUP.md.
  deletion_window_in_days = 30

  # Inline key policy. This is what kms:* actions are gated by, in
  # addition to IAM. Both must allow for an action to succeed.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Account root admin. Required by AWS or the account loses
        # control of its own key. This is the only place kms:* lives.
        Sid    = "EnableRootAccountAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        # The Lambda's runtime role gets only what it needs to operate
        # on encrypted PHI: Decrypt to read existing objects/items, and
        # GenerateDataKey to produce envelope keys for new writes
        # (S3 SSE-KMS uses envelope encryption under the hood).
        # Explicitly NOT kms:* — least privilege at the key level
        # mirrors HIPAA 164.312(a)(1) "minimum necessary" for IAM.
        Sid    = "AllowLambdaUseOfKey"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name       = "acme-health-app-cmk"
    Compliance = "hipaa"
    # AWS tag values allow [a-zA-Z0-9 _.:/=+\-@]. Parentheses are NOT
    # allowed, so we render the HIPAA citation with dots instead of
    # the canonical "164.312(a)(2)(iv)".
    Control = "164.312.a.2.iv"
    Purpose = "phi-workload-encryption"
  }
}

# Aliases give the key a stable, human-readable name. The key ID itself
# is a UUID and changes if the key is recreated; alias references
# (kms:DescribeKey by alias) survive recreation.
resource "aws_kms_alias" "app" {
  name          = "alias/acme-health-app"
  target_key_id = aws_kms_key.app.key_id
}

######################################################################
# Evidence CMK — protects audit artifacts in the evidence vault.
#
# Critically, the Lambda role does NOT appear in this key policy. A
# workload compromise should not be able to read audit evidence. The
# pipeline's GitHub Actions OIDC role and a verifier role get added
# here in Layer 3 when the evidence vault and signing flow are built.
######################################################################

resource "aws_kms_key" "evidence" {
  description = "Acme Health evidence vault CMK — signed pipeline artifacts, audit chain of custody"

  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        # CloudTrail must be able to generate envelope keys to
        # encrypt its log files at rest. The EncryptionContext
        # condition scopes this grant to ONLY trails in this
        # account: a CloudTrail trail in any other account
        # cannot use this key, even if it somehow obtained the
        # key ARN. AWS sets the encryption context automatically
        # on every trail-driven KMS call.
        Sid    = "AllowCloudTrailEncryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        # CloudTrail also needs Decrypt to validate its own
        # generated keys during log file validation. Same
        # encryption-context scope.
        Sid    = "AllowCloudTrailDecryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        # GitHub Actions pipeline (Layer 3): the role assumed via
        # OIDC needs to encrypt signed bundles on upload to the
        # evidence vault, and read the terraform.tfstate file
        # (also encrypted with this CMK).
        Sid    = "AllowGitHubActionsRoleUseOfKey"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.gh_actions.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      {
        # CloudWatch Logs needs envelope-key access to encrypt the
        # /acme-health/* log groups (e.g., the AWS Config violations
        # group from monitoring.tf). The EncryptionContext condition
        # scopes the grant to log groups under that prefix only —
        # any other log group in the account cannot use this key.
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/acme-health/*"
          }
        }
      },
      # Future addition: a verifier role with kms:Decrypt only,
      # used by the grader and human auditors to verify signed
      # bundles. Not in scope for the capstone submission.
    ]
  })

  tags = {
    Name       = "acme-health-evidence-cmk"
    Compliance = "hipaa"
    Control    = "164.312.b" # audit controls (parens disallowed in AWS tags)
    Purpose    = "audit-evidence-encryption"
    # Override the default_tags DataClass=phi inherited from the
    # provider block. This key protects audit evidence, not PHI.
    DataClass = "audit-evidence"
  }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/acme-health-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}
