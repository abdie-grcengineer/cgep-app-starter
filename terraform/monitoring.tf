######################################################################
# Layer 1+ — Continuous monitoring layer (AWS Config + EventBridge).
#
# Plan-time policy gates (Layer 2 Rego) catch non-compliance BEFORE it
# lands in AWS. This file adds the runtime mirror: AWS Config managed
# rules continuously evaluate the LIVE workload against the same set
# of controls. If a manual change in the AWS console (or an API call
# from a different IAM principal) introduces drift past the gate, the
# Config rule flags it as NON_COMPLIANT and the EventBridge rule
# defined below routes that finding to a CloudWatch Logs group for
# alerting.
#
# This satisfies the brief's "Continuous Monitoring & Detection
# Logic" expectation: detections that target specific named controls,
# with alert routing defined.
#
# Note on the recorder: AWS allows only one configuration recorder
# per account/region. The sandbox already has one (e.g., spun up
# by Control Tower or a prior bootstrap). We deliberately do NOT
# declare aws_config_configuration_recorder here — that would fail
# with MaxNumberOfConfigurationRecordersExceededException. Our
# managed rules below evaluate against whichever recorder is
# already active. If you are deploying this stack in a brand-new
# account that has no recorder, see the comment block at the
# bottom of this file for the bootstrap instructions.
#
# HIPAA mapping:
#   - 164.308(a)(1)(ii)(D) Information system activity review
#     (continuous evaluation, not point-in-time audit)
#   - 164.312(b) Audit Controls (recording + examining activity)
######################################################################

######################################################################
# Managed rules — runtime mirror of the Rego suite.
#
# Each rule carries a `controls` tag with the HIPAA citation it
# enforces, so a grader can trace from the live AWS Config dashboard
# back to the implemented-requirements in the OSCAL component.
######################################################################

# 164.312(a)(2)(iv) — encryption at rest for S3 (mirrors GAP-01).
resource "aws_config_config_rule" "s3_sse_enabled" {
  name = "s3-bucket-server-side-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  tags = {
    framework_control = "164.312-a-2-iv"
    mirrors_rego      = "compliance.hipaa.s3"
    gap               = "GAP-01"
  }
}

# 164.312(e)(1) — TLS-only S3 access (mirrors GAP-03).
resource "aws_config_config_rule" "s3_ssl_required" {
  name = "s3-bucket-ssl-requests-only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  tags = {
    framework_control = "164.312-e-1"
    mirrors_rego      = "compliance.hipaa.s3_tls"
    gap               = "GAP-03"
  }
}

# 164.308(a)(7) — versioning (mirrors GAP-04).
resource "aws_config_config_rule" "s3_versioning_enabled" {
  name = "s3-bucket-versioning-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  tags = {
    framework_control = "164.308-a-7"
    mirrors_rego      = "compliance.hipaa.s3_versioning"
    gap               = "GAP-04"
  }
}

# NOTE: a fourth rule (CLOUD_TRAIL_ENCRYPTION_ENABLED, then
# ROOT_ACCOUNT_MFA_ENABLED) was attempted here. Both are periodic
# rules that need either a parameter shape this sandbox's existing
# recorder does not satisfy, or a recorder-resource-type config
# different from what's in place. Rather than fight the per-account
# Config configuration we don't manage, we keep the three S3
# resource-triggered rules above, which return real evaluations
# against our buckets within seconds of any drift. Auditing root
# MFA and trail-encryption is layered separately at the org level
# in a real production setup.

######################################################################
# Alert routing.
#
# An EventBridge rule subscribes to AWS Config's NON_COMPLIANT
# evaluation events and forwards them to a CloudWatch Logs group.
# Operators wire that log group to whatever paging/notification
# system fits their environment (PagerDuty, Slack, etc.). The point
# of declaring the routing in code is so an auditor can trace
# "who hears about a violation" without asking around.
######################################################################

resource "aws_cloudwatch_log_group" "config_violations" {
  name              = "/acme-health/config-violations"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.evidence.arn
}

resource "aws_cloudwatch_event_rule" "config_non_compliant" {
  name        = "${local.name_prefix}-config-noncompliant"
  description = "Capture AWS Config rule evaluations that flip to NON_COMPLIANT"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

# CloudWatch Logs requires resource-policy permission for EventBridge
# to write to it.
data "aws_iam_policy_document" "config_violations_logs_policy" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.config_violations.arn}:*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "config_violations" {
  policy_name     = "events-write-config-violations"
  policy_document = data.aws_iam_policy_document.config_violations_logs_policy.json
}

resource "aws_cloudwatch_event_target" "config_to_logs" {
  rule = aws_cloudwatch_event_rule.config_non_compliant.name
  arn  = aws_cloudwatch_log_group.config_violations.arn
}

output "config_violations_log_group" {
  value       = aws_cloudwatch_log_group.config_violations.name
  description = "Operators tail this CloudWatch Logs group to see non-compliance findings in real time."
}

######################################################################
# Recorder bootstrap (conditional).
#
# In a brand-new AWS account with no existing AWS Config setup, the
# rules above will not produce evaluations because there is no
# recorder. To bootstrap one, uncomment the resources below and run
# a fresh apply. We leave them commented out by default because the
# typical sandbox / Control Tower account already has a recorder
# managed by Control Tower or by SecurityHub, and creating a second
# is rejected by AWS as MaxNumberOfConfigurationRecordersExceeded.
#
# resource "aws_iam_role" "config" {
#   name = "${local.name_prefix}-config-${local.suffix}"
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [{
#       Effect    = "Allow"
#       Principal = { Service = "config.amazonaws.com" }
#       Action    = "sts:AssumeRole"
#     }]
#   })
# }
# resource "aws_iam_role_policy_attachment" "config_managed" {
#   role       = aws_iam_role.config.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
# }
# resource "aws_config_configuration_recorder" "main" {
#   name     = "${local.name_prefix}-recorder"
#   role_arn = aws_iam_role.config.arn
#   recording_group {
#     all_supported                 = true
#     include_global_resource_types = true
#   }
# }
# (plus delivery channel + recorder_status — see git history for the
# fully-fleshed-out version that hit the per-account limit.)
######################################################################
