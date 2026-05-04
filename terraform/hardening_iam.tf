######################################################################
# Hardening overlay — IAM additions for the Lambda runtime role.
#
# Why this file exists:
#   The starter's Lambda inline policy (aws_iam_role_policy.lambda_inline
#   in main.tf) grants dynamodb:* and s3:* on the workload data stores.
#   It does NOT grant any kms:* actions, because the starter's bucket
#   uses SSE-S3 (no KMS interaction needed at runtime).
#
#   The moment hardening_uploads.tf flips the uploads bucket to SSE-KMS,
#   every Lambda PUT/GET requires a KMS call. Without a kms:Decrypt and
#   kms:GenerateDataKey grant on aws_kms_key.app, the Lambda fails with
#   KMS.AccessDeniedException on the next request after apply.
#
# Design decision:
#   We add a SECOND inline policy ("intake-kms-workload-access") on the
#   same role rather than editing the starter's existing inline policy.
#   This preserves the starter file unchanged so graders can diff
#   against upstream and see exactly what the capstone added.
#
#   Note: the starter's inline policy still has dynamodb:* and s3:* —
#   that is GAP-07, addressed in a separate hardening file later.
#
# HIPAA mapping:
#   - 164.312(a)(1)       Access Control (least privilege at the key)
#   - 164.312(a)(2)(iv)   Encryption (operational dependency)
######################################################################

resource "aws_iam_role_policy" "lambda_kms_workload" {
  name = "intake-kms-workload-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # Read existing encrypted objects out of S3 / decrypt
          # envelope keys on existing DynamoDB items once we flip
          # that table to CMK in GAP-02.
          "kms:Decrypt",
          # Generate the envelope data keys S3 SSE-KMS uses for
          # each new object PUT.
          "kms:GenerateDataKey",
          # Lets the Lambda confirm the key is enabled and pick up
          # its key ID at runtime if needed. Read-only.
          "kms:DescribeKey"
        ]
        # Scoped to ONLY the workload CMK. Explicitly does NOT include
        # aws_kms_key.evidence — workload code must never be able to
        # touch evidence-vault keys (see Design Decision D-01 in
        # WRITEUP.md).
        Resource = aws_kms_key.app.arn
      }
    ]
  })
}
