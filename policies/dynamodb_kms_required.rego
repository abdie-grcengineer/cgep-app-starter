# METADATA
# title: DynamoDB tables holding PHI must use a customer-managed CMK
# description: |
#   DynamoDB tables encrypt at rest by default with an AWS-owned key.
#   For PHI workloads, HIPAA 164.312(a)(2)(iv) requires customer
#   custody of encryption keys. The aws-managed key alias
#   (alias/aws/dynamodb) is also rejected: it is in the customer's
#   account but uses an AWS-decided key policy, not the workload's.
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#     - "164.312(a)(1)"
#   severity: high
#   remediation: |
#     Add a server_side_encryption block to the aws_dynamodb_table
#     resource with enabled = true and kms_key_arn referencing your
#     customer-managed KMS key. See terraform/main.tf for the pattern
#     applied to aws_dynamodb_table.intake.
#   gap: GAP-02
package compliance.hipaa.dynamodb

import future.keywords.contains
import future.keywords.if
import future.keywords.in

############################################################
# Helpers
############################################################

# Plan-action filter. Catches creates AND in-place updates so we
# also fire on a PR that re-introduces a non-compliant config on
# an existing table (the original "create only" check missed this).
is_create_or_update(change) if "create" in change.change.actions
is_create_or_update(change) if "update" in change.change.actions

# Set of DynamoDB table addresses being created or updated.
dynamodb_tables_created contains addr if {
	some change in input.resource_changes
	change.type == "aws_dynamodb_table"
	is_create_or_update(change)
	addr := change.address
}

# Returns true if the given table address has a server_side_encryption
# block with enabled = true AND a kms_key_arn pointing at a CMK.
#
# We read from input.configuration (not change.after) because
# kms_key_arn is "known after apply" in the plan (it resolves at
# apply-time from a reference to aws_kms_key.app.arn). The
# configuration block preserves the source-level expressions.
table_has_cmk_encryption(table_addr) if {
	some cfg in input.configuration.root_module.resources
	cfg.address == table_addr
	cfg.type == "aws_dynamodb_table"

	# Must have at least one server_side_encryption block.
	sse_block := cfg.expressions.server_side_encryption[0]

	# Block must explicitly enable encryption.
	sse_block.enabled.constant_value == true

	# Block must specify a kms_key_arn — either a reference to a CMK
	# resource or a hardcoded ARN string. Absence means AWS-managed
	# alias/aws/dynamodb (default), which is not customer custody.
	has_kms_key_arn(sse_block)
}

has_kms_key_arn(sse_block) if sse_block.kms_key_arn.references[_]
has_kms_key_arn(sse_block) if sse_block.kms_key_arn.constant_value

############################################################
# Deny rule
############################################################

deny contains msg if {
	some table_addr in dynamodb_tables_created
	not table_has_cmk_encryption(table_addr)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] DynamoDB table %q has no customer-managed-key encryption. PHI tables must declare server_side_encryption { enabled = true, kms_key_arn = <CMK> }. Default AWS-owned and AWS-managed keys do not satisfy customer custody. See terraform/main.tf:aws_dynamodb_table.intake for the pattern.",
		[table_addr],
	)
}
