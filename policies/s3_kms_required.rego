# METADATA
# title: S3 buckets must use SSE-KMS with a customer-managed CMK
# description: |
#   PHI buckets must be encrypted at rest under a key the customer
#   controls. AWS-managed SSE-S3 (the 2023 default) does not satisfy
#   HIPAA 164.312(a)(2)(iv) because the key custody is with AWS, not
#   the covered entity. SSE-KMS without a kms_master_key_id is also
#   rejected: it falls back to the AWS-managed S3 default key, which
#   is still not the CMK we provisioned.
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#     - "164.308(a)(7)"
#   severity: high
#   remediation: |
#     Add aws_s3_bucket_server_side_encryption_configuration for this
#     bucket with sse_algorithm = "aws:kms" and kms_master_key_id set
#     to your customer-managed KMS key ARN. See
#     terraform/hardening_uploads.tf for the pattern.
#   gap: GAP-01
package compliance.hipaa.encryption

# Modern Rego idioms (Rego v1-style). `contains` defines a rule that
# returns a SET of values; `if` makes the rule body explicit.
import future.keywords.contains
import future.keywords.if
import future.keywords.in

############################################################
# Helpers
############################################################

# Set of S3 bucket Terraform addresses that the plan would create.
# We only care about creates — modifications/destroys don't introduce
# new unencrypted PHI surface.
s3_buckets_created contains addr if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket"
	"create" in change.change.actions
	addr := change.address
}

# For a given bucket address, returns the SET of addresses of any
# SSE-KMS-with-CMK configurations the plan will attach to it.
#
# We have to look at input.configuration (not input.resource_changes)
# because the bucket reference and the kms_master_key_id are both
# "known after apply" values, so they show up as null in the plan
# diff. The configuration block preserves the source-level expressions
# (references, constants), which is what we need to verify.
#
# Rego v1 note: parameterized rules (functions) can't use `contains`
# directly, so we use a set comprehension to build the result set.
sse_kms_config_for(bucket_addr) := result if {
	result := {sse_addr |
		# Step 1: find an SSE config resource being created.
		some change in input.resource_changes
		change.type == "aws_s3_bucket_server_side_encryption_configuration"
		"create" in change.change.actions
		sse_addr := change.address

		# Step 2: confirm it points at THIS bucket via the
		# configuration block's reference list. Terraform records
		# both "aws_s3_bucket.uploads.id" and "aws_s3_bucket.uploads"
		# in the references array; we match on the ".id" form
		# because that's the actual attribute the resource takes.
		some cfg in input.configuration.root_module.resources
		cfg.address == sse_addr
		some ref in cfg.expressions.bucket.references
		ref == sprintf("%s.id", [bucket_addr])

		# Step 3: confirm the algorithm is aws:kms (not AES256).
		default_block := cfg.expressions.rule[0].apply_server_side_encryption_by_default[0]
		default_block.sse_algorithm.constant_value == "aws:kms"

		# Step 4: confirm a key ID was set. We accept either a
		# reference (e.g. aws_kms_key.app.arn) or a hardcoded ARN
		# string. We do NOT accept its absence: that path falls
		# back to the AWS-managed S3 default key, which is not
		# customer custody.
		has_key_id(default_block)
	}
}

# Returns true if the encryption block has any kms_master_key_id set.
has_key_id(default_block) if default_block.kms_master_key_id.references[_]
has_key_id(default_block) if default_block.kms_master_key_id.constant_value

############################################################
# Deny rule
############################################################

# Fires once per non-compliant bucket. The message is what a developer
# sees in the failed conftest output, so it names the control ID and
# points at the remediation file.
deny contains msg if {
	some bucket_addr in s3_buckets_created
	count(sse_kms_config_for(bucket_addr)) == 0
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] S3 bucket %q has no SSE-KMS configuration referencing a customer-managed CMK. PHI buckets must declare aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=\"aws:kms\" and kms_master_key_id pointing at your CMK. See terraform/hardening_uploads.tf.",
		[bucket_addr],
	)
}
