# METADATA
# title: S3 buckets holding PHI must have versioning enabled
# description: |
#   Without versioning a PUT overwrites the previous object with no
#   recovery, and a DELETE is permanent. HIPAA 164.308(a)(7) requires
#   a contingency plan with a data backup component; for object
#   stores, versioning is the floor that makes per-object recovery
#   possible. Suspended or absent versioning is rejected.
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
#   remediation: |
#     Add aws_s3_bucket_versioning attached to this bucket with
#     versioning_configuration.status = "Enabled". See
#     terraform/hardening_uploads.tf for the pattern.
#   gap: GAP-04
package compliance.hipaa.s3_versioning

import future.keywords.contains
import future.keywords.if
import future.keywords.in

############################################################
# Helpers
############################################################

# Set of S3 bucket addresses being created in the plan.
s3_buckets_created contains addr if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket"
	"create" in change.change.actions
	addr := change.address
}

# Set of S3 bucket addresses for which the plan attaches a
# versioning configuration with status = "Enabled".
buckets_with_versioning_enabled contains bucket_addr if {
	# Step 1: find an aws_s3_bucket_versioning being created.
	some change in input.resource_changes
	change.type == "aws_s3_bucket_versioning"
	"create" in change.change.actions

	# Step 2: resolve which bucket via the configuration block.
	some cfg in input.configuration.root_module.resources
	cfg.address == change.address
	some ref in cfg.expressions.bucket.references
	endswith(ref, ".id")
	bucket_addr := trim_suffix(ref, ".id")

	# Step 3: confirm the status is "Enabled". We accept the
	# constant_value form (most common in HCL) or a reference to a
	# variable that resolves later. AWS S3 supports three states:
	# "Enabled", "Suspended", and "Disabled". Only "Enabled" passes.
	cfg.expressions.versioning_configuration[0].status.constant_value == "Enabled"
}

############################################################
# Deny rule
############################################################

deny contains msg if {
	some bucket_addr in s3_buckets_created
	not bucket_addr in buckets_with_versioning_enabled
	msg := sprintf(
		"[HIPAA 164.308(a)(7)] S3 bucket %q has no aws_s3_bucket_versioning resource with status=\"Enabled\". PHI buckets must have versioning so individual objects are recoverable after overwrite or delete. See terraform/hardening_uploads.tf:aws_s3_bucket_versioning.uploads.",
		[bucket_addr],
	)
}
