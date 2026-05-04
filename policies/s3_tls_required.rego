# METADATA
# title: S3 buckets must enforce TLS-only access via bucket policy
# description: |
#   AWS S3 accepts plain HTTP and HTTPS by default. PHI buckets must
#   reject any request that did not arrive over TLS, otherwise an
#   internal misconfiguration (Lambda using http://, SDK with TLS
#   verification disabled, intermediary proxy stripping HTTPS) can
#   silently transmit PHI in cleartext. The standard pattern is a
#   bucket policy with an explicit Deny on aws:SecureTransport=false.
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   remediation: |
#     Add an aws_s3_bucket_policy resource attached to the bucket with
#     a single statement: Effect=Deny, Principal=*, Action=s3:*,
#     Resource=[bucket_arn, bucket_arn/*], Condition Bool
#     aws:SecureTransport=false. See terraform/hardening_uploads.tf
#     for the pattern (resource aws_s3_bucket_policy.uploads_tls_only).
#   gap: GAP-03
package compliance.hipaa.s3_tls

import future.keywords.contains
import future.keywords.if
import future.keywords.in

############################################################
# Helpers
############################################################

# Set of S3 bucket addresses being created in the plan. Same shape as
# the helper in s3_kms_required.rego; redefined here because each
# policy lives in its own sub-package for metadata isolation.
s3_buckets_created contains addr if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket"
	"create" in change.change.actions
	addr := change.address
}

# Set of S3 bucket addresses for which the plan attaches a bucket
# policy that contains a Deny on aws:SecureTransport=false. Reading
# from change.after.policy works when the bucket already exists at
# plan time (the typical case in this capstone, since the bucket is
# applied before its hardening). The configuration block is consulted
# to resolve the bucket reference itself.
buckets_with_tls_deny contains bucket_addr if {
	# Step 1: find an aws_s3_bucket_policy being created.
	some change in input.resource_changes
	change.type == "aws_s3_bucket_policy"
	"create" in change.change.actions

	# Step 2: resolve which bucket this policy is attached to via
	# the configuration block. We DERIVE the bucket address from
	# the reference string (rather than pattern-match on it):
	# Rego only unifies head variables that are bound in the body,
	# and `bucket_addr` is our head, so it must come from data.
	# Terraform records refs like "aws_s3_bucket.uploads.id";
	# stripping the ".id" suffix gives us the resource address.
	some cfg in input.configuration.root_module.resources
	cfg.address == change.address
	some ref in cfg.expressions.bucket.references
	endswith(ref, ".id")
	bucket_addr := trim_suffix(ref, ".id")

	# Step 3: parse the policy JSON. Terraform's jsonencode produces
	# a string; if all references inside resolve at plan time the
	# string appears in change.after.policy. If it didn't resolve
	# (e.g., bucket-and-policy created together), this match fails
	# silently and the gap is reported, which is the safe default.
	policy_doc := json.unmarshal(change.change.after.policy)

	# Step 4: confirm at least one Deny statement exists with the
	# aws:SecureTransport=false condition. We accept either the
	# string "false" or boolean false (Terraform tends to serialize
	# as a string but other tooling may emit a boolean).
	some stmt in policy_doc.Statement
	stmt.Effect == "Deny"
	is_secure_transport_false_condition(stmt.Condition)
}

# Helper: condition matches the canonical TLS-deny pattern.
#   "Condition": { "Bool": { "aws:SecureTransport": "false" } }
is_secure_transport_false_condition(condition) if {
	condition.Bool["aws:SecureTransport"] == "false"
}

is_secure_transport_false_condition(condition) if {
	condition.Bool["aws:SecureTransport"] == false
}

############################################################
# Deny rule
############################################################

deny contains msg if {
	some bucket_addr in s3_buckets_created
	not bucket_addr in buckets_with_tls_deny
	msg := sprintf(
		"[HIPAA 164.312(e)(1)] S3 bucket %q has no aws:SecureTransport=false deny statement. PHI buckets must reject plain-HTTP requests at the bucket policy level. See terraform/hardening_uploads.tf:aws_s3_bucket_policy.uploads_tls_only for the pattern.",
		[bucket_addr],
	)
}
