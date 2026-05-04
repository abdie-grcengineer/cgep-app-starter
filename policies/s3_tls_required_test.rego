# Tests for s3_tls_required.rego
#
# Run with:  opa test ./policies
#
# The policy lives in compliance.hipaa.s3_tls. Tests in this file
# only see deny rules from that package, so fixtures don't need to
# also satisfy the SSE-KMS policy.

package compliance.hipaa.s3_tls

import future.keywords.if

############################################################
# Helpers (test-only) — build a plausible plan-shaped input around
# a given bucket-policy JSON string.
############################################################

# Build a plan with a bucket and (optionally) a bucket policy whose
# `policy` field is the supplied JSON string. If policy_json is the
# empty string, the bucket has no associated policy.
build_plan(policy_json) := {
	"resource_changes": resource_changes,
	"configuration": {"root_module": {"resources": config_resources}},
} if {
	policy_json == ""
	resource_changes := [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"]},
	}]
	config_resources := []
}

build_plan(policy_json) := {
	"resource_changes": resource_changes,
	"configuration": {"root_module": {"resources": config_resources}},
} if {
	policy_json != ""
	resource_changes := [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"]},
		},
		{
			"address": "aws_s3_bucket_policy.uploads_tls_only",
			"type": "aws_s3_bucket_policy",
			"change": {
				"actions": ["create"],
				"after": {"policy": policy_json},
			},
		},
	]
	config_resources := [{
		"address": "aws_s3_bucket_policy.uploads_tls_only",
		"type": "aws_s3_bucket_policy",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
	}]
}

############################################################
# Fixtures (compliant + non-compliant policy JSON shapes)
############################################################

compliant_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyInsecureTransport",
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": [
			"arn:aws:s3:::bucket",
			"arn:aws:s3:::bucket/*",
		],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

# Wrong: a bucket policy that allows public read instead of denying
# insecure transport. Common starter mistake. Should still fire deny.
public_read_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "PublicRead",
		"Effect": "Allow",
		"Principal": "*",
		"Action": "s3:GetObject",
		"Resource": "arn:aws:s3:::bucket/*",
	}],
})

# Wrong: TLS condition is checking for true (allows HTTPS) instead
# of denying when transport is false. Looks similar to a TLS deny
# at a glance — exactly the kind of typo a developer might commit.
backwards_condition_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "AllowOnlyTLS",
		"Effect": "Allow",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "true"}},
	}],
})

############################################################
# Tests
############################################################

# Compliant: bucket plus a TLS-deny bucket policy.
test_bucket_with_tls_deny_passes if {
	count(deny) == 0 with input as build_plan(compliant_policy_json)
}

# Failing #1: bucket exists but has no bucket policy at all (the
# starter's exact baseline for the uploads bucket).
test_bucket_without_any_policy_is_denied if {
	count(deny) == 1 with input as build_plan("")
}

# Failing #2: bucket has a policy, but it's an Allow-public-read,
# not a TLS deny.
test_bucket_with_wrong_policy_is_denied if {
	count(deny) == 1 with input as build_plan(public_read_policy_json)
}

# Failing #3: bucket has a policy with the SecureTransport condition
# but checking the wrong direction (Allow when true, instead of Deny
# when false). Allow-when-HTTPS does not block HTTP.
test_bucket_with_backwards_condition_is_denied if {
	count(deny) == 1 with input as build_plan(backwards_condition_policy_json)
}

# Regression test for the create-only-blind-spot bug: an UPDATE on
# an existing bucket without a TLS-deny policy resource must fire.
test_existing_bucket_updated_without_tls_deny_is_denied if {
	update_plan := {
		"resource_changes": [{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["update"]},
		}],
		"configuration": {"root_module": {"resources": []}},
	}
	count(deny) == 1 with input as update_plan
}
