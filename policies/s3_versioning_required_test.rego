# Tests for s3_versioning_required.rego
#
# Run with:  opa test ./policies

package compliance.hipaa.s3_versioning

import future.keywords.if

############################################################
# Fixtures
############################################################

# Compliant: bucket plus aws_s3_bucket_versioning with Enabled.
versioning_enabled_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"]},
		},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"change": {"actions": ["create"]},
		},
	],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
		},
	}]}},
}

# Bare bucket: no versioning resource. Mirrors the starter baseline.
no_versioning_plan := {
	"resource_changes": [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"]},
	}],
	"configuration": {"root_module": {"resources": []}},
}

# Versioning resource exists but status is "Suspended".
versioning_suspended_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"]},
		},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"change": {"actions": ["create"]},
		},
	],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"versioning_configuration": [{"status": {"constant_value": "Suspended"}}],
		},
	}]}},
}

############################################################
# Tests
############################################################

test_versioning_enabled_passes if {
	count(deny) == 0 with input as versioning_enabled_plan
}

test_no_versioning_resource_is_denied if {
	count(deny) == 1 with input as no_versioning_plan
}

test_versioning_suspended_is_denied if {
	count(deny) == 1 with input as versioning_suspended_plan
}

# Regression test for the create-only-blind-spot bug: an UPDATE
# on an existing bucket without a versioning resource must fire.
test_existing_bucket_updated_without_versioning_is_denied if {
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
