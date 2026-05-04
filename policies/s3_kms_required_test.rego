# Tests for s3_kms_required.rego
#
# Run with:  opa test ./policies
#
# Each test_* rule below builds a minimal terraform-plan-shaped input
# and asserts whether the deny rule fires. The fixtures are abbreviated
# but structurally accurate to what `terraform show -json plan.tfplan`
# emits — same field names, same nesting.

package compliance.hipaa.s3

import future.keywords.if

############################################################
# Fixtures
############################################################

# Compliant: a bucket plus an SSE-KMS config that references a CMK.
# This mirrors what hardening_uploads.tf adds on top of the starter.
compliant_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"]},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"actions": ["create"]},
		},
	],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": {"constant_value": "aws:kms"},
				"kms_master_key_id": {"references": ["aws_kms_key.app.arn", "aws_kms_key.app"]},
			}]}],
		},
	}]}},
}

# Bare bucket: no SSE config at all (this is exactly what the starter
# ships — main.tf line 131-133). Should be denied.
bare_bucket_plan := {
	"resource_changes": [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"]},
	}],
	"configuration": {"root_module": {"resources": []}},
}

# SSE-S3 bucket: an SSE config exists but uses AES256 (AWS-managed
# SSE-S3) instead of aws:kms. Should be denied because the customer
# does not control the key.
sse_s3_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"]},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"actions": ["create"]},
		},
	],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "AES256"}}]}],
		},
	}]}},
}

# SSE-KMS no key: aws:kms is set but kms_master_key_id is absent.
# AWS would fall back to the AWS-managed default S3 KMS key, still
# not the customer's CMK. Should be denied.
sse_kms_no_key_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"]},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"actions": ["create"]},
		},
	],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}}]}],
		},
	}]}},
}

############################################################
# Tests
############################################################

# Passing fixture: gate stays green.
test_compliant_bucket_with_cmk_passes if {
	count(deny) == 0 with input as compliant_plan
}

# Failing fixture #1: bucket with no SSE config at all (the starter's
# baseline). The whole point of GAP-01.
test_bare_bucket_is_denied if {
	count(deny) == 1 with input as bare_bucket_plan
}

# Failing fixture #2: explicit SSE-S3 (AES256). Customer doesn't
# control the key.
test_sse_s3_bucket_is_denied if {
	count(deny) == 1 with input as sse_s3_plan
}

# Failing fixture #3: SSE-KMS but no kms_master_key_id, so it would
# fall back to the AWS-managed S3 default KMS key.
test_sse_kms_without_cmk_is_denied if {
	count(deny) == 1 with input as sse_kms_no_key_plan
}

# Regression test for the create-only-blind-spot bug: an existing
# bucket whose plan action is "update" with no SSE-KMS sibling
# should still fire the deny.
test_existing_bucket_updated_without_sse_is_denied if {
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
