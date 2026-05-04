# Tests for dynamodb_kms_required.rego
#
# Run with:  opa test ./policies
#
# Lives in its own sub-package (compliance.hipaa.dynamodb) so the
# file-level METADATA on dynamodb_kms_required.rego does not collide
# with the S3 policy's METADATA. Tests in this file only see deny
# rules from this package.

package compliance.hipaa.dynamodb

import future.keywords.if

############################################################
# Fixtures
############################################################

# Compliant: a DynamoDB table with SSE block, enabled = true, and
# kms_key_arn referencing a CMK resource.
ddb_compliant_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {"actions": ["create"]},
	}],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {"server_side_encryption": [{
			"enabled": {"constant_value": true},
			"kms_key_arn": {"references": ["aws_kms_key.app.arn", "aws_kms_key.app"]},
		}]},
	}]}},
}

# No SSE block at all: this is exactly the starter's baseline
# (main.tf line 104-116 before our hardening edit). Must deny.
ddb_no_sse_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {"actions": ["create"]},
	}],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {},
	}]}},
}

# SSE block with enabled = true but no kms_key_arn: this would use
# the AWS-managed alias/aws/dynamodb key. Customer's account but not
# customer-controlled key policy. Must deny.
ddb_aws_managed_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {"actions": ["create"]},
	}],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {"server_side_encryption": [{"enabled": {"constant_value": true}}]},
	}]}},
}

# SSE block explicitly disabled: an even worse state than no block.
# Must deny.
ddb_explicitly_disabled_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {"actions": ["create"]},
	}],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {"server_side_encryption": [{
			"enabled": {"constant_value": false},
			"kms_key_arn": {"references": ["aws_kms_key.app.arn"]},
		}]},
	}]}},
}

############################################################
# Tests
############################################################

test_ddb_with_cmk_passes if {
	count(deny) == 0 with input as ddb_compliant_plan
}

test_ddb_with_no_sse_block_is_denied if {
	count(deny) == 1 with input as ddb_no_sse_plan
}

test_ddb_with_aws_managed_key_is_denied if {
	count(deny) == 1 with input as ddb_aws_managed_plan
}

test_ddb_with_explicitly_disabled_sse_is_denied if {
	count(deny) == 1 with input as ddb_explicitly_disabled_plan
}

# Regression test for the create-only-blind-spot bug: an UPDATE on
# an existing table that removes the SSE block must fire deny.
test_ddb_update_without_sse_is_denied if {
	update_plan := {
		"resource_changes": [{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"change": {"actions": ["update"]},
		}],
		"configuration": {"root_module": {"resources": [{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"expressions": {},
		}]}},
	}
	count(deny) == 1 with input as update_plan
}
