# Tests for iam_no_wildcards.rego
#
# Run with:  opa test ./policies

package compliance.hipaa.iam

import future.keywords.if

############################################################
# Helpers (test-only) — wrap an IAM policy JSON in a plan shape.
############################################################

build_plan(resource_type, policy_json) := {"resource_changes": [{
	"address": "aws_iam_role_policy.example",
	"type": resource_type,
	"change": {
		"actions": ["create"],
		"after": {"policy": policy_json},
	},
}]}

############################################################
# Fixture policies (compliant + violating)
############################################################

# Compliant: all actions are specific. Mirrors the GAP-07 fix.
compliant_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": ["dynamodb:PutItem"],
			"Resource": "arn:aws:dynamodb:us-east-1:111:table/foo",
		},
		{
			"Effect": "Allow",
			"Action": ["s3:PutObject"],
			"Resource": "arn:aws:s3:::foo/*",
		},
	],
})

# Violating: dynamodb:* (the starter's GAP-07 baseline).
service_wildcard_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "dynamodb:*",
		"Resource": "arn:aws:dynamodb:us-east-1:111:table/foo",
	}],
})

# Violating: super-admin "*" on everything. Worst case.
super_admin_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "*",
		"Resource": "*",
	}],
})

# Violating: a mixed list where one action is fine and one is a
# wildcard. The single bad action should be enough to deny.
mixed_list_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": ["s3:PutObject", "s3:*"],
		"Resource": "arn:aws:s3:::foo/*",
	}],
})

# Edge case: a wildcard inside a Deny statement. Auditors do not
# flag deny-wildcards (broad safety, not broad permission). Should
# pass the policy.
wildcard_in_deny_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Deny",
		"Action": "s3:*",
		"Resource": "*",
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

############################################################
# Tests
############################################################

test_specific_actions_pass if {
	count(deny) == 0 with input as build_plan("aws_iam_role_policy", compliant_policy_json)
}

test_service_wildcard_is_denied if {
	count(deny) == 1 with input as build_plan("aws_iam_role_policy", service_wildcard_policy_json)
}

test_super_admin_wildcard_is_denied if {
	count(deny) == 1 with input as build_plan("aws_iam_role_policy", super_admin_policy_json)
}

test_mixed_list_with_wildcard_is_denied if {
	count(deny) == 1 with input as build_plan("aws_iam_role_policy", mixed_list_policy_json)
}

test_wildcard_inside_deny_passes if {
	count(deny) == 0 with input as build_plan("aws_iam_role_policy", wildcard_in_deny_policy_json)
}

test_aws_iam_policy_resource_type_also_inspected if {
	count(deny) == 1 with input as build_plan("aws_iam_policy", service_wildcard_policy_json)
}
