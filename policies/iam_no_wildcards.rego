# METADATA
# title: IAM inline and customer-managed policies must not use wildcard actions
# description: |
#   Allow statements with wildcard actions (e.g., "*", "s3:*",
#   "dynamodb:*") violate HIPAA 164.312(a)(1) minimum-necessary
#   access. A wildcard turns a small Lambda compromise into the
#   ability to delete tables, rewrite bucket policies, or grant
#   public access. Real workload code only needs a few specific
#   actions; the policy must enumerate them.
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#     - "164.308(a)(4)"
#   severity: critical
#   remediation: |
#     Replace any wildcard action ("*" or "<service>:*") with the
#     specific actions the workload performs. For the Acme intake
#     handler that means:
#       dynamodb:* -> ["dynamodb:PutItem"]
#       s3:*       -> ["s3:PutObject"]
#     Add additional actions only when the handler genuinely needs
#     them. See terraform/main.tf:aws_iam_role_policy.lambda_inline
#     for the corrected pattern.
#   gap: GAP-07
package compliance.hipaa.iam

import future.keywords.contains
import future.keywords.if
import future.keywords.in

############################################################
# Helpers
############################################################

# Plan-action filter. Catches creates AND in-place updates. The
# original "create only" version of this policy missed updates,
# which let a PR re-introduce a wildcard on an existing IAM policy
# resource without firing the gate.
is_create_or_update(change) if "create" in change.change.actions
is_create_or_update(change) if "update" in change.change.actions

# Returns true if any character in the string is the wildcard "*".
# Catches both "*" (super-admin) and "<service>:*" (service-wide).
contains_wildcard(action) if {
	is_string(action)
	contains(action, "*")
}

# Normalizes the Action field of an IAM statement to a set of strings.
# AWS allows Action to be a single string OR an array of strings.
action_set(stmt) := result if {
	is_string(stmt.Action)
	result := {stmt.Action}
}

action_set(stmt) := result if {
	is_array(stmt.Action)
	result := {a | some a in stmt.Action}
}

# Returns the set of (resource_address, offending_action) pairs for
# every Allow statement in a customer-controlled IAM policy that
# uses a wildcard action. We only inspect aws_iam_role_policy and
# aws_iam_policy: the resources WE write. AWS-managed policies
# attached via aws_iam_role_policy_attachment are out of scope —
# we cannot edit them.
wildcard_violations contains violation if {
	some change in input.resource_changes
	change.type in {"aws_iam_role_policy", "aws_iam_policy"}
	is_create_or_update(change)

	# Parse the rendered policy JSON. If references inside the
	# jsonencode were unknown at plan time the policy field is null
	# and json.unmarshal raises, the rule fails silently for that
	# resource — acceptable since nothing dangerous is being claimed.
	policy_doc := json.unmarshal(change.change.after.policy)

	# Look at each Allow statement. (We do not flag wildcards in
	# Deny statements: a wildcard Deny is broad-safety and rarely
	# what auditors complain about.)
	some stmt in policy_doc.Statement
	stmt.Effect == "Allow"

	some action in action_set(stmt)
	contains_wildcard(action)

	violation := {"address": change.address, "action": action}
}

############################################################
# Deny rule
############################################################

deny contains msg if {
	some v in wildcard_violations
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] IAM policy %q contains a wildcard Allow action %q. PHI workloads must enumerate specific actions instead. See terraform/main.tf:aws_iam_role_policy.lambda_inline for the corrected pattern.",
		[v.address, v.action],
	)
}
