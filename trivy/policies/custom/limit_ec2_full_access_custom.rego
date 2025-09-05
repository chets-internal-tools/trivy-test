# METADATA
# title: "Disallow unrestricted EC2 IAM Policies"
# description: "Ensure that the creation of the unrestricted EC2 IAM policies is disallowed."
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: ID002
#   provider: aws
#   service: iam
#   severity: HIGH
#   recommended_action: "Create more restrictive EC2 policies"
#   input:
#     selector:
#       - type: cloud
package custom.limit_ec2_full_access.ID002

import rego.v1

dangerous_actions := {"ec2:*"}

is_action_allowed(statements, action_to_check) := action if {
	some statement in statements
	lower(statement.Effect) == "allow"
	some action in statement.Action
	lower(action) == lower(action_to_check)
}

is_overridden_by_deny(statements, action_to_check) if {
	some statement in statements
	lower(statement.Effect) == "deny"
	some action in statement.Action
	lower(action) == lower(action_to_check)
}

allowed_ec2_dangerous_actions(document) := [action |
	value := json.unmarshal(document)
	some action_to_check in dangerous_actions
	not is_overridden_by_deny(value.Statement, action_to_check)
	action := is_action_allowed(value.Statement, action_to_check)
]

deny contains res if {
	some policy in input.aws.iam.policies
	some action in allowed_ec2_dangerous_actions(policy.document.value)
	res = result.new(
		sprintf("IAM policy allows '%s' action", [action]),
		policy.document,
	)
}

deny contains res if {
	some role in input.aws.iam.roles
	some policy in role.policies
	some action in allowed_ec2_dangerous_actions(policy.document.value)
	res = result.new(
		sprintf("IAM role uses a policy that allows '%s' action", [action]),
		policy.document,
	)
}