################################################################################
# METADATA (comment form for older Trivy engines)
# id: CUSTOM_IAM_BOUNDARY_POLICY_LEGACY
# title: IAM role missing required permissions boundary (legacy)
# severity: HIGH
# type: terraform
# description: IAM roles must use the EnforcedBoundaryPolicy permissions boundary.
# recommended_actions:
#   - Attach the required permissions boundary to the IAM role.
################################################################################

# Legacy syntax version of IAM boundary check for older Trivy/OPA
package main.iam_boundary_check_legacy.ID001

__rego_metadata__ := {
	"id": "CUSTOM_IAM_BOUNDARY_POLICY_LEGACY",
	"title": "IAM role missing required permissions boundary (legacy)",
	"severity": "HIGH",
	"type": "terraform",
	"description": "IAM roles must use the EnforcedBoundaryPolicy permissions boundary.",
	"recommended_actions": [
		"Attach the required permissions boundary to the IAM role."
	],
	"input": {"selector": [{"type": "terraform"}]}
}

required_boundary := "arn:aws:iam::123456789012:policy/EnforcedBoundaryPolicy"

# Static HCL shape: resources exposed under input.resource.<type>
# Each aws_iam_role item has attributes under .values

# Direct per-resource shape (Trivy often evaluates each resource separately with type/name/values at root input)
deny[message] {
	input.type == "aws_iam_role"
	not input.values.permissions_boundary
	name := coalesce(input.values.name, "", "unknown-role")
	message := sprintf("IAM role '%s' is missing a permissions boundary.", [name])
}

deny[message] {
	input.type == "aws_iam_role"
	input.values.permissions_boundary
	input.values.permissions_boundary != required_boundary
	name := coalesce(input.values.name, "", "unknown-role")
	message := sprintf("IAM role '%s' has an incorrect permissions boundary: '%s'.", [name, input.values.permissions_boundary])
}

deny[message] {
	role := input.resource.aws_iam_role[_]
	not role.values.permissions_boundary
	name := coalesce(role.values.name, "", "unknown-role")
	message := sprintf("IAM role '%s' is missing a permissions boundary.", [name])
}

deny[message] {
	role := input.resource.aws_iam_role[_]
	role.values.permissions_boundary
	role.values.permissions_boundary != required_boundary
	name := coalesce(role.values.name, "", "unknown-role")
	message := sprintf("IAM role '%s' has an incorrect permissions boundary: '%s'.", [name, role.values.permissions_boundary])
}

# Map-style resources (when aws_iam_role is an object keyed by resource name)
deny[message] {
	roles := input.resource.aws_iam_role
	roles != null
	some k
	role := roles[k]
	not role.values.permissions_boundary
	name := coalesce(role.values.name, k, "unknown-role")
	message := sprintf("IAM role '%s' is missing a permissions boundary.", [name])
}

deny[message] {
	roles := input.resource.aws_iam_role
	roles != null
	some k
	role := roles[k]
	role.values.permissions_boundary
	role.values.permissions_boundary != required_boundary
	name := coalesce(role.values.name, k, "unknown-role")
	message := sprintf("IAM role '%s' has an incorrect permissions boundary: '%s'.", [name, role.values.permissions_boundary])
}

# Helper: first non-empty string (legacy syntax)
coalesce(a, b, c) = out {
	out := a
	a != ""
} else {
	out := b
	b != ""
} else {
	out := c
}
