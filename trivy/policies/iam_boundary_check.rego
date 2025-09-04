# METADATA
# title: Deployment not allowed
# description: Deployments are not allowed because of missing boundary policy
# custom:
#   id: ID001
#   severity: HIGH
#   input:
#     selector:
#       - type: json

package main.iam_boundary_check.ID001

__rego_metadata__ := {
	"id": "CUSTOM_IAM_BOUNDARY_POLICY",
	"title": "IAM role missing required permissions boundary",
	"severity": "HIGH",
	"type": "terraform",
	"description": "IAM roles must use the EnforcedBoundaryPolicy permissions boundary.",
	"recommended_actions": [
		"Attach the required permissions boundary to the IAM role."
	],
}

required_boundary := "arn:aws:iam::123456789012:policy/EnforcedBoundaryPolicy"

# Evaluate Terraform Plan JSON resources
deny[message] {
	resource := input.resource_changes[_]
	resource.type == "aws_iam_role"
	not resource.change.after.permissions_boundary

	message := sprintf("IAM role '%s' is missing a permissions boundary.", [resource.name])
}

deny[message] {
	resource := input.resource_changes[_]
	resource.type == "aws_iam_role"
	boundary := resource.change.after.permissions_boundary
	boundary != required_boundary

	message := sprintf("IAM role '%s' has an incorrect permissions boundary: '%s'.", [resource.name, boundary])
}

deny[message] {
    role := input.aws_iam_role[_]
    not role.permissions_boundary
    name := coalesce(role.name, role.resource_name, "unknown-role")
    message := sprintf("IAM role '%s' is missing a permissions boundary.", [name])
}

deny[message] {
    role := input.aws_iam_role[_]
    role.permissions_boundary
    role.permissions_boundary != required_boundary
    name := coalesce(role.name, role.resource_name, "unknown-role")
    message := sprintf("IAM role '%s' has an incorrect permissions boundary: '%s'.", [name, role.permissions_boundary])
}

# Helper: first non-empty string
coalesce(a, b, c) = out {
    out := a
    a != ""
} else = out {
    out := b
    b != ""
} else = out {
    out := c
}