package main.iam_boundary_check.ID001_test

import data.main.iam_boundary_check.ID001 as policy

required_boundary := "arn:aws:iam::123456789012:policy/EnforcedBoundaryPolicy"

# Terraform plan style inputs (resource_changes)

test_missing_boundary_plan_deny if {
	input_obj := {
		"resource_changes": [
			{
				"type": "aws_iam_role",
				"name": "test_fail",
				"change": {
					"after": {
						"name": "test-role-fail",
						"assume_role_policy": "{}"
					}
				}
			}
		]
	}

	# Policy uses resource.name ("test_fail") not the after.name attribute
	expected := "IAM role 'test_fail' is missing a permissions boundary."
	policy.deny[msg] with input as input_obj
	msg == expected
}

test_incorrect_boundary_plan_deny if {
	bad_boundary := "arn:aws:iam::123456789012:policy/WrongPolicy"
	input_obj := {
		"resource_changes": [
			{
				"type": "aws_iam_role",
				"name": "test_incorrect",
				"change": {
					"after": {
						"name": "test-role-bad-boundary",
						"assume_role_policy": "{}",
						"permissions_boundary": bad_boundary
					}
				}
			}
		]
	}

	# Expect resource.name ("test_incorrect")
	expected := sprintf("IAM role '%s' has an incorrect permissions boundary: '%s'.", ["test_incorrect", bad_boundary])
	policy.deny[msg] with input as input_obj
	msg == expected
}

test_correct_boundary_plan_no_deny if {
	input_obj := {
		"resource_changes": [
			{
				"type": "aws_iam_role",
				"name": "test_pass",
				"change": {
					"after": {
						"name": "test-role-pass",
						"assume_role_policy": "{}",
						"permissions_boundary": required_boundary
					}
				}
			}
		]
	}

	deny_msgs := [m | policy.deny[m] with input as input_obj]
	count(deny_msgs) == 0
}

# Direct aws_iam_role array style inputs

test_missing_boundary_array_uses_name if {
	input_obj := {
		"aws_iam_role": [
			{
				"name": "array-role-missing",
				"assume_role_policy": "{}"
			}
		]
	}

	expected := "IAM role 'array-role-missing' is missing a permissions boundary."
	policy.deny[msg] with input as input_obj
	msg == expected
}

test_missing_boundary_array_uses_resource_name if {
	# name absent so resource_name should be used
	input_obj := {
		"aws_iam_role": [
			{
				"resource_name": "resource-fallback",
				"assume_role_policy": "{}"
			}
		]
	}

	expected := "IAM role 'resource-fallback' is missing a permissions boundary."
	policy.deny[msg] with input as input_obj
	msg == expected
}

test_missing_boundary_array_unknown_role if {
	# Neither name nor resource_name present -> unknown-role
	input_obj := {
		"aws_iam_role": [
			{
				# intentionally empty object
			}
		]
	}

	expected := "IAM role 'unknown-role' is missing a permissions boundary."
	policy.deny[msg] with input as input_obj
	msg == expected
}

test_incorrect_boundary_array_deny if {
	bad_boundary := "arn:aws:iam::123456789012:policy/SomeOtherPolicy"
	input_obj := {
		"aws_iam_role": [
			{
				"name": "array-role-wrong",
				"permissions_boundary": bad_boundary
			}
		]
	}

	expected := sprintf("IAM role '%s' has an incorrect permissions boundary: '%s'.", ["array-role-wrong", bad_boundary])
	policy.deny[msg] with input as input_obj
	msg == expected
}

test_correct_boundary_array_no_deny if {
	input_obj := {
		"aws_iam_role": [
			{
				"name": "array-role-correct",
				"permissions_boundary": required_boundary
			}
		]
	}

	deny_msgs := [m | policy.deny[m] with input as input_obj]
	count(deny_msgs) == 0
}

# Parameterized table-driven variant to ensure both input shapes behave the same

test_no_deny_across_shapes[case] if {
	some case, tc in {
		"plan-shape": {
			"input": {
				"resource_changes": [{
					"type": "aws_iam_role",
					"name": "shape-plan",
					"change": {
						"after": {
							"name": "shape-plan",
							"permissions_boundary": required_boundary
						}
					}
				}]
			}
		},
		"array-shape": {
			"input": {
				"aws_iam_role": [{
					"name": "shape-array",
					"permissions_boundary": required_boundary
				}]
			}
		}
	}

	deny_msgs := [m | policy.deny[m] with input as tc.input]
	count(deny_msgs) == 0
}
