package custom.aws.iam.limit_s3_full_access

__rego_metadata__ := {
  "id": "CUSTOM-AWS-LIMIT-S3-FULL-ACCESS",
  "title": "Disallow unrestricted S3 IAM Policies",
  "severity": "HIGH",
  "type": "terraform",
  "description": "Ensure that the creation of unrestricted S3 IAM policies is disallowed.",
  "recommended_actions": ["Remove or scope down s3:* and resources * in policy statements."]
}

__rego_input__ := {
  "selector": [ {"type": "terraform"} ]
}

# Deny when an IAM policy statement (parsed cloud model) grants s3:* over * resources
# This assumes Trivy's cloud adapted input shape; fall back to terraform resource parsing separately if needed.

# Cloud-adapted input path removed; focusing on terraform resource shape only for this custom rule.

# Terraform HCL parsing path: iterate raw aws_iam_policy resources

deny[msg] {
  res := input.resource.aws_iam_policy[_]
  name := get_val(res, "name", "unnamed")
  raw := get_val(res, "policy", "")
  raw != ""
  doc := parse_json(raw)
  st := doc.Statement[_]
  act := to_array(st.Action)[_]
  startswith(act, "s3:")
  wildcard_action(act)
  res_item := to_array(st.Resource)[_]
  res_item == "*"
  sid := object.get(st, "Sid", "(no Sid)")
  msg := sprintf("IAM policy '%s' allows unrestricted S3 access with action '%s' on resource '*': %s", [name, act, sid])
}

################################################################################
# Helpers
################################################################################

to_array(x) = arr { is_array(x); arr := x } else = arr { not is_array(x); arr := [x] }

wildcard_action(a) { a == "s3:*" } else { endswith(a, "*") }

get_val(res, key, def) = v {
  values := object.get(res, "values", {})
  v := object.get(values, key, def)
}

parse_json(s) = v { not startswith(s, "{"); v := {"Statement": []} } else = v { json.unmarshal(s, v) }
