package custom.aws.iam.limit_s3_full_access

__rego_metadata__ := {
  "id": "CUSTOM-AWS-LIMIT-S3-FULL-ACCESS",
  "title": "Disallow unrestricted S3 IAM Policies",
  "severity": "HIGH",
  "type": "cloud",
  "description": "Ensure that the creation of unrestricted S3 IAM policies is disallowed.",
  "recommended_actions": ["Remove or scope down s3:* and resources * in policy statements."],
  "input": {"selector": [{"type": "cloud", "subtypes": [{"service": "iam", "provider": "aws"}]}]}
}

# Deny when an IAM policy statement (parsed cloud model) grants s3:* over * resources
# This assumes Trivy's cloud adapted input shape; fall back to terraform resource parsing separately if needed.

deny[msg] {
  some p
  pol := input.aws.iam.policies[p]
  some i
  st := pol.policy.document.Statement[i]
  actions := to_array(st.Action)
  some a
  a := actions[_]
  startswith(a, "s3:")
  wildcard_action(a)
  resources := to_array(st.Resource)
  some r
  r := resources[_]
  r == "*"
  msg := sprintf("IAM policy '%s' allows unrestricted S3 access with action '%s' on resource '*': %s", [pol.name, a, st.Sid])
}

# Terraform HCL parsing path: iterate raw aws_iam_policy resources

deny[msg] {
  res := input.resource.aws_iam_policy[_]
  name := safe_attr(res, ["values", "name"], "unnamed")
  raw := safe_attr(res, ["values", "policy"], "")
  raw != ""
  doc := parse_json(raw)
  st := doc.Statement[_]
  acts := to_array(st.Action)
  some a; a := acts[_]; startswith(a, "s3:"); wildcard_action(a)
  rs := to_array(st.Resource)
  some r; r := rs[_]; r == "*"
  sid := object.get(st, "Sid", "(no Sid)")
  msg := sprintf("IAM policy '%s' allows unrestricted S3 access with action '%s' on resource '*': %s", [name, a, sid])
}

################################################################################
# Helpers
################################################################################

to_array(x) = arr { is_array(x); arr := x } else = arr { not is_array(x); arr := [x] }

wildcard_action(a) { a == "s3:*" } else { endswith(a, "*") }

safe_attr(obj, path, def) = v { not walk_path(obj, path, _); v := def } else = v { walk_path(obj, path, v) }
walk_path(curr, [], curr)
walk_path(curr, [p, rest...], v) { object.get(curr, p, null) != null; walk_path(curr[p], rest, v) }

parse_json(s) = v { not startswith(s, "{"); v := {"Statement": []} } else = v { json.unmarshal(s, v) }
