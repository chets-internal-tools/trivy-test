package custom.aws.iam.no_policy_wildcards

__rego_metadata__ := {
  "id": "CUSTOM-AWS-NO-POLICY-WILDCARDS",
  "title": "IAM policy uses wildcard action or resource",
  "severity": "HIGH",
  "type": "terraform",
  "description": "Disallow any IAM policy statement containing '*' in Action or Resource (including prefix or ARN segment wildcards).",
  "recommended_actions": ["Replace wildcard patterns with explicit actions and resource ARNs."],
  "input": {"selector": [{"type": "terraform"}]}
}

deny[msg] {
  res := input.resource.aws_iam_policy[_]
  name := get_val(res, "name", "unnamed")
  raw := get_val(res, "policy", "")
  raw != ""
  doc := parse_json(raw)
  st := doc.Statement[_]
  act := to_array(st.Action)[_]
  contains(act, "*")
  sid := object.get(st, "Sid", "(no Sid)")
  msg := sprintf("IAM policy '%s' statement '%s' has wildcard action '%s'", [name, sid, act])
}

deny[msg] {
  res := input.resource.aws_iam_policy[_]
  name := get_val(res, "name", "unnamed")
  raw := get_val(res, "policy", "")
  raw != ""
  doc := parse_json(raw)
  st := doc.Statement[_]
  resrc := to_array(st.Resource)[_]
  contains(resrc, "*")
  sid := object.get(st, "Sid", "(no Sid)")
  msg := sprintf("IAM policy '%s' statement '%s' has wildcard resource '%s'", [name, sid, resrc])
}

################################################################################
# Helpers
################################################################################

to_array(x) = arr { is_array(x); arr := x } else = arr { not is_array(x); arr := [x] }

get_val(res, key, def) = v {
  values := object.get(res, "values", {})
  v := object.get(values, key, def)
}

parse_json(s) = v { not startswith(s, "{"); v := {"Statement": []} } else = v { json.unmarshal(s, v) }
