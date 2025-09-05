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
  name := safe_attr(res, ["values", "name"], "unnamed")
  raw := safe_attr(res, ["values", "policy"], "")
  raw != ""
  doc := parse_json(raw)
  st := doc.Statement[_]
  acts := to_array(st.Action)
  some a
  a := acts[_]
  contains(a, "*")
  sid := object.get(st, "Sid", "(no Sid)")
  msg := sprintf("IAM policy '%s' statement '%s' has wildcard action '%s'", [name, sid, a])
}

deny[msg] {
  res := input.resource.aws_iam_policy[_]
  name := safe_attr(res, ["values", "name"], "unnamed")
  raw := safe_attr(res, ["values", "policy"], "")
  raw != ""
  doc := parse_json(raw)
  st := doc.Statement[_]
  rs := to_array(st.Resource)
  some r
  r := rs[_]
  contains(r, "*")
  sid := object.get(st, "Sid", "(no Sid)")
  msg := sprintf("IAM policy '%s' statement '%s' has wildcard resource '%s'", [name, sid, r])
}

################################################################################
# Helpers
################################################################################

to_array(x) = arr { is_array(x); arr := x } else = arr { not is_array(x); arr := [x] }

safe_attr(obj, path, def) = v { not walk_path(obj, path, _); v := def } else = v { walk_path(obj, path, v) }
walk_path(curr, [], curr)
walk_path(curr, [p, rest...], v) { object.get(curr, p, null) != null; walk_path(curr[p], rest, v) }

parse_json(s) = v { not startswith(s, "{"); v := {"Statement": []} } else = v { json.unmarshal(s, v) }
