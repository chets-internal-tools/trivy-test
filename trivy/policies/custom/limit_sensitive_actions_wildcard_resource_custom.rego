# METADATA
# title: "Disallow wildcard resource for sensitive IAM actions (PassRole / RunInstances)"
# description: "Flags IAM policy statements that Allow iam:PassRole or ec2:RunInstances on all resources (*)"
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: ID003
#   provider: aws
#   service: iam
#   severity: HIGH
#   recommended_action: "Restrict iam:PassRole and ec2:RunInstances to specific role ARNs and instance profiles instead of *"
#   input:
#     selector:
#       - type: cloud

package custom.limit_sensitive_actions_wildcard_resource.ID003

import rego.v1

# Actions considered sensitive when granted across all resources
sensitive_actions := {"iam:passrole", "ec2:runinstances"}

# Normalize an action list that can be string or array in the JSON policy
#################################################################
# Utility helpers
#################################################################

# Normalize an action value that can be either a string or an array
normalized_actions(raw) = arr if {
    is_array(raw)
    arr := raw
}
normalized_actions(raw) = arr if {
    not is_array(raw)
    arr := [raw]
}

# Determine if a statement has a wildcard resource (*) either as string or among a list
has_wildcard_resource(stmt) if {
    r := stmt.Resource
    not is_array(r)
    lower(r) == "*"
} else if {
    r := stmt.Resource
    is_array(r)
    some i
    lower(r[i]) == "*"
}

# True if the statement effect is Allow
is_allow(stmt) if {
    lower(stmt.Effect) == "allow"
}

#################################################################
# Statement/action matching helpers
#################################################################

# True for each sensitive action present in the statement
#################################################################
# Sensitive action collection
#################################################################

sensitive_wildcard_actions_in_doc(doc_json) := [a | 
    value := json.unmarshal(doc_json)
    some stmt in value.Statement
    is_allow(stmt)
    has_wildcard_resource(stmt)
    actions := normalized_actions(stmt.Action)
    some a in actions
    lower(a) in sensitive_actions
]

# (helper already returns the list of sensitive wildcard actions; no second definition required)

# Deny for standalone IAM policies
deny contains res if {
    some policy in input.aws.iam.policies
    some act in sensitive_wildcard_actions_in_doc(policy.document.value)
    res = result.new(
        sprintf("IAM policy allows sensitive action '%s' on all resources (*)", [act]),
        policy.document,
    )
}

# Deny for inline or attached role policies
deny contains res if {
    some role in input.aws.iam.roles
    some pol in role.policies
    some act in sensitive_wildcard_actions_in_doc(pol.document.value)
    res = result.new(
        sprintf("IAM role uses a policy that allows sensitive action '%s' on all resources (*)", [act]),
        pol.document,
    )
}
