package requirednamespacequota

import rego.v1

# Enforce that every namespace must have a ResourceQuota
violation[{"msg": msg}] if {
    input.review.kind.kind == "Namespace"
    ns := input.review.object.metadata.name
    not has_quota
    msg := sprintf("Namespace %v must have a ResourceQuota", [ns])
}

# Check if a namespace has a ResourceQuota
has_quota if {
    some quota in input.review.related
    quota.kind == "ResourceQuota"
    quota.metadata.namespace == input.review.object.metadata.name
}
